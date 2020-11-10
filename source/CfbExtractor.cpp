#include <fstream>

#include "CfbExtractor.h"
#include "readHelper.h"
#include "LogHelper.h"

CfbExtractor::CfbExtractor()
{

}

CfbExtractor::~CfbExtractor()
{
	if (m_fatEntries)
		delete[] m_fatEntries;

	if (m_dirEntries)
		delete[] m_dirEntries;

	if (m_miniFatEntries)
		delete[] m_miniFatEntries;

	if (m_miniStream)
		delete[] m_miniStream;

	if (m_input)
		m_input.close();
}

bool CfbExtractor::initialize(const std::string fullPath)
{
	m_input.open(fullPath, std::ios::binary);
	if (!m_input.is_open())
	{
		Log(LogLevel::Error, "Failed to open cfb file");
		return false;
	}

	//getFileSize
	m_input.seekg(0, std::ios::end);
	DWORD zero = 0;
	if (m_input.tellg() > static_cast<std::streampos>(zero - 1))
	{
		Log(LogLevel::Error, "File to long. Max file size: 4,294,967,295");
		return false;
	}
	m_fileSize = static_cast<DWORD>(m_input.tellg());
	m_input.seekg(std::ios::beg);
	//end of getFileSize

	Log(LogLevel::Info, "File Size: ", m_fileSize);

	if (!readVariable(m_input, m_cfbHeader))
	{
		Log(LogLevel::Error, "Problem with loading cfbHeader");
		return false;
	}
	return true;
}

bool CfbExtractor::parseCfbHeader()
{
	constexpr QWORD Cfb_Magic = 0xe11ab1a1e011cfd0;
	if (m_cfbHeader.cfbMagic != Cfb_Magic)
	{
		Log(LogLevel::Warning, "Invalid magic");
		return false;
	}

	if (m_cfbHeader.majorVer != 3 && m_cfbHeader.majorVer != 4)
	{
		Log(LogLevel::Warning, "Invalid majorVer");
		return false;
	}

	constexpr WORD Little_Endian = 0xFFFE;
	if (m_cfbHeader.byteOrder != Little_Endian)
	{
		Log(LogLevel::Warning, "Invalid byteOrder");
		return false;
	}

	if (!(m_cfbHeader.majorVer == 3 && m_cfbHeader.secShift == 9) && !(m_cfbHeader.majorVer == 4 && m_cfbHeader.secShift == 0x0C))
	{
		Log(LogLevel::Warning, "Invalid secShift");
		return false;
	}

	if (m_cfbHeader.majorVer == 3 && m_cfbHeader.dirSecNum != 0)
	{
		Log(LogLevel::Warning, "dirSecNum for version 3 should be 0");
		return false;
	}

	if (m_cfbHeader.miniSecShift != 6)
	{
		Log(LogLevel::Warning, "Invalid miniSecShift");
		return false;
	}

	constexpr DWORD Min_Stream_Size = 0x00001000;
	if (m_cfbHeader.minStreamSize != Min_Stream_Size)
	{
		Log(LogLevel::Warning, "Invalid minStreamSize");
		return false;
	}

	if (m_cfbHeader.fatSecNum == 0)
	{
		Log(LogLevel::Error, "fatSecNum == 0");
		return false;
	}
	else if (m_cfbHeader.fatSecNum > 1 && m_cfbHeader.fatSecNum <= MAX_FAT_SECTIONS_COUNT_IN_HEADER)
	{
		Log(LogLevel::Info, "Multiple fat sections");
	}
	else if (m_cfbHeader.fatSecNum > MAX_FAT_SECTIONS_COUNT_IN_HEADER)
	{
		if (m_cfbHeader.difatSecNum == 0)
		{
			Log(LogLevel::Warning, "Difat section should be present");
			return false;
		}
		Log(LogLevel::Info, "Difat sections are present");
	}

	m_sectionSize = 1 << m_cfbHeader.secShift;
	Log(LogLevel::Info, "Sector size = ", m_sectionSize);

	m_miniSectionSize = 1 << m_cfbHeader.miniSecShift;
	Log(LogLevel::Info, "Sector size = ", m_miniSectionSize);

	m_sectionCount = m_fileSize / m_sectionSize - 1;
	if (m_fileSize % m_sectionSize)
	{
		m_sectionCount++;
	}
	Log(LogLevel::Info, "Sections number = ", m_sectionCount);

	if (m_cfbHeader.difatArray[0] >= m_sectionCount - 1)
	{
		Log(LogLevel::Error, "Incorrect index of fat section: ", m_cfbHeader.difatArray[0]);
		return false;
	}
	return true;
}

bool CfbExtractor::loadFatEntries()
{
	bool status = false;

	bool breakAfterLoop = false;

	const DWORD dwordsInSection = m_sectionSize / sizeof(DWORD);
	DWORD * difatEntries = new DWORD[m_cfbHeader.fatSecNum];

	do {
		//read difat section
		if (m_cfbHeader.fatSecNum <= MAX_FAT_SECTIONS_COUNT_IN_HEADER)
		{
			::memcpy(difatEntries, m_cfbHeader.difatArray, m_cfbHeader.fatSecNum * sizeof(DWORD));
		}
		else
		{
			const DWORD difatInHeaderSize = MAX_FAT_SECTIONS_COUNT_IN_HEADER * sizeof(DWORD);
			::memcpy(difatEntries, m_cfbHeader.difatArray, difatInHeaderSize);
			DWORD difatSecId = m_cfbHeader.firstDifatSecId;
			DWORD difatsToRead = m_cfbHeader.fatSecNum - MAX_FAT_SECTIONS_COUNT_IN_HEADER;
			const DWORD maxDifatsInSections = dwordsInSection - 1;

			for (DWORD i = 0; i < m_cfbHeader.difatSecNum; i++)
			{
				DWORD dwordsCountToReadInThisIter = maxDifatsInSections;
				if (difatsToRead < maxDifatsInSections)
				{
					dwordsCountToReadInThisIter = difatsToRead;
				}
				DWORD difatSectionOffset = (difatSecId + 1) * m_sectionSize;
				ASSERT_BREAK_AFTER_LOOP_1(readArray(m_input, difatEntries + MAX_FAT_SECTIONS_COUNT_IN_HEADER + i * maxDifatsInSections, 
					dwordsCountToReadInThisIter, difatSectionOffset), breakAfterLoop);

				ASSERT_BREAK_AFTER_LOOP_1(readVariable(m_input, difatSecId, difatSectionOffset + m_sectionSize - sizeof(DWORD)), breakAfterLoop);
				difatsToRead -= maxDifatsInSections;
			}
		}
		ASSERT_BREAK_AFTER_LOOP_2(breakAfterLoop);

		//read fat section
		const DWORD maxFatArraySize = m_cfbHeader.fatSecNum * dwordsInSection;

		m_fatEntries = new DWORD[maxFatArraySize];
		for (DWORD i = 0; i < m_cfbHeader.fatSecNum; i++)
		{
			DWORD fatSectionOffset = (difatEntries[i] + 1) * m_sectionSize;
			ASSERT_BREAK_AFTER_LOOP_1(readArray(m_input, m_fatEntries + i * dwordsInSection, dwordsInSection, fatSectionOffset), breakAfterLoop)
		}
	
		status = true;
	}
	while (false);

	//cleanup
	if (difatEntries)
		delete[] difatEntries;

	return status;
}

bool CfbExtractor::loadMiniFatEntries()
{
	//minifat section
	const DWORD miniFatEntriesInSection = m_sectionSize / sizeof(DWORD);
	m_miniFatArraySize = m_cfbHeader.miniFatSecNum * miniFatEntriesInSection;
	const DWORD miniFatDataSize = m_cfbHeader.miniFatSecNum * m_sectionSize;
	m_miniFatEntries = new DWORD[m_miniFatArraySize];
	ASSERT_BOOL(readChunkOfDataFromCfb(m_input, m_miniFatEntries, m_cfbHeader.firstMiniSecId, miniFatDataSize, m_sectionSize, m_fatEntries, m_sectionCount));
	return true;
}

bool CfbExtractor::loadDirEntries()
{
	//dir section
	DWORD dirSecNum = m_cfbHeader.dirSecNum;
	DWORD dirSecId = m_cfbHeader.firstDirSecId;
	if (m_cfbHeader.majorVer == 3)
	{
		//dirSecNum is not used in version 3 so we need to count this number
		while (dirSecId != ENDOFCHAIN)
		{
			if (dirSecId >= m_sectionCount)
			{
				Log(LogLevel::Error, "\"dirSecId\" index out of bound: ", dirSecId);
				return false;
			}

			dirSecNum++;
			dirSecId = m_fatEntries[dirSecId];
		}
	}

	const DWORD dirEntriesInSection = m_sectionSize / sizeof(DirectoryEntry);
	m_dirEntriesCount = dirSecNum * dirEntriesInSection;
	const DWORD dirDataSize = dirSecNum * m_sectionSize;
	m_dirEntries = new DirectoryEntry[m_dirEntriesCount];
	ASSERT_BOOL(readChunkOfDataFromCfb(m_input, m_dirEntries, m_cfbHeader.firstDirSecId, dirDataSize, m_sectionSize, m_fatEntries, m_sectionCount));
	m_rootDirEntry = m_dirEntries[0];
	return true;
}

bool CfbExtractor::loadMiniStreamEntries()
{
	//mini stream
	DWORD miniStreamSize = static_cast<DWORD>(m_rootDirEntry.streamSize);
	m_miniStream = new BYTE[miniStreamSize];
	ASSERT_BOOL(readChunkOfDataFromCfb(m_input, m_miniStream, m_rootDirEntry.startSecLocation, miniStreamSize, m_sectionSize, m_fatEntries, m_sectionCount));
	return true;
}

bool CfbExtractor::initRedableStreamNamesFromRawNames()
{
	std::string name;
	for (DWORD i = 0; i < m_dirEntriesCount; i++)
	{
		const DirectoryEntry& streamEntry = m_dirEntries[i];
		ASSERT_BOOL(convertStreamNameToReadableString(streamEntry.dirEntryName, streamEntry.dirEntryNameLength, name));
		m_mapStreamNameToSectionId[name] = i;
	}
	return true;
}

bool CfbExtractor::readAndAllocateStream(std::string tableName, BYTE** stream, DWORD& streamSize)
{
	if (m_mapStreamNameToSectionId.count(tableName) <= 0)
	{
		Log(LogLevel::Error, "The table doesn't belong to msi ");
		return false;
	}

	const DirectoryEntry& streamEntry = m_dirEntries[m_mapStreamNameToSectionId[tableName]];
	if (streamEntry.objectType == DirEntryType::Stream)
	{
		DWORD streamSecId = streamEntry.startSecLocation;
		streamSize = static_cast<DWORD>(streamEntry.streamSize);
		*stream = new BYTE[streamSize];

		if (streamSize <= m_cfbHeader.minStreamSize)
		{
			//data is stored in miniStream
			ASSERT_BOOL(readChunkOfDataFromCfb(m_miniStream, *stream, streamSecId, streamSize, m_miniSectionSize, m_miniFatEntries, m_miniFatArraySize, true));
		}
		else
		{
			ASSERT_BOOL(readChunkOfDataFromCfb(m_input, *stream, streamSecId, streamSize, m_sectionSize, m_fatEntries, m_sectionCount, false));
		}
	}
	else
	{
		Log(LogLevel::Warning, "The directory is storage, not a stream. Dir id: ", m_mapStreamNameToSectionId[tableName]);
	}
	return true;
}

/*	The names of stream which contain a msi tables are very strange. These names are encoded. I spent a lot of ttime 
	looking for a the pattern. Thanks to Orca.exe I was able to add my custom table names and checks how it is encoded.

	We can divide characters on four groups:
	a) common characters (look at StreamNameCharacters[] below)
		- two characters are coded on two bytes. If this coding start from odd byte, then the last byte is filled
		  with 0x48 value. Then we are getting even number of bytes. The index of character is checked in StreamNameCharacters
		  (eg. "a" has index 36) and this index is encoded in six the lower bits (from 0 - 5). Then we take an second character 
		  index (the same way as previous) and we encode in on the next six lower bits (from 6 - 11). Then 
		  we add 0x3800 value to our word (eg. "a4" after encoding is 0x3924)
	b) not allowed characters (below 0x20, higher than 0x7f and '!', '%', ':', '/', '\', '`')
		- these characters can't be coded (for obvious reasons)
	c) special character (sign "!" which every table need be began)
		- is coded 0x4840 word, begins from even bytes
	d) rest ascii characters
		- occupy two bytes, where higher byte is empty and char representation in ascii is coded on lower bytes 

*/
const char StreamNameCharacters[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',
'B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X',
'Y','Z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','.','_' };

bool CfbExtractor::convertStreamNameToReadableString(const WORD* tableNameArray, const DWORD tableNameLength, std::string& readableStreamName)
{
	std::string name;
	for (DWORD i = 0; i < tableNameLength / sizeof(WORD); i++)
	{
		WORD wholeWord = tableNameArray[i];
		BYTE higherByte = HIBYTE(wholeWord);
		BYTE lowerByte = LOBYTE(wholeWord);

		if (higherByte == 0)
		{
			//string have null ptr termination so don't need add null
			if (lowerByte == 0)
			{
				break;
			}

			name += lowerByte;
		}
		else if (higherByte >= 0x38 && higherByte <= 0x47)
		{
			//get 6 bits from lower byte
			DWORD firstCharIndex = lowerByte & 0x3F;
			char firstChar = StreamNameCharacters[firstCharIndex];
			name += firstChar;

			//get next 6 bits
			DWORD secondCharIndex = (wholeWord - 0x3800) >> 6;
			char secondChar = StreamNameCharacters[secondCharIndex];
			name += secondChar;
		}
		else if (higherByte == 0x48)
		{
			constexpr WORD Exlamation_Mark_Magic = 0x4840;
			if (wholeWord == Exlamation_Mark_Magic) //exclamation is special
			{
				name += '!';
			}
			else
			{
				//only lower byte should be processed
				//get 6 bits from lower byte
				DWORD firstCharIndex = lowerByte & 0x3F;
				char firstChar = StreamNameCharacters[firstCharIndex];
				name += firstChar;
			}
		}
		else // 0x01 - 0x37 and  > 0x49
		{
			Log(LogLevel::Error, "unknown encoding of stream name");
			return false;
		}

	}
	readableStreamName = name;
	return true;
}