#include <vector>

#include "MsiTableParser.h"
#include "LogHelper.h"

MsiTableParser::MsiTableParser(Ole2Extractor& extractor) : m_oleExtractor(extractor)
{

}

bool MsiTableParser::initStringVector()
{
	bool status = false;

	BYTE* stringDataStream = nullptr;
	BYTE* stringPoolByteStream = nullptr;

	do {
		//get StringData
		DWORD stringDataStreamSize = 0;
		ASSERT_BREAK(m_oleExtractor.readAndAllocateTable(StringData_Table_Name, &stringDataStream, stringDataStreamSize));

		if (stringDataStream)
		{
			//if you want save stream, uncomment lines
			writeToFile(StringData_Table_Name, (const char*)stringDataStream, stringDataStreamSize);
			std::string msg = std::string(StringData_Table_Name) + " written to file";
			Log(LogLevel::Info, msg.data());
		}
		Log(LogLevel::Info, "Success of reading !_StringData table");

		//get StringPool
		DWORD stringPoolByteStreamSize = 0;
		ASSERT_BREAK(m_oleExtractor.readAndAllocateTable(StringPool_Table_Name, &stringPoolByteStream, stringPoolByteStreamSize));

		const DWORD stringFieldsCount = stringPoolByteStreamSize / sizeof(DWORD);

		//if longStrings occur then we allocate to much size, but it should't be a problem
		m_vecStrings.resize(stringFieldsCount);

		WORD* stringPoolStream = (WORD*)stringPoolByteStream;

		DWORD offset = 0;
		DWORD stringIndex = 0;
		for (DWORD i = 0; i < stringFieldsCount; i++)
		{
			WORD occuranceNumber = stringPoolStream[2 * i + 1];
			WORD stringLenght = stringPoolStream[2 * i];

			if (occuranceNumber > 0)
			{
				if (stringLenght == 0)
				{
					//there is long string
					i++;
					DWORD longStringLenght = *(((DWORD*)stringPoolStream) + i);
					m_vecStrings[stringIndex].resize(longStringLenght);
					::memcpy((void*)m_vecStrings[stringIndex].data(), stringDataStream + offset, longStringLenght);
					offset += longStringLenght;

				}
				else if (stringLenght > 0)
				{
					m_vecStrings[stringIndex].resize(stringLenght);
					::memcpy((void*)m_vecStrings[stringIndex].data(), stringDataStream + offset, stringLenght);
					offset += stringLenght;
				}
				else
				{
					//something wrong
				}
			}
			stringIndex++;
		}

		if (stringPoolByteStream)
		{
			//if you want save stream, uncomment lines
			writeToFile(StringPool_Table_Name, (const char*)stringPoolByteStream, stringPoolByteStreamSize);
			std::string msg = std::string(StringPool_Table_Name) + " written to file";
			Log(LogLevel::Info, msg.data());
		}
		Log(LogLevel::Info, "Success of reading !_StringPool table");

		status = true;
	} while (false);

	//all deletes and clean up
	if (stringDataStream)
		delete[] stringDataStream;

	if (stringPoolByteStream)
		delete[] stringPoolByteStream;

	return status;
}

bool MsiTableParser::printTablesFromMetadata()
{
	bool status = false;
	BYTE* tablesByteStream = nullptr;

	do {
		//get StringData
		DWORD tablesByteStreamSize = 0;
		ASSERT_BREAK(m_oleExtractor.readAndAllocateTable(Tables_Table_Name, &tablesByteStream, tablesByteStreamSize));

		WORD* tablesStream = (WORD*)tablesByteStream;
		std::cout << "Tables:\n";
		for (DWORD i = 0; i < tablesByteStreamSize / sizeof(WORD); i++)
		{
			WORD stringIndex = tablesStream[i];
			m_tableNameIndices.push_back(stringIndex);

			std::cout << m_vecStrings[stringIndex] << std::endl;;
		}
		std::cout << std::endl;

		if (tablesByteStream)
		{
			//if you want save stream, uncomment lines
			writeToFile(Tables_Table_Name, (const char*)tablesByteStream, tablesByteStreamSize);
			std::string msg = std::string(Tables_Table_Name) + " written to file";
			Log(LogLevel::Info, msg.data());
		}
		Log(LogLevel::Info, "Success of reading !_Tables table");

		status = true;
	} while (false);

	return status;
}

bool MsiTableParser::printColumnsFromMetadata()
{
	bool status = false;
	BYTE* columnsByteStream = nullptr;

	do {
		//get StringData
		DWORD columnsByteStreamSize = 0;
		ASSERT_BREAK(m_oleExtractor.readAndAllocateTable(Columns_Table_Name, &columnsByteStream, columnsByteStreamSize));

		WORD* columnsStream = (WORD*)columnsByteStream;

		//note difference between tableIndex and tableNameIndex
		DWORD tableIndex = 0;
		DWORD columnCount = 0;
		DWORD currTableNameIndex = m_tableNameIndices[0];

		//we need to know, where is ending of table names
		DWORD i;
		for (i = 0; i < columnsByteStreamSize / sizeof(WORD); i++)
		{
			WORD stringIndex = columnsStream[i];
			if (stringIndex == currTableNameIndex)
			{
				columnCount++;
			}
			else
			{
				m_columnCount[currTableNameIndex] = columnCount;
				tableIndex++;
				if (tableIndex >= m_tableNameIndices.size())
				{
					//end of columns counting
					break;
				}

				currTableNameIndex = m_tableNameIndices[tableIndex];
				if (stringIndex != currTableNameIndex)
				{
					//something wrong
				}
				columnCount = 1;
			}
		}
		std::cout << std::endl;

		if (columnsByteStream)
		{
			//if you want save stream, uncomment lines
			writeToFile(Columns_Table_Name, (const char*)columnsByteStream, columnsByteStreamSize);
			std::string msg = std::string(Columns_Table_Name) + " written to file";
			Log(LogLevel::Info, msg.data());
		}
		Log(LogLevel::Info, "Success of reading !_Tables table\n");

		status = true;
	} while (false);

	return status;
}

//write to file helper
bool MsiTableParser::writeToFile(std::string fileName, const char* pStream, size_t streamSize)
{
	std::ofstream outputFile(fileName, std::ios::binary);
	if (!outputFile)
	{
		//maybe filename is inappropriate? maybe to long?
		std::string newFileName;
		for (char c : fileName)
		{
			if (c <= 0x20 || (c >= 0x3A && c <= 0x3F) || c >= 0x7F || c == '"' ||
				c == '%' || c == '*' || c == ',' || c == '.' || c == '/' || c == '\\')
			{
				//skip
				continue;
			}
			newFileName += c;

		}

		outputFile.open(newFileName);
		if (!outputFile)
		{
			Log(LogLevel::Warning, "Failed to create output file");
			Log(LogLevel::Warning, "File name lenght: ", fileName.length());
			return false;
		}
	}

	outputFile.write(pStream, streamSize);
	outputFile.close();

	return true;
}