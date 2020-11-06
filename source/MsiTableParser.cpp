#include <vector>

#include "MsiTableParser.h"
#include "LogHelper.h"

MsiTableParser::MsiTableParser(Ole2Extractor& extractor) : m_oleExtractor(extractor)
{

}

MsiTableParser::~MsiTableParser()
{
	if (m_columnsByteStream)
		delete[] m_columnsByteStream;
}

bool MsiTableParser::initStringVector()
{
	bool status = false;

	BYTE* stringDataStream = nullptr;
	BYTE* stringPoolByteStream = nullptr;

	do {
		//get StringData
		DWORD stringDataStreamSize = 0;
		ASSERT_BREAK(m_oleExtractor.readAndAllocateTable(StringData_Stream_Name, &stringDataStream, stringDataStreamSize));

		if (stringDataStream)
		{
			//if you want save stream, uncomment lines
			writeToFile(StringData_Stream_Name, (const char*)stringDataStream, stringDataStreamSize);
			std::string msg = std::string(StringData_Stream_Name) + " written to file";
			Log(LogLevel::Info, msg.data());
		}
		Log(LogLevel::Info, "Success of reading !_StringData table");

		//get StringPool
		DWORD stringPoolByteStreamSize = 0;
		ASSERT_BREAK(m_oleExtractor.readAndAllocateTable(StringPool_Stream_Name, &stringPoolByteStream, stringPoolByteStreamSize));

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
			writeToFile(StringPool_Stream_Name, (const char*)stringPoolByteStream, stringPoolByteStreamSize);
			std::string msg = std::string(StringPool_Stream_Name) + " written to file";
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
		ASSERT_BREAK(m_oleExtractor.readAndAllocateTable(Tables_Stream_Name, &tablesByteStream, tablesByteStreamSize));

		WORD* tablesStream = (WORD*)tablesByteStream;
		std::cout << "Tables:\n";
		for (DWORD i = 0; i < tablesByteStreamSize / sizeof(WORD); i++)
		{
			WORD stringIndex = tablesStream[i];
			m_tableNameIndices.push_back(stringIndex);
			m_mapTNStringToTNIndex[m_vecStrings[stringIndex]] = stringIndex;
			std::cout << m_vecStrings[stringIndex] << std::endl;;
		}
		std::cout << std::endl;

		if (tablesByteStream)
		{
			//if you want save stream, uncomment lines
			writeToFile(Tables_Stream_Name, (const char*)tablesByteStream, tablesByteStreamSize);
			std::string msg = std::string(Tables_Stream_Name) + " written to file";
			Log(LogLevel::Info, msg.data());
		}
		Log(LogLevel::Info, "Success of reading !_Tables table");

		status = true;
	} while (false);

	return status;
}

bool MsiTableParser::extractColumnsFromMetadata()
{
	bool status = false;

	do {
		//get StringData
		DWORD columnsByteStreamSize = 0;
		ASSERT_BREAK(m_oleExtractor.readAndAllocateTable(Columns_Stream_Name, &m_columnsByteStream, columnsByteStreamSize));

		WORD* columnsStream = (WORD*)m_columnsByteStream;

		//note difference between tableIndex and tableNameIndex
		DWORD tableIndex = 0;
		DWORD columnCount = 0;

		DWORD currTableNameIndex = m_tableNameIndices[0];
		m_tableNameIndexToColumnCountAndOffset[currTableNameIndex].second = m_allColumnsCount;
		//we need to know, where is ending of table names
		for (DWORD i = 0; i < columnsByteStreamSize / sizeof(WORD); i++)
		{
			WORD stringIndex = columnsStream[i];
			if (stringIndex == currTableNameIndex)
			{
				columnCount++;
			}
			else
			{
				m_allColumnsCount += columnCount;
				m_tableNameIndexToColumnCountAndOffset[currTableNameIndex].first = columnCount;

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
				m_tableNameIndexToColumnCountAndOffset[currTableNameIndex].second = m_allColumnsCount;

				columnCount = 1;
			}
		}

		//check if stream is correct size
		constexpr DWORD metadataColumnCount = 4;
		if (m_allColumnsCount * sizeof(WORD) * metadataColumnCount != columnsByteStreamSize)
		{
			//something wrong
		}

		if (m_columnsByteStream)
		{
			//if you want save stream, uncomment lines
			writeToFile(Columns_Stream_Name, (const char*)m_columnsByteStream, columnsByteStreamSize);
			std::string msg = std::string(Columns_Stream_Name) + " written to file";
			Log(LogLevel::Info, msg.data());
		}
		Log(LogLevel::Info, "Success of reading !_Tables table\n");

		status = true;
	} while (false);

	return status;
}

bool MsiTableParser::printCustomActionTable()
{
	bool status = false;

	do {
		//take info only about !_CustomAction table
		//cA -> shortcut from customAction
		DWORD cATableNameIndex = 0;
		ASSERT_BREAK(getTableNameIndex(CustomAction_Table_Name, cATableNameIndex));


		const DWORD cAColumnCount = m_tableNameIndexToColumnCountAndOffset[cATableNameIndex].first;
		const DWORD cAColumnOffset = m_tableNameIndexToColumnCountAndOffset[cATableNameIndex].second;

		std::vector<ColumnInfo> cAColumns(cAColumnCount);
		const DWORD Index_ColumnIndex = 1;
		const DWORD Name_ColumnIndex = 2;
		const DWORD Type_ColumnIndex = 3;

		DWORD indicesOffset = Index_ColumnIndex * m_allColumnsCount + cAColumnOffset;
		DWORD namesOffset = Name_ColumnIndex * m_allColumnsCount + cAColumnOffset;
		DWORD typesOffset = Type_ColumnIndex * m_allColumnsCount + cAColumnOffset;

		bool breakAfterLoop = false;

		WORD* columnsStream = (WORD*)m_columnsByteStream;
		for (DWORD j = 0; j < cAColumnCount; j++)
		{
			//indices. Indices have always highest bit set to 1, I don't know why. Ignore it
			cAColumns[j].index = columnsStream[indicesOffset + j] & 0x7fff;

			//names
			WORD nameId = columnsStream[namesOffset + j];
			ASSERT_BREAK(nameId < m_vecStrings.size());
			cAColumns[j].name = m_vecStrings[nameId];

			//types
			getColumnType(columnsStream[typesOffset + j], cAColumns[j].type);
		}

		if (breakAfterLoop) break;
	} 
	while (false);

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

bool MsiTableParser::getTableNameIndex(std::string tableName, DWORD& index)
{
	if (m_mapTNStringToTNIndex.count(tableName) <= 0)
	{
		std::string msg = tableName + " doesn't exists";
		Log(LogLevel::Warning, msg.data());
		return false;
	}

	index = m_mapTNStringToTNIndex[tableName];

	return true;
}

void MsiTableParser::getColumnType(WORD columnWordType, ColumnTypeInfo& columnTypeInfo)
{
	//1. if ( BITTEST(&type, 12) ) -> then field is nullable (can be null
	//2. there are other types: 'o', 'v', 'f', 'g', 'j' but for as it isn't important
	if (BITTEST(columnWordType, 11u))
	{
		if (BITTEST(columnWordType, 10u))
		{
			if (BITTEST(columnWordType, 8u))
				columnTypeInfo.kind = (columnWordType & 0x200) != 0 ? ColumnKind::LocString : ColumnKind::OrdString;
			else
				columnTypeInfo.kind = ColumnKind::Unknown;
			columnTypeInfo.value = (unsigned __int8)columnWordType;// &0xff; //take only one byte
		}
		else if (BITTEST(columnWordType, 8u))
		{
			columnTypeInfo.kind = ColumnKind::Unknown;
		}
		else
		{
			columnTypeInfo.kind = ColumnKind::Unknown;
		}
	}
	else //there is an integer
	{
		columnTypeInfo.kind = ColumnKind::Number;
		columnTypeInfo.value = (columnWordType & 0x400) != 0 ? 2 : 4;
	}
}