#include <vector>
#include <filesystem>

#include "MsiTableParser.h"
#include "LogHelper.h"

//statics
std::map<ActionTargetType, std::string> MsiTableParser::s_mapScriptTypeToExt = { 
	{ActionTargetType::JSContent, ".js"},
	{ActionTargetType::VBSContent, ".vb"} 
};

std::map<ActionTargetType, std::string> MsiTableParser::s_mapActionTargetEnumToString = {
	{ActionTargetType::Dll, "DllEntry"},
	{ActionTargetType::Exe, "ExeCommand"},
	{ActionTargetType::Text, "Text"},
	{ActionTargetType::Error, "Error"},
	{ActionTargetType::JSCall, "JSCall"},
	{ActionTargetType::VBSCall, "VBSCall"},
	{ActionTargetType::Install, "Install"},
};

std::map<ActionSourceType, std::string> MsiTableParser::s_mapActionScourceEnumToString = {
	{ActionSourceType::BinaryData, "BinaryData"},
	{ActionSourceType::SourceFile, "SourceFile"},
	{ActionSourceType::Directory, "Directory"},
	{ActionSourceType::Property, "Property"}
};

MsiTableParser::MsiTableParser(CfbExtractor& extractor) : m_cfbExtractor(extractor)
{

}

MsiTableParser::~MsiTableParser()
{
	if (m_columnsByteStream)
		delete[] m_columnsByteStream;
}

/*	How I discovered that a "!_StringPool" stream contains string lengths?

	Thanks for dynamic analysis with IDA
*/
bool MsiTableParser::initStringVector()
{
	bool status = false;

	BYTE* stringDataStream = nullptr;
	BYTE* stringPoolByteStream = nullptr;

	do {
		//get StringData
		DWORD stringDataStreamSize = 0;
		ASSERT_BREAK(m_cfbExtractor.readAndAllocateTable(StringData_Stream_Name, &stringDataStream, stringDataStreamSize));

		if (stringDataStream)
		{
			//if you want save stream, uncomment lines
			writeToFile(StringData_Stream_Name, (const char*)stringDataStream, stringDataStreamSize, std::ios::binary);
			std::string msg = std::string(StringData_Stream_Name) + " written to file";
			Log(LogLevel::Info, msg.data());
		}
		Log(LogLevel::Info, "Success of reading !_StringData table");

		//get StringPool
		DWORD stringPoolByteStreamSize = 0;
		ASSERT_BREAK(m_cfbExtractor.readAndAllocateTable(StringPool_Stream_Name, &stringPoolByteStream, stringPoolByteStreamSize));

		m_stringCount = stringPoolByteStreamSize / sizeof(DWORD);

		//if longStrings occur then we allocate to much size, but it should't be a problem
		m_vecStrings.resize(m_stringCount);

		WORD* stringPoolStream = (WORD*)stringPoolByteStream;

		DWORD offset = 0;
		DWORD stringIndex = 0;
		for (DWORD i = 0; i < m_stringCount; i++)
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
			writeToFile(StringPool_Stream_Name, (const char*)stringPoolByteStream, stringPoolByteStreamSize, std::ios::binary);
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

/*	How I discovered that a "!_Tables" stream contains string lengths?

	It was quite easy. I noticed a word count in this stream correspond to tables number
	and that's all.
*/
bool MsiTableParser::printTablesFromMetadata()
{
	bool status = false;
	BYTE* tablesByteStream = nullptr;

	do {
		//get StringData
		DWORD tablesByteStreamSize = 0;
		ASSERT_BREAK(m_cfbExtractor.readAndAllocateTable(Tables_Stream_Name, &tablesByteStream, tablesByteStreamSize));

		WORD* tablesStream = (WORD*)tablesByteStream;
		std::cout << "Tables:\n";
		for (DWORD i = 0; i < tablesByteStreamSize / sizeof(WORD); i++)
		{
			WORD stringIndex = tablesStream[i];
			m_tableNameIndices.push_back(stringIndex);
			m_mapTNStringToTNIndex[m_vecStrings[stringIndex]] = stringIndex;
			std::cout << m_vecStrings[stringIndex] << std::endl;
		}
		std::cout << std::endl;

		if (tablesByteStream)
		{
			//if you want save stream, uncomment lines
			writeToFile(Tables_Stream_Name, (const char*)tablesByteStream, tablesByteStreamSize, std::ios::binary);
			std::string msg = std::string(Tables_Stream_Name) + " written to file";
			Log(LogLevel::Info, msg.data());
		}
		Log(LogLevel::Info, "Success of reading !_Tables table\n");

		status = true;
	} while (false);

	return status;
}

/*	How I discovered that a "!_Columns" stream contains string lengths?

	Thanks for dynamic analysis with IDA, WIX and my insights.
*/
bool MsiTableParser::extractColumnsFromMetadata()
{
	bool status = false;

	do {
		//get StringData
		DWORD columnsByteStreamSize = 0;
		ASSERT_BREAK(m_cfbExtractor.readAndAllocateTable(Columns_Stream_Name, &m_columnsByteStream, columnsByteStreamSize));

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
			writeToFile(Columns_Stream_Name, (const char*)m_columnsByteStream, columnsByteStreamSize, std::ios::binary);
			std::string msg = std::string(Columns_Stream_Name) + " written to file";
			Log(LogLevel::Info, msg.data());
		}
		Log(LogLevel::Info, "Success of reading !_Columns table\n");

		status = true;
	} while (false);

	return status;
}

/* How do I know "customAction" constatns (eg. bit masks)?

	My knowledge in this field is based on WIX, excatly on "MsiInterop.cs" and "Decompiler.cs". 
	There is information how to retrieve all information from customAction table.
*/
bool MsiTableParser::printCustomActionTable()
{
	bool status = false;
	bool breakAfterLoop = false;

	BYTE* customActionByteStream = nullptr;
	std::ofstream reportStream;
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

		

		WORD* columnsStream = (WORD*)m_columnsByteStream;
		DWORD oneRowByteSize = 0;
		for (DWORD j = 0; j < cAColumnCount; j++)
		{
			//indices. Indices have always highest bit set to 1, I don't know why. Ignore it
			cAColumns[j].index = columnsStream[indicesOffset + j] & 0x7fff;

			//names
			WORD nameId = columnsStream[namesOffset + j];
			ASSERT_BREAK_AFTER_LOOP_1(nameId < m_vecStrings.size(), breakAfterLoop);
			cAColumns[j].name = m_vecStrings[nameId];

			//types
			getColumnType(columnsStream[typesOffset + j], cAColumns[j].type);

			if (cAColumns[j].type.kind == ColumnKind::Number && cAColumns[j].type.value == 4)
			{
				oneRowByteSize += 4;
			}
			else
			{
				oneRowByteSize += 2;
			}
		}

		ASSERT_BREAK_AFTER_LOOP_2(breakAfterLoop);

		DWORD customActionByteStreamSize = 0;
		ASSERT_BREAK(m_cfbExtractor.readAndAllocateTable(CustomAction_Stream_Name, &customActionByteStream, customActionByteStreamSize));

		const DWORD rowCount = customActionByteStreamSize / oneRowByteSize;
		if (customActionByteStreamSize % oneRowByteSize)
		{
			Log(LogLevel::Warning, "Something wrong: customActionByteStreamSize % oneRowByteSize = ", 
				customActionByteStreamSize % oneRowByteSize);
			break;
		}

		std::vector<std::vector<DWORD>> customActionTable(rowCount);
		for (auto& vec : customActionTable)
		{
			vec.resize(cAColumns.size());
		}

		BYTE* customActionStream = customActionByteStream;
		
		//load table to vector
		for (DWORD i = 0; i < cAColumns.size(); i++)
		{
			DWORD fieldSize = sizeof(WORD);
			if (cAColumns[i].type.kind == ColumnKind::Number && cAColumns[i].type.value == 4)
			{
				fieldSize = sizeof(DWORD);
			}

			for (DWORD j = 0; j < rowCount; j++)
			{
				::memcpy(&customActionTable[j][i], customActionStream, fieldSize);
				customActionStream += fieldSize;
			}
		}

		//for (auto vec : customActionTable)
		//{
		//	for (DWORD i = 0; i < vec.size(); i++)
		//	{
		//		const ColumnTypeInfo& t = cAColumns[i].type;
		//		if (t.kind == ColumnKind::LocString || t.kind == ColumnKind::OrdString)
		//		{
		//			if (vec[i] >= m_vecStrings.size())
		//			{
		//				//error
		//			}
		//			const std::string& s = m_vecStrings[vec[i]];
		//			if (s.size() > t.value)
		//			{
		//				std::cout << s.substr(t.value) << "\t";
		//			}
		//			else
		//			{
		//				std::cout << s << "\t";
		//			}
		//			
		//		}
		//		else if (t.kind == ColumnKind::Number)
		//		{
		//			std::cout << vec[i] << "\t";
		//		}
		//		else
		//		{
		//			//unknown type. Print it in hex
		//			std::cout << std::hex << vec[i] << "\t";
		//		}
		//	}
		//	std::cout << std::endl;
		//}

		const std::string reportFileName = "msiAnalyzeReport.txt";
		reportStream.open(reportFileName);
		if (!reportStream)
		{
			Log(LogLevel::Error, "Cannot open report file");
			break;
		}

		for (auto row : customActionTable)
		{
			if (cAColumns[0].type.kind != ColumnKind::OrdString)
			{
				Log(LogLevel::Warning, "First column in CustomAction should be a string");
				break;
			}
			ASSERT_BREAK_AFTER_LOOP_1(row[0] < m_stringCount, breakAfterLoop);
			std::string id = m_vecStrings[row[0]];

			if (cAColumns[1].type.kind != ColumnKind::Number)
			{
				Log(LogLevel::Warning, "Second column in CustomAction should be number");
				break;
			}
			DWORD type = row[1];

			ActionSourceType actionSourceType = static_cast<ActionSourceType>(type & ActionBitMask::Source);
			ActionTargetType actionTargetType = static_cast<ActionTargetType>(type & ActionBitMask::Target);
			
			switch (actionTargetType)
			{
			case ActionTargetType::Dll:
			case ActionTargetType::Exe:
				break;
			case ActionTargetType::Text:
				if (actionSourceType == ActionSourceType::SourceFile)
				{
					actionTargetType = ActionTargetType::Error;
				}
				break;
			case ActionTargetType::JSCall:
				if (actionSourceType == ActionSourceType::Directory)
				{
					actionTargetType = ActionTargetType::JSContent;
				}
				break;
			case ActionTargetType::VBSCall:
				if (actionSourceType == ActionSourceType::Directory)
				{
					actionTargetType = ActionTargetType::VBSContent;
				}
				break;

			//add powershell scripts

			default:
				Log(LogLevel::Warning, "Unknown custom target type");
				continue;
			}

			if (cAColumns[2].type.kind != ColumnKind::OrdString)
			{
				Log(LogLevel::Warning, "Third column in CustomAction should be a string");
				break;
			}
			ASSERT_BREAK_AFTER_LOOP_1(row[2] < m_stringCount, breakAfterLoop);
			std::string actionSource = m_vecStrings[row[2]];

			if (cAColumns[3].type.kind != ColumnKind::OrdString)
			{
				Log(LogLevel::Warning, "Fourth column in CustomAction should be a string");
				break;
			}
			ASSERT_BREAK_AFTER_LOOP_1(row[3] < m_stringCount, breakAfterLoop);
			std::string actionContent = m_vecStrings[row[3]];

			switch (actionTargetType)
			{
			//save script to separate file
			case ActionTargetType::JSContent:
			case ActionTargetType::VBSContent:
			{
				const std::string scriptFolder = "scripts";
				if (std::experimental::filesystem::exists(scriptFolder))
				{
					Log(LogLevel::Warning, "Scripts folder already exist.");
				}
				else
				{
					if (!std::experimental::filesystem::create_directories(scriptFolder))
					{
						Log(LogLevel::Warning, "Can't create scripts folder");
						continue;
					}
				}

				if (id.empty())
					id = "unknown_id";

				if (id.size() < 3 || id.substr(id.size() -3, 3).compare(s_mapScriptTypeToExt[actionTargetType]) != 0)
				{
					id += s_mapScriptTypeToExt[actionTargetType];
				}
				std::string scriptPath = scriptFolder + "\\" + id;
				ASSERT_BREAK_AFTER_LOOP_1(writeToFile(scriptPath, actionContent.data(), actionContent.size()), breakAfterLoop);
				break;
			}
			//and every action to report
			default:
			{
				reportStream << "ID: " << id << " \t" << s_mapActionScourceEnumToString[actionSourceType] <<
					" = \"" << actionSource << "\" \t" << s_mapActionTargetEnumToString[actionTargetType] <<
					" = \"" << actionContent << "\"" << std::endl;
				break;
			}
			}
		}
		ASSERT_BREAK_AFTER_LOOP_2(breakAfterLoop);


		if (customActionByteStream)
		{
			//if you want save stream, uncomment lines
			writeToFile(CustomAction_Stream_Name, (const char*)customActionByteStream, customActionByteStreamSize, std::ios::binary);
			std::string msg = std::string(CustomAction_Stream_Name) + " written to file";
			Log(LogLevel::Info, msg.data());
		}
		Log(LogLevel::Info, "Success of reading !CustomAction table\n");
	} 
	while (false);

	if (customActionByteStream)
		delete[] customActionByteStream;

	if (reportStream.is_open())
		reportStream.close();

	return status;
}

//write to file helper
bool MsiTableParser::writeToFile(std::string fileName, const char* pStream, size_t streamSize, std::ios_base::openmode mod)
{
	std::ofstream outputFile(fileName, mod);
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

/*	This function is based on research from msi.dll (with IDA). I looked on "CMsiView::GetColumnTypes" 
	and based on that I retrieved information which I need. Because I'am not interested of many types
	(eg. object) so I treat them like a simple numbers.
*/
void MsiTableParser::getColumnType(WORD columnWordType, ColumnTypeInfo& columnTypeInfo)
{
	//1. if ( BITTEST(&type, 12) ) -> then field is nullable (can be null)
	//2. there are other types: 'o', 'v', 'f', 'g', 'j' but for as are not important
	columnTypeInfo.kind = ColumnKind::Unknown;
	if (BITTEST(columnWordType, 11)) 
	{
		if (BITTEST(columnWordType, 10) && BITTEST(columnWordType, 8))
		{
			columnTypeInfo.kind = ColumnKind::OrdString;
			if (BITTEST(columnWordType, 9))
			{
				columnTypeInfo.kind = ColumnKind::LocString;
			}
			columnTypeInfo.value = columnWordType & 0xff; //take only one byte
		}
	}
	else //there is an integer
	{
		columnTypeInfo.kind = ColumnKind::Number;
		columnTypeInfo.value = (columnWordType & 0x400) != 0 ? 2 : 4;
	}
}