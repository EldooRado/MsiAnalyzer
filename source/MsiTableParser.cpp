#include <vector>
#include <filesystem>
#include <regex>

#include "MsiTableParser.h"
#include "LogHelper.h"

std::map<ActionTargetType, std::string> MsiTableParser::s_mapActionTargetEnumToString = {
	{ActionTargetType::Dll, "DllEntry"},
	{ActionTargetType::Exe, "ExeCommand"},
	{ActionTargetType::Text, "Text"},
	{ActionTargetType::Error, "Error"},
	{ActionTargetType::JSCall, "JSCall"},
	{ActionTargetType::VBSCall, "VBSCall"},
	{ActionTargetType::PS1Call, "PS1Call"},
	{ActionTargetType::Install, "Install"},
};

std::map<ActionSourceType, std::string> MsiTableParser::s_mapActionScourceEnumToString = {
	{ActionSourceType::BinaryData, "File"},
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
	Thanks to dynamic analysis with IDA.

	STRUCTURE
	"!_StringPool" stream is composed from DWORD's where first WORD means a length of
	string and second its occurance number. String length more than a MAX_WORD is a special case.
	Then occurance number is > 0 but lenght == 0, and it means that length is store on the next DWORD.

	Example: "!_StringData" -> "NameTableTypeColumn". "!_StringPool" ->  hex: 
	"00 00 00 00 04 00 0A 00 05 00 02 00 00 00 00 00 04 00 06 00 06 00 02 00"
	Result string vector: {"", "Name", "Table", "", "Type", "Column")
*/
bool MsiTableParser::initStringVector()
{
	bool status = false;

	BYTE* stringDataStream = nullptr;
	BYTE* stringPoolByteStream = nullptr;

	do {
		//get StringData
		DWORD stringDataStreamSize = 0;
		ASSERT_BREAK(m_cfbExtractor.readAndAllocateStream(StringData_Stream_Name, &stringDataStream, stringDataStreamSize));

		//if you want save stream, uncomment lines
		/*if (stringDataStream)
		{
			if (writeToFile(StringData_Stream_Name, (const char*)stringDataStream, stringDataStreamSize, std::ios::binary))
			{
				std::string msg = std::string(StringData_Stream_Name) + " written to file";
				Log(LogLevel::Info, msg.data());
			}
		}*/

		//get StringPool
		DWORD stringPoolByteStreamSize = 0;
		ASSERT_BREAK(m_cfbExtractor.readAndAllocateStream(StringPool_Stream_Name, &stringPoolByteStream, stringPoolByteStreamSize));

		m_stringCount = stringPoolByteStreamSize / sizeof(DWORD);

		//if longStrings occur then we allocate to much size, but it should't be a problem
		m_vecStrings.resize(m_stringCount);

		WORD* stringPoolStream = (WORD*)stringPoolByteStream;

		DWORD offset = 0;
		DWORD stringIndex = 0;
		for (DWORD i = 0; i < m_stringCount; i++)
		{
			WORD occuranceNumber = stringPoolStream[2 * i + 1];
			WORD stringLength = stringPoolStream[2 * i];

			if (occuranceNumber > 0)
			{
				if (stringLength == 0)
				{
					//there is long string
					i++;
					DWORD longStringLenght = *(((DWORD*)stringPoolStream) + i);
					m_vecStrings[stringIndex].resize(longStringLenght);
					::memcpy((void*)m_vecStrings[stringIndex].data(), stringDataStream + offset, longStringLenght);
					offset += longStringLenght;
				}
				else if (stringLength > 0)
				{
					m_vecStrings[stringIndex].resize(stringLength);
					::memcpy((void*)m_vecStrings[stringIndex].data(), stringDataStream + offset, stringLength);
					offset += stringLength;
				}
			}
			stringIndex++;
		}

		//if you want save stream, uncomment lines
		/*if (stringPoolByteStream)
		{
			if (writeToFile(StringPool_Stream_Name, (const char*)stringPoolByteStream, stringPoolByteStreamSize, std::ios::binary))
			{
				std::string msg = std::string(StringPool_Stream_Name) + " written to file";
				Log(LogLevel::Info, msg.data());
			}
		}*/

		status = true;
	} while (false);

	//all deletes and clean up
	if (stringDataStream)
		delete[] stringDataStream;

	if (stringPoolByteStream)
		delete[] stringPoolByteStream;

	return status;
}

/*	How I discovered a "!_Tables" structure?
	It was quite easy. I noticed a word count in this stream correspond to tables number
	and that's all.

	Each word means a string index in string vector. And it is table name.
*/
bool MsiTableParser::readTableNamesFromMetadata()
{
	bool status = false;
	bool breakAfterLoop = false;
	BYTE* tablesByteStream = nullptr;

	do {
		//get StringData
		DWORD tablesByteStreamSize = 0;
		ASSERT_BREAK(m_cfbExtractor.readAndAllocateStream(Tables_Stream_Name, &tablesByteStream, tablesByteStreamSize));

		WORD* tablesStream = (WORD*)tablesByteStream;
		for (DWORD i = 0; i < tablesByteStreamSize / sizeof(WORD); i++)
		{
			WORD stringIndex = tablesStream[i];
			ASSERT_BREAK_AFTER_LOOP_1(stringIndex < m_vecStrings.size(), breakAfterLoop);
			m_tableNameIndices.push_back(stringIndex);
			m_mapTNStringToTNIndex[m_vecStrings[stringIndex]] = stringIndex;
		}
		ASSERT_BREAK_AFTER_LOOP_2(breakAfterLoop);

		//if you want save stream, uncomment lines
		/*if (tablesByteStream)
		{
			if (writeToFile(Tables_Stream_Name, (const char*)tablesByteStream, tablesByteStreamSize, std::ios::binary))
			{
				std::string msg = std::string(Tables_Stream_Name) + " written to file";
				Log(LogLevel::Info, msg.data());
			}
		}*/

		status = true;
	} while (false);

	return status;
}

/*	How I discovered a "!_Columns" structure?
	Thanks to dynamic analysis with IDA, WIX and my insights.

	STRUCTURE
	"!_Columns" table contains all columns in msi database. Table size is 4 * sizeof(WORD) * columnsCount.
	Why 4? Because each column is described by 4 values. First value is a tableName. It allows match
	column table. Second value is column index. Third is a column name and last is column type. 
	Order in this file is strange. There is no "first column info(tableName), second column info(index), etc" but,
	first column info for each column, then second column info for each column, etc.

	Example:
	We have to tables in database. First table has 3 columns, second has 2. "!_Columns" table (hex):
	07 00 07 00 07 00 22 00 22 00 -> table names
	01 80 02 80 03 80 01 80 02 80 -> indices
	02 00 05 00 10 00 23 00 0B 00 -> column names
	20 AD 20 AD 04 8D FF 9D 48 AD -> column types
*/
bool MsiTableParser::extractColumnsFromMetadata()
{
	bool status = false;

	do {
		DWORD columnsByteStreamSize = 0;
		ASSERT_BREAK(m_cfbExtractor.readAndAllocateStream(Columns_Stream_Name, &m_columnsByteStream, columnsByteStreamSize));

		WORD* columnsStream = (WORD*)m_columnsByteStream;

		//note difference between tableIndex and tableNameIndex
		DWORD tableIndex = 0;
		DWORD columnCount = 0;

		DWORD currTableNameIndex = m_tableNameIndices[0];
		m_tableNameIndexToColumnCountAndOffset[currTableNameIndex].second = m_allColumnsCount;
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
					Log(LogLevel::Warning, "Strange situation with indices in \"extractColumnsFromMetadata()\". Check it.");
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
			Log(LogLevel::Warning, "Strange situation with columnCount in \"extractColumnsFromMetadata()\". Check it.");
		}

		//if you want save stream, uncomment lines
		/*if (m_columnsByteStream)
		{
			if (writeToFile(Columns_Stream_Name, (const char*)m_columnsByteStream, columnsByteStreamSize, std::ios::binary))
			{
				std::string msg = std::string(Columns_Stream_Name) + " written to file";
				Log(LogLevel::Info, msg.data());
			}
		}*/

		status = true;
	} while (false);

	return status;
}

bool MsiTableParser::loadTable(std::string tableName, std::vector<ColumnInfo>& columns, std::vector<std::vector<DWORD>>& table)
{
	bool status = false;
	bool breakAfterLoop = false;

	BYTE* tableByteStream = nullptr;

	do
	{
		DWORD tableNameIndex = 0;
		ASSERT_BREAK(getTableNameIndex(tableName, tableNameIndex));

		ASSERT_BREAK(m_tableNameIndexToColumnCountAndOffset.count(tableNameIndex) > 0);
		const DWORD columnCount = m_tableNameIndexToColumnCountAndOffset[tableNameIndex].first;
		const DWORD columnOffset = m_tableNameIndexToColumnCountAndOffset[tableNameIndex].second;

		columns.resize(columnCount);
		const DWORD Index_ColumnIndex = 1;
		const DWORD Name_ColumnIndex = 2;
		const DWORD Type_ColumnIndex = 3;

		DWORD indicesOffset = Index_ColumnIndex * m_allColumnsCount + columnOffset;
		DWORD namesOffset = Name_ColumnIndex * m_allColumnsCount + columnOffset;
		DWORD typesOffset = Type_ColumnIndex * m_allColumnsCount + columnOffset;

		WORD* columnsStream = (WORD*)m_columnsByteStream;
		DWORD oneRowByteSize = 0;

		//this loop help load columns info for CustomAction table
		for (DWORD j = 0; j < columnCount; j++)
		{
			//indices. Indices have always highest bit set to 1, I don't know why. Ignore it
			columns[j].index = columnsStream[indicesOffset + j] & 0x7fff;

			//names
			WORD nameId = columnsStream[namesOffset + j];
			ASSERT_BREAK_AFTER_LOOP_1(nameId < m_vecStrings.size(), breakAfterLoop);
			columns[j].name = m_vecStrings[nameId];

			//types
			getColumnType(columnsStream[typesOffset + j], columns[j].type);

			//there is possible store DWORD. In this case we need read 4 bytes, not 2
			if (columns[j].type.kind == ColumnKind::Number && columns[j].type.value == 4)
			{
				oneRowByteSize += 4;
			}
			else
			{
				oneRowByteSize += 2;
			}
		}
		ASSERT_BREAK_AFTER_LOOP_2(breakAfterLoop);

		DWORD tableByteStreamSize = 0;
		const std::string streamName = "!" + tableName;
		ASSERT_BREAK(m_cfbExtractor.readAndAllocateStream(streamName, &tableByteStream, tableByteStreamSize));

		const DWORD rowCount = tableByteStreamSize / oneRowByteSize;
		if (tableByteStreamSize % oneRowByteSize)
		{
			Log(LogLevel::Warning, "Something wrong: tableByteStreamSize % oneRowByteSize = ",
				tableByteStreamSize % oneRowByteSize);
			break;
		}

		//we can allocate memory for customTable data
		table.resize(rowCount);
		for (auto& vec : table)
		{
			vec.resize(columns.size());
		}

		BYTE* tableStream = tableByteStream;

		//load table to vector
		for (DWORD i = 0; i < columns.size(); i++)
		{
			DWORD fieldSize = sizeof(WORD);

			//there is possible store DWORD. In this case we need read 4 bytes, not 2
			if (columns[i].type.kind == ColumnKind::Number && columns[i].type.value == 4)
			{
				fieldSize = sizeof(DWORD);
			}

			for (DWORD j = 0; j < rowCount; j++)
			{
				::memcpy(&table[j][i], tableStream, fieldSize);
				tableStream += fieldSize;
			}
		}

		status = true;
	} while (false);

	while (false);

	if (tableByteStream)
		delete[] tableByteStream;

	return status;
}

bool MsiTableParser::loadProperties()
{
	bool status = false;
	bool breakAfterLoop = false;

	BYTE* tableByteStream = nullptr;
	do
	{
		std::vector<ColumnInfo> columns;
		std::vector<std::vector<DWORD>> table;
		ASSERT_BREAK(loadTable(Property_Table_Name, columns, table));
		for (auto vec : table)
		{
			ASSERT_BREAK_AFTER_LOOP_1(vec[0] < m_stringCount, breakAfterLoop);
			std::string key = m_vecStrings[vec[0]];

			ASSERT_BREAK_AFTER_LOOP_1(vec[1] < m_stringCount, breakAfterLoop);
			std::string value = m_vecStrings[vec[1]];

			m_mapProperties[key] = value;
		}
		ASSERT_BREAK_AFTER_LOOP_2(breakAfterLoop);

		status = true;
	} while (false);

	while (false);

	if (tableByteStream)
		delete[] tableByteStream;

	return status;
}

/* How do I know "customAction" constatns (eg. bit masks)?

	My knowledge in this field is based on WIX, excatly on "MsiInterop.cs" and "Decompiler.cs". 
	There is information how to retrieve all information from customAction table.

	In each table is similar situation like in "!_Columns". Firstly we have first column value for
	each row, next second, etc. 
*/
bool MsiTableParser::analyzeCustomActionTable()
{
	bool status = false;
	bool breakAfterLoop = false;

	BYTE* customActionByteStream = nullptr;
	std::ofstream reportStream;
	do {
		std::vector<ColumnInfo> cAColumns;
		std::vector<std::vector<DWORD>> customActionTable;
		ASSERT_BREAK(loadTable(CustomAction_Table_Name, cAColumns, customActionTable));

		const std::string reportFileName = "msiAnalyzeReport.txt";
		reportStream.open(reportFileName);
		if (!reportStream)
		{
			Log(LogLevel::Error, "Cannot open report file");
			break;
		}

		//analyze data in customAction table
		const char Script_Preamble[] = "\1ScriptPreamble\2";
		bool scriptPreambleIsPresent = false;
		std::string scriptPreamble;

		for (auto row : customActionTable)
		{
			//read row
			if (cAColumns[0].type.kind != ColumnKind::OrdString)
			{
				Log(LogLevel::Warning, "First column in CustomAction should be a string");
				ASSERT_BREAK_AFTER_LOOP_1(false, breakAfterLoop);
			}
			
			std::string id = m_vecStrings[row[0]];
			if (id.empty())
				id = "unknown_id";

			if (cAColumns[1].type.kind != ColumnKind::Number)
			{
				Log(LogLevel::Warning, "Second column in CustomAction should be number");
				ASSERT_BREAK_AFTER_LOOP_1(false, breakAfterLoop);
			}
			DWORD type = row[1];

			if (cAColumns[2].type.kind != ColumnKind::OrdString)
			{
				Log(LogLevel::Warning, "Third column in CustomAction should be a string");
				ASSERT_BREAK_AFTER_LOOP_1(false, breakAfterLoop);
			}
			ASSERT_BREAK_AFTER_LOOP_1(row[2] < m_stringCount, breakAfterLoop);
			std::string actionSource = m_vecStrings[row[2]];

			if (cAColumns[3].type.kind != ColumnKind::OrdString)
			{
				Log(LogLevel::Warning, "Fourth column in CustomAction should be a string");
				ASSERT_BREAK_AFTER_LOOP_1(false, breakAfterLoop);
			}
			ASSERT_BREAK_AFTER_LOOP_1(row[3] < m_stringCount, breakAfterLoop);
			std::string actionContent = m_vecStrings[row[3]];
			//end read row

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
				else if (actionSourceType == ActionSourceType::Property)
				{
					//it can be powershell
					const char AI_DATA_SETTER[] = "AI_DATA_SETTER";
					if (id.compare(0, sizeof(AI_DATA_SETTER) - 1, AI_DATA_SETTER) == 0)
					{
						if (actionSource.compare("CustomActionData") == 0)
						{
							//script
							const char PS1_Script_Magic[] = "\1Script\2";
							DWORD scriptMagicBegin = actionContent.find(PS1_Script_Magic);
							if (scriptMagicBegin != std::string::npos)
							{
								//this is powershell script
								const char Params_Magic[] = "\1Params\2";
								std::string params;
								DWORD paramsMagicBegin = actionContent.find(Params_Magic);
								if (paramsMagicBegin != std::string::npos)
								{
									DWORD paramsBegin = paramsMagicBegin + sizeof(Params_Magic) - 1;
									ASSERT_BREAK_AFTER_LOOP_1(scriptMagicBegin > paramsBegin, breakAfterLoop);
									params = "#INPUT PARAMETERS\r\n#" + actionContent.substr(paramsBegin, scriptMagicBegin - paramsBegin) + "\r\n";
								}

								std::string actionContentCopy = actionContent;

								DWORD scriptBegin = scriptMagicBegin + sizeof(PS1_Script_Magic) - 1;
								actionContent = actionContent.substr(scriptBegin);
								actionTargetType = ActionTargetType::PS1Content;

								DWORD scriptPreambleMagicBegin = actionContent.find(Script_Preamble, scriptBegin);
								if (scriptPreambleMagicBegin != std::string::npos)
								{
									DWORD scriptPreambleBegin = scriptPreambleMagicBegin + sizeof(Script_Preamble) - 1;
									actionContent = actionContent.substr(0, scriptPreambleMagicBegin);

									if (!scriptPreambleIsPresent)
									{
										scriptPreamble = actionContentCopy.substr(scriptBegin + scriptPreambleBegin);
										scriptPreambleIsPresent = true;
									}
								}
								ASSERT_BREAK_AFTER_LOOP_1(transformPS1Script(actionContent, actionContent), breakAfterLoop);
								actionContent = params + actionContent;

								//add apropriate extenstion
								if (id.size() >= 5 && id.substr(id.size() - 5, 5).compare(".psm1") == 0)
								{
									//nothing to do
									
								}
								else if (id.size() >= 4 && id.substr(id.size() - 4, 4).compare(".ps1") == 0)
								{
									//nothing to do
								}
								else
								{
									id += ".ps1";
								}
								break;
							}
						}
						const char PS1_Call_Magic[] = "\1Property\2";
						DWORD propertyBegin = actionContent.find(PS1_Call_Magic);

						if (propertyBegin != std::string::npos)
						{
							DWORD pathBegin = actionContent.find("\2", propertyBegin + 1);
							DWORD pathEnd = actionContent.find("\1", pathBegin + 1);
							if (pathBegin != std::string::npos && pathEnd != std::string::npos)
							{
								std::string actionContentCopy = actionContent;
								actionContent = actionContent.substr(pathBegin + 1, pathEnd - pathBegin - 1);
								actionTargetType = ActionTargetType::PS1Call;

								if (!scriptPreambleIsPresent)
								{
									DWORD scriptPreambleMagicBegin = actionContentCopy.find(Script_Preamble, pathEnd);
									if (scriptPreambleMagicBegin != std::string::npos)
									{
										DWORD scriptPreambleBegin = scriptPreambleMagicBegin + sizeof(Script_Preamble) - 1;
										scriptPreamble = actionContentCopy.substr(scriptPreambleBegin);
										scriptPreambleIsPresent = true;
									}
								}
							}
						}
					}	
				}
				break;
			case ActionTargetType::JSCall:
				if (actionSourceType == ActionSourceType::Directory)
				{
					actionTargetType = ActionTargetType::JSContent;

					//add apropriate extenstion
					if (id.size() < 3 || id.substr(id.size() - 3, 3).compare(".js") != 0)
					{
						id += ".js";
					}
				}
				break;
			case ActionTargetType::VBSCall:
				if (actionSourceType == ActionSourceType::Directory)
				{
					actionTargetType = ActionTargetType::VBSContent;

					//add apropriate extenstion
					
					if (id.size() >= 4 && id.substr(id.size() - 4, 4).compare(".vbs") == 0)
					{
						//nothing to do
					}
					else if (id.size() >= 3 && id.substr(id.size() - 3, 3).compare(".vb") == 0)
					{
						//nothing to do
					}
					else
					{
						id += ".vbs";
					}
				}
				break;

			//add powershell scripts

			default:
				Log(LogLevel::Warning, "Unknown custom target type");
				continue;
			}

			switch (actionTargetType)
			{
			//save script to separate file
			case ActionTargetType::JSContent:
			case ActionTargetType::VBSContent:
			case ActionTargetType::PS1Content:
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
				
				std::string scriptPath = scriptFolder + "\\" + id;
				ASSERT_BREAK_AFTER_LOOP_1(writeToFile(scriptPath, actionContent.data(), actionContent.size(), std::ios::binary), breakAfterLoop);
				break;
			}
			//and every action to report
			default:
			{
				//dealing with properties
				ASSERT_BREAK_AFTER_LOOP_1(useProperties(actionContent, actionContent), breakAfterLoop);

				if (actionSourceType == ActionSourceType::Property)
				{
					if (actionTargetType == ActionTargetType::Text)
					{
						m_mapProperties[actionSource] = actionContent;
					}
					else if (m_mapProperties.count(actionSource) > 0)
					{
						actionSource = m_mapProperties[actionSource];
					}		
				}

				reportStream << "ID: " << id << " \t" << s_mapActionScourceEnumToString[actionSourceType] <<
					" = \"" << actionSource << "\" \t" << s_mapActionTargetEnumToString[actionTargetType] <<
					" = \"" << actionContent << "\"" << std::endl;
				break;
			}
			}
		}
		ASSERT_BREAK_AFTER_LOOP_2(breakAfterLoop);

		if (scriptPreambleIsPresent)
		{
			const std::string scriptsDirectoryName = "scripts";
			if (!std::experimental::filesystem::exists(scriptsDirectoryName))
			{
				if (!std::experimental::filesystem::create_directories(scriptsDirectoryName))
				{
					Log(LogLevel::Warning, "Can't create \"scripts\" folder");
					return false;
				}
			}

			std::string scriptPreamblePath = scriptsDirectoryName + "\\ScriptPreamble.ps1";
			//if (std::experimental::filesystem::exists(scriptFolder))
			//{
			//	Log(LogLevel::Warning, "Scripts folder already exist.");

			//	//add random suffix
			//	std::srand(static_cast<DWORD>(std::time(nullptr)));
			//	DWORD suffix = std::rand();
			//	scriptPreamblePath += std::to_string(suffix);
			//}

			ASSERT_BREAK(transformPS1Script(scriptPreamble, scriptPreamble));
			ASSERT_BREAK(writeToFile(scriptPreamblePath, scriptPreamble.data(), scriptPreamble.size(), std::ios::binary));
		}

		//if you want save stream, uncomment lines
		/*if (customActionByteStream)
		{
			if (writeToFile(CustomAction_Stream_Name, (const char*)customActionByteStream, customActionByteStreamSize, std::ios::binary))
			{
				std::string msg = std::string(CustomAction_Stream_Name) + " written to file";
				Log(LogLevel::Info, msg.data());
			}
		}*/
		status = true;
	} 
	while (false);

	if (customActionByteStream)
		delete[] customActionByteStream;

	if (reportStream.is_open())
		reportStream.close();

	return status;
}

bool MsiTableParser::printTable(const std::string tableName, const std::string tablePath)
{
	std::string msg = "Printing \"" + tableName + "\" table";
	Log(LogLevel::Info, msg.data());
	bool status = false;
	bool breakAfterLoop = false;

	std::ofstream tableOutStream(tablePath);
	if (!tableOutStream)
	{
		Log(LogLevel::Error, "Cannot open report file");
		return false;
	}

	BYTE* tableByteStream = nullptr;
	do
	{
		std::vector<ColumnInfo> columns;
		std::vector<std::vector<DWORD>> table;
		ASSERT_BREAK(loadTable(tableName, columns, table));

		//print column names
		tableOutStream <<"\t|\t";
		for (auto col : columns)
		{
			tableOutStream << col.name << " \t|\t" ;
		}
		tableOutStream << "\r\n";

		int index = 1;
		for (auto vec : table)
		{
			tableOutStream << index++ << ".\t";
			for (DWORD i = 0; i < vec.size(); i++)
			{
				const ColumnTypeInfo& t = columns[i].type;
				if (t.kind == ColumnKind::LocString || t.kind == ColumnKind::OrdString)
				{
					ASSERT_BREAK_AFTER_LOOP_1(vec[i] < m_vecStrings.size(), breakAfterLoop);
					const std::string& s = m_vecStrings[vec[i]];
					if (s.size() > t.value)
					{
						tableOutStream << s.substr(t.value);
					}
					else
					{
						tableOutStream << s;
					}

				}
				else if (t.kind == ColumnKind::Number)
				{
					tableOutStream << vec[i];
				}
				else
				{
					//unknown type. Print it in hex
					tableOutStream << std::hex << vec[i];
				}

				if(i != vec.size() - 1)
					tableOutStream << " \t|\t ";
			}
			ASSERT_BREAK_AFTER_LOOP_2(breakAfterLoop);
			tableOutStream << std::endl;
		}

		status = true;
	} while (false);

	while (false);

	if (tableByteStream)
		delete[] tableByteStream;

	if (tableOutStream.is_open())
		tableOutStream.close();

	return status;
}

bool MsiTableParser::printAllTables()
{
	//create "tables" directory
	const std::string tablesDirectoryName = "tables";
	if (!std::experimental::filesystem::exists(tablesDirectoryName))
	{
		if (!std::experimental::filesystem::create_directories(tablesDirectoryName))
		{
			Log(LogLevel::Warning, "Can't create \"tables\" dir");
			return false;
		}
	}
	//end

	for (auto i : m_mapTNStringToTNIndex)
	{
		std::string tablePath = tablesDirectoryName + "\\" + i.first;
		printTable(i.first, tablePath);
	}
	return true;
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

bool MsiTableParser::transformPS1Script(const std::string rawScript, std::string& decodedScript)
{
	decodedScript.clear();
	decodedScript.reserve(rawScript.size());

	for (DWORD i = 0; i < rawScript.size(); i++)
	{
		if (rawScript[i] == '[')
		{
			if (rawScript.size() < i + 3)
			{
				Log(LogLevel::Warning, "PS1 script is truncated");
				return false;
			}

			if (rawScript[i + 1] == '\\' && rawScript[i + 3] == ']')
			{
				decodedScript += rawScript[i + 2];
				i += 3;
			}
		}
		else
		{
			decodedScript += rawScript[i];
		}
	}

	return true;
}

bool MsiTableParser::useProperties(std::string inputString, std::string& outputString)
{
	std::smatch property_match;
	std::regex property_regex("(\\[)([a-zA-Z0-9_]+)(\\])");
	if (std::regex_search(inputString, property_match, property_regex))
	{
		outputString = ""; 
		while (std::regex_search(inputString, property_match, property_regex))
		{
			outputString += property_match.prefix();;
			std::string key = property_match[2].str();
			if (m_mapProperties.count(key) > 0)
			{
				outputString += m_mapProperties[key];
			}
			else
			{
				outputString += property_match[0].str();;
			}
			inputString = property_match.suffix();
		}
		outputString += inputString;
	}
	return true;
}