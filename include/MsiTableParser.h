#pragma once
#include <map>

#include "CfbExtractor.h"
#include "customActionConstants.h"

enum class ColumnKind
{
	OrdString, //ordinal string
	LocString, //localized string
	Number,
	Unknown
};

struct ColumnTypeInfo
{
	ColumnKind kind;
	WORD value;
};

struct ColumnInfo
{
	WORD index;
	std::string name;
	ColumnTypeInfo type;
};

class MsiTableParser
{
private:
	//CONSTANTS
	//metadata table names
	static constexpr char StringData_Stream_Name[] = "!_StringData";
	static constexpr char StringPool_Stream_Name[] = "!_StringPool";
	static constexpr char Tables_Stream_Name[] = "!_Tables";
	static constexpr char Columns_Stream_Name[] = "!_Columns";

	//ordinary table names
	static constexpr char CustomAction_Table_Name[] = "CustomAction";
	static constexpr char Property_Table_Name[] = "Property";
	static constexpr char AI_FileDownload_Table_Name[] = "AI_FileDownload";
	static constexpr char MPB_RunActions_Table_Name[] = "MPB_RunActions";

	//MEMBERS
	//when I try make it const, then some methods from CfbExtractor must be const
	// and then occurs problem with templates. Strange thing
	CfbExtractor& m_cfbExtractor;
	const std::string m_outputDir;
	const std::string m_scriptsDir;
	const std::string m_tablesDir;
	const std::string m_filesDir;

	std::vector<std::string> m_vecStrings;
	std::vector<DWORD> m_tableNameIndices;
	
	DWORD m_stringCount = 0;
	BYTE* m_columnsByteStream = nullptr;
	DWORD m_allColumnsCount = 0;
	

	//key: tableNameIndex, value: std::pair<columnCount, columnOffset> 
	//(columnOffset is a index of the first column for table in !_Columns
	std::map<DWORD, std::pair<DWORD, DWORD>> m_tableNameIndexToColumnCountAndOffset;

	//key: tableNameString, value: tableNameId.		TableName -> TN
	std::map<std::string, DWORD> m_mapTNStringToTNIndex;

	//key: propertyName, value: propertyName
	std::map<std::string, std::string> m_mapProperties;

	//METHODS
public:
	MsiTableParser(CfbExtractor& extractor, const std::string outDir);
	~MsiTableParser();
	bool initStringVector();
	bool readTableNamesFromMetadata();
	bool extractColumnsFromMetadata();
	bool loadProperties();
	bool analyzeCustomActionTable(DWORD& saveScriptsCount, DWORD& savedActionsCount);
	bool saveAllTables(bool& AI_FileDownload_IsPresent, bool& MPB_RunActions_IsPresent, DWORD& tablesNumber);
	bool saveAllFiles(DWORD& savedFilesCount);

private:
	bool writeToFile(std::string fileName, const char* pStream, size_t streamSize, std::ios_base::openmode mod = std::ios::out);
	bool getTableNameIndex(std::string tableName, DWORD& index);
	void getColumnType(WORD columnWordType, ColumnTypeInfo& columnTypeInfo);
	bool transformPS1Script(const std::string rawScript, std::string& decodedScript);
	bool loadTable(std::string tableName, std::vector<ColumnInfo>& columns, std::vector<std::vector<DWORD>>& table);
	bool useProperties(std::string inputString, std::string& outputString);
	bool saveTable(const std::string tableName, const std::string tablePath);

	//statics
	//key: ActionTargetType, value: actionTarget name (eg. "ExeCommand")
	static std::map<ActionTargetType, std::string> s_mapActionTargetEnumToString;
	//key: ActionSourceType, value: actionSource name (eg. "Directory")
	static std::map<ActionSourceType, std::string> s_mapActionScourceEnumToString;
};