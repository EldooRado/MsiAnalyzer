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
	static constexpr char CustomAction_Stream_Name[] = "!CustomAction";
	static constexpr char CustomAction_Table_Name[] = "CustomAction";

	//MEMBERS
	//when I try make it const, then some methods from CfbExtractor must be const
	// and then occurs problem with templates. Strange thing
	CfbExtractor& m_cfbExtractor;
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

	//METHODS
public:
	MsiTableParser(CfbExtractor& extractor);
	~MsiTableParser();
	bool initStringVector();
	bool readTableNamesFromMetadata();
	bool extractColumnsFromMetadata();
	bool analyzeCustomActionTable();

private:
	bool writeToFile(std::string fileName, const char* pStream, size_t streamSize, std::ios_base::openmode mod = std::ios::out);
	bool getTableNameIndex(std::string tableName, DWORD& index);
	void getColumnType(WORD columnWordType, ColumnTypeInfo& columnTypeInfo);

	//statics
	//key: ActionTargetType, value: script extension (".js" or ".vbs")
	static std::map<ActionTargetType, std::string> s_mapScriptTypeToExt;
	//key: ActionTargetType, value: actionTarget name (eg. "ExeCommand")
	static std::map<ActionTargetType, std::string> s_mapActionTargetEnumToString;
	//key: ActionSourceType, value: actionSource name (eg. "Directory")
	static std::map<ActionSourceType, std::string> s_mapActionScourceEnumToString;
};