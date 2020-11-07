#pragma once
#include "Ole2Extractor.h"

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
	//when I try make it const, then some methods from Ole2Extractor must be const
	// and then occurs problem with templates. Strange thing
	Ole2Extractor& m_oleExtractor;
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
	MsiTableParser(Ole2Extractor& extractor);
	~MsiTableParser();
	bool initStringVector();
	bool printTablesFromMetadata();
	bool extractColumnsFromMetadata();
	bool printCustomActionTable();

private:
	bool writeToFile(std::string fileName, const char* pStream, size_t streamSize);
	bool getTableNameIndex(std::string tableName, DWORD& index);
	void getColumnType(WORD columnWordType, ColumnTypeInfo& columnTypeInfo);
};