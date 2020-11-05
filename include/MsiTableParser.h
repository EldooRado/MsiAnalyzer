#pragma once
#include "Ole2Extractor.h"

class MsiTableParser
{
private:
	//constants
	static constexpr char StringData_Table_Name[] = "!_StringData";
	static constexpr char StringPool_Table_Name[] = "!_StringPool";
	static constexpr char Tables_Table_Name[] = "!_Tables";
	static constexpr char Columns_Table_Name[] = "!_Columns";

	//members

	//when I try make it const, then some methods from Ole2Extractor must be const
	// and then occurs problem with templates. Strange thing
	Ole2Extractor& m_oleExtractor;
	std::vector<std::string> m_vecStrings;
	std::vector<DWORD> m_tableNameIndices;

	//key: tableIndex, value: columnCount
	std::map<DWORD, DWORD> m_columnCount; 

	//methods
public:
	MsiTableParser(Ole2Extractor& extractor);
	bool initStringVector();
	bool printTablesFromMetadata();
	bool printColumnsFromMetadata();

private:
	bool writeToFile(std::string fileName, const char* pStream, size_t streamSize);
};