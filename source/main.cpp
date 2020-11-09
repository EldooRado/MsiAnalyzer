#include <fstream>
#include <filesystem>

#include "CfbExtractor.h"
#include "MsiTableParser.h"
#include "LogHelper.h"

int main(int argc, char* argv[])
{
	std::string szMsiName;
	/*if (argc == 2)
	{
		szMsiName = std::string(argv[1]);

		if (!std::experimental::filesystem::exists(szMsiName))
		{
			std::cout << "Given file not exists" << std::endl;
			return -2;
		}
	}
	else
	{
		std::cout << "MsiAnalyzer.exe <msi_file>" << std::endl;
		return -2;
	}*/
	szMsiName = "C:\\work\\msi\\tools\\wixedit-0.7.5.msi";

	/*	How to analyze compoud file binary?
		1. check a header and get important information
		2. load fat entries (fat array contains metadata information about stream)
			PS. If file is huge, then we need firstly load difat array, which contains
			infomraiton about fat array
		3. load mini fat entries (similarly like fat, but store metadata about ministream)
		4. load dir section (it store infromation about type of data: storage, stream, ministream)
		5. load ministream section (ministream store small streams, where size is less than section size)
		
	*/
	CfbExtractor extractor;
	ASSERT(extractor.initialize(szMsiName));
	Log(LogLevel::Info, "Successful initialization of the extractor");

	ASSERT(extractor.parseCfbHeader());
	Log(LogLevel::Info, "Successful parsing of the cfbHeader");

	ASSERT(extractor.loadFatEntries());
	Log(LogLevel::Info, "Successful loading of the fatEntries");

	ASSERT(extractor.loadMiniFatEntries());
	Log(LogLevel::Info, "Successful loading of the miniFatEntries");

	ASSERT(extractor.loadDirEntries());
	Log(LogLevel::Info, "Successful loading of the dirEntries");

	ASSERT(extractor.loadMiniStreamEntries());
	Log(LogLevel::Info, "Successful loading of the miniStreamEntries");

	//get a stream names
	ASSERT(extractor.initRedableStreamNamesFromRawNames());
	Log(LogLevel::Info, "Successful initializing of the readableStreamNames");


	/*	How to analyze msi file?
		1. load !_StringPool and !_StringData. Then extract every string in msi file.
		2. load !_Tables and get table names
		3. load !_Columns and get information about every column in every table
		Then all metadata information is loaded.

		PS. There is a on more metadata table "!_Validationa". It allows to validate every tables.

		At this moment we can get information from interesting tables. Which are interesting?
		It depends on our purpose. If we want check, what msi file can do during installation,
		then we should analyze !_CustomAction.

	*/
	MsiTableParser parser(extractor);
	//	!_StringPool and !_StringData
	ASSERT(parser.initStringVector());
	Log(LogLevel::Info, "Successful initialization of the msi strings");

	//	!_Tables
	ASSERT(parser.readTableNamesFromMetadata());
	Log(LogLevel::Info, "Successful printing of !_Tables");

	//	!_Columns
	ASSERT(parser.extractColumnsFromMetadata());
	Log(LogLevel::Info, "Successful extraction of !_Columns");

	//	!CustomAction
	ASSERT(parser.analyzeCustomActionTable());
	Log(LogLevel::Info, "Successful analysis of !CustomTable");

	Log(LogLevel::Info, "\n----------SUCCESS----------");
	return 0;
}