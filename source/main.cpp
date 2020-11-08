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
	CfbExtractor extractor;
	ASSERT(extractor.initialize(szMsiName));
	Log(LogLevel::Info, "Success of initialize extractor");

	ASSERT(extractor.parseCfbHeader());
	Log(LogLevel::Info, "Success of parsing cfbHeader");

	ASSERT(extractor.loadFatEntries());
	Log(LogLevel::Info, "Success of loading fatEntries");

	ASSERT(extractor.loadMiniFatEntries());
	Log(LogLevel::Info, "Success of loading miniFatEntries");

	ASSERT(extractor.loadDirEntries());
	Log(LogLevel::Info, "Success of loading dirEntries");

	ASSERT(extractor.loadMiniStreamEntries());
	Log(LogLevel::Info, "Success of loading miniStreamEntries");

	//get a stream names
	extractor.initTableNames();

	MsiTableParser parser(extractor);

	//init strings
	ASSERT(parser.initStringVector());

	//print "!_Tables" table
	ASSERT(parser.printTablesFromMetadata());

	//analyze "!_Columns" table
	ASSERT(parser.extractColumnsFromMetadata());

	//print "!CustomAction" table
	ASSERT(parser.printCustomActionTable());

	Log(LogLevel::Info, "\n----------SUCCESS----------");
	return 0;
}