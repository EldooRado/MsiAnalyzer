#include <fstream>
#include <filesystem>

#include "CfbExtractor.h"
#include "MsiTableParser.h"
#include "LogHelper.h"

int main(int argc, char* argv[])
{
	std::string szMsiPath;
	std::string outpuDir = "";

	if (argc != 2 && argc != 3)
	{
		std::cout << "MsiAnalyzer.exe <msi_file> or" << std::endl;
		std::cout << "MsiAnalyzer.exe <msi_file> <output_dir>" << std::endl;
		return -2;
	}

	//get input msi
	if (argc >= 2)
	{
		szMsiPath = std::string(argv[1]);

		if (!std::experimental::filesystem::exists(szMsiPath))
		{
			std::cout << "Given file not exists" << std::endl;
			return -2;
		}
	}

	//get output dir
	if(argc == 3)
	{
		outpuDir = std::string(argv[2]);

		if (std::experimental::filesystem::exists(outpuDir))
		{
			std::string msg = "\"" + outpuDir + "\" dir created";
			Log(LogLevel::Info, msg.data());
		}
		else
		{
			Log(LogLevel::Warning, "Given output dir exists");
			if (!std::experimental::filesystem::create_directories(outpuDir))
			{
				std::cout<< "Can't create \""<< outpuDir  <<"\" dir";
				return false;
			}
		}
	}

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
	ASSERT_ERROR_LOG(extractor.initialize(szMsiPath));
	Log(LogLevel::Info, "Successful initialization of the extractor");

	ASSERT_ERROR_LOG(extractor.parseCfbHeader());
	Log(LogLevel::Info, "Successful parsing of the cfbHeader");

	ASSERT_ERROR_LOG(extractor.loadFatEntries());
	Log(LogLevel::Info, "Successful loading of the fatEntries");

	ASSERT_ERROR_LOG(extractor.loadMiniFatEntries());
	Log(LogLevel::Info, "Successful loading of the miniFatEntries");

	ASSERT_ERROR_LOG(extractor.loadDirEntries());
	Log(LogLevel::Info, "Successful loading of the dirEntries");

	ASSERT_ERROR_LOG(extractor.loadMiniStreamEntries());
	Log(LogLevel::Info, "Successful loading of the miniStreamEntries");

	//get a stream names
	ASSERT_ERROR_LOG(extractor.initRedableStreamNamesFromRawNames());
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
	MsiTableParser parser(extractor, outpuDir);
	//	!_StringPool and !_StringData
	ASSERT_ERROR_LOG(parser.initStringVector());
	Log(LogLevel::Info, "Successful initialization of the msi strings");

	//	!_Tables
	ASSERT_ERROR_LOG(parser.readTableNamesFromMetadata());
	Log(LogLevel::Info, "Successful printing of !_Tables");

	//	!_Columns
	ASSERT_ERROR_LOG(parser.extractColumnsFromMetadata());
	Log(LogLevel::Info, "Successful extraction of !_Columns");

	//	!Property
	ASSERT_ERROR_LOG(parser.loadProperties());
	Log(LogLevel::Info, "Successful loading of !Properties");

	//	!CustomAction
	DWORD savedScriptsCount = 0;
	DWORD savedActionsCount = 0;
	ASSERT_ERROR_LOG(parser.analyzeCustomActionTable(savedScriptsCount, savedActionsCount));
	Log(LogLevel::Info, "Successful analysis of !CustomTable");

	bool AI_FileDownload_IsPresent = false;
	bool MPB_RunActions_IsPresent = false;
	DWORD tablesNumber = 0;
	ASSERT_ERROR_LOG(parser.saveAllTables(AI_FileDownload_IsPresent, MPB_RunActions_IsPresent, tablesNumber));
	Log(LogLevel::Info, "Successful saving all tables");

	DWORD savedFilesCount = 0;
	ASSERT_ERROR_LOG(parser.saveAllFiles(savedFilesCount));
	Log(LogLevel::Info, "Successful saving all binaries");

	//PRODUCE REPORT
	std::ofstream reportStream(outpuDir + "\\analyzeReport.txt");
	if (!reportStream)
	{
		Log(LogLevel::Warning, "Can't open \"analyzeReport.txt\" file");
		return -2;
	}

	reportStream << "----------REPORT----------" << std::endl;
	reportStream << "Msi path: " << szMsiPath << std::endl;
	reportStream << "Tables number:  \t" << tablesNumber << "\tSee \"<output_dir>\\tables\" directory" << std::endl;

	if(savedFilesCount > 0)
		reportStream << "Files number:   \t" << savedFilesCount <<"\tSee \"<output_dir>\\files\" directory"<< std::endl;

	if (savedScriptsCount > 0)
		reportStream << "Scripts number: \t" << savedScriptsCount << "\tSee \"<output_dir>\\scripts\" directory" << std::endl;

	if (savedActionsCount > 0)
		reportStream << "Actions number: \t" << savedActionsCount << "\tSee \"<output_dir>\\actions.txt file" << std::endl;

	if (AI_FileDownload_IsPresent || MPB_RunActions_IsPresent)
		reportStream << "\r\nTool specific table is present. It can be dangerous:" << std::endl;

	if (AI_FileDownload_IsPresent)
		reportStream << "AdvancedInstaller feature that allows to download a file during installation. See: \"<output_dir>\\tables\\AI_FileDownload\" table" << std::endl;

	if (MPB_RunActions_IsPresent)
		reportStream << "EMCO feature that supports additional actions. See: \"<output_dir>\\tables\\MPB_RunActions\" table" << std::endl;


	reportStream.close();

	std::cout << "\n----------SUCCESS----------" << std::endl;
	return 0;
}