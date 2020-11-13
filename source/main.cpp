#include <fstream>
#include <filesystem>

#include "CfbExtractor.h"
#include "MsiTableParser.h"
#include "LogHelper.h"

int analyzeMsi(std::string szMsiPath, std::string outpuDir);

int main(int argc, char* argv[])
{
	//return -1; means problem with command line args 
	//return -2; means problem with parse msi
	//return -3; means problem with fiel or dir creation

	std::string szMsiPath;
	std::string outpuDir = "";
	if (argc != 2 && argc != 3)
	{
		std::cout << "MsiAnalyzer.exe <msi_file> or" << std::endl;
		std::cout << "MsiAnalyzer.exe <msi_file> <output_dir>" << std::endl;
		return -1;
	}

	//get input msi
	if (argc >= 2)
	{
		szMsiPath = std::string(argv[1]);

		if (!std::experimental::filesystem::exists(szMsiPath))
		{
			std::cout << "Given file not exists" << std::endl;
			return -3;
		}
	}

	//get output dir
	if (argc == 3)
	{
		outpuDir = std::string(argv[2]);

		if (!std::experimental::filesystem::exists(outpuDir))
		{
			std::cout << "WARNING: Given output dir exists"<<std::endl;
			if (!std::experimental::filesystem::create_directories(outpuDir))
			{
				std::cout << "Can't create \"" << outpuDir << "\" dir" << std::endl;
				return -2;
			}
		}
	}

	LogHelper::init("logOutput.txt");
	int status = analyzeMsi(szMsiPath, outpuDir);
	LogHelper::deinit();

	if (status == 0)
	{
		std::cout << "\n----------SUCCESS----------" << std::endl;
	}
	else
	{
		std::cout << "\n----------FAILURE----------" << std::endl;
	}
	return status;
}

//make initialization for main
int analyzeMsi(std::string szMsiPath, std::string outpuDir)
{
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
	ASSERT(extractor.initialize(szMsiPath));
	LogHelper::PrintLog(LogLevel::Info, "Successful initialization of the extractor");

	ASSERT(extractor.parseCfbHeader());
	LogHelper::PrintLog(LogLevel::Info, "Successful parsing of the cfbHeader");

	ASSERT(extractor.loadFatEntries());
	LogHelper::PrintLog(LogLevel::Info, "Successful loading of the fatEntries");

	ASSERT(extractor.loadMiniFatEntries());
	LogHelper::PrintLog(LogLevel::Info, "Successful loading of the miniFatEntries");

	ASSERT(extractor.loadDirEntries());
	LogHelper::PrintLog(LogLevel::Info, "Successful loading of the dirEntries");

	ASSERT(extractor.loadMiniStreamEntries());
	LogHelper::PrintLog(LogLevel::Info, "Successful loading of the miniStreamEntries");

	//get a stream names
	ASSERT(extractor.initRedableStreamNamesFromRawNames());
	LogHelper::PrintLog(LogLevel::Info, "Successful initializing of the readableStreamNames");


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
	ASSERT(parser.initStringVector());
	LogHelper::PrintLog(LogLevel::Info, "Successful initialization of the msi strings");

	//	!_Tables
	ASSERT(parser.readTableNamesFromMetadata());
	LogHelper::PrintLog(LogLevel::Info, "Successful printing of !_Tables");

	//	!_Columns
	ASSERT(parser.extractColumnsFromMetadata());
	LogHelper::PrintLog(LogLevel::Info, "Successful extraction of !_Columns");

	//	!Property
	ASSERT(parser.loadProperties());
	LogHelper::PrintLog(LogLevel::Info, "Successful loading of !Properties");

	//	!CustomAction
	DWORD savedScriptsCount = 0;
	DWORD savedActionsCount = 0;
	ASSERT(parser.analyzeCustomActionTable(savedScriptsCount, savedActionsCount));
	LogHelper::PrintLog(LogLevel::Info, "Successful analysis of !CustomTable");

	bool AI_FileDownload_IsPresent = false;
	bool MPB_RunActions_IsPresent = false;
	DWORD tablesNumber = 0;
	ASSERT(parser.saveAllTables(AI_FileDownload_IsPresent, MPB_RunActions_IsPresent, tablesNumber));
	LogHelper::PrintLog(LogLevel::Info, "Successful saving all tables");

	DWORD savedFilesCount = 0;
	ASSERT(parser.saveAllFiles(savedFilesCount));
	LogHelper::PrintLog(LogLevel::Info, "Successful saving all binaries");

	//PRODUCE REPORT
	std::ofstream reportStream(outpuDir + "\\analyzeReport.txt");
	if (!reportStream)
	{
		LogHelper::PrintLog(LogLevel::Warning, "Can't open \"analyzeReport.txt\" file");
		return -3;
	}

	reportStream << "----------REPORT----------" << std::endl;
	reportStream << "Msi path: " << szMsiPath << std::endl;
	reportStream << "Tables number:  \t" << tablesNumber << "\tSee \"<output_dir>\\tables\" directory" << std::endl;

	if (savedFilesCount > 0)
		reportStream << "Files number:   \t" << savedFilesCount << "\tSee \"<output_dir>\\files\" directory" << std::endl;

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
	return 0;
}