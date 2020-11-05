#include <fstream>
#include <filesystem>

#include "../include/Ole2Extractor.h"
#include "../include/LogHelper.h"

bool writeToFile(std::string fileName, const char* pStream, size_t streamSize);

int main(int argc, char* argv[])
{
	std::string szMsiName;
	if (argc == 2)
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
	}

	Ole2Extractor extractor;
	ASSERT(extractor.initialize(szMsiName));
	Log(LogLevel::Info, "Success of initialize extractor");

	ASSERT(extractor.parseOleHeader());
	Log(LogLevel::Info, "Success of parsing oleHeader");

	ASSERT(extractor.loadFatEntries());
	Log(LogLevel::Info, "Success of loading fatEntries");

	ASSERT(extractor.loadMiniFatEntries());
	Log(LogLevel::Info, "Success of loading miniFatEntries");

	ASSERT(extractor.loadDirEntries());
	Log(LogLevel::Info, "Success of loading dirEntries");

	ASSERT(extractor.loadMiniStreamEntries());
	Log(LogLevel::Info, "Success of loading miniStreamEntries");

	//get a stream names
	std::vector<std::string> vecNames = extractor.getStreamNames();

	//get particular section
	const std::string Table_Name = "!_StringData";
	for (DWORD i = 0; i < vecNames.size(); i++)
	{
		if (vecNames[i].compare(Table_Name) == 0)
		{
			BYTE* currStream = nullptr;
			DWORD streamSize = 0;
			ASSERT(extractor.allocateStream(i, &currStream, streamSize));

			if (currStream)
			{
				writeToFile(Table_Name, (const char*)currStream, streamSize);
				delete[] currStream;
				std::string msg = Table_Name + " written to file";
				Log(LogLevel::Info, msg.data());
			}
			else
			{
				Log(LogLevel::Warning, "Failed to save file");
			}
		}
	}

	return 0;
}
bool writeToFile(std::string fileName, const char* pStream, size_t streamSize)
{
	std::ofstream outputFile(fileName);
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