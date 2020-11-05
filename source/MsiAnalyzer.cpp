#include <fstream>
#include <filesystem>

#include "../include/Ole2Extractor.h"
#include "../include/LogHelper.h"

bool writeToFile(std::string fileName, const char* pStream, size_t streamSize);
bool getStringVector(Ole2Extractor& extractor, const DWORD stringDataIndex, const DWORD stringPoolIndex, std::vector<std::string>& outVecStrings);

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

	const std::string StringData_Name = "!_StringData";
	DWORD stringDataTableIndex = -1;

	const std::string StringPool_Name = "!_StringPool";
	DWORD stringPoolTableIndex = -1;

	for (DWORD i = 0; i < vecNames.size(); i++)
	{
		if (vecNames[i].compare(StringData_Name) == 0)
		{
			stringDataTableIndex = i;
		}
		else if (vecNames[i].compare(StringPool_Name) == 0)
		{
			stringPoolTableIndex = i;
		}
	}

	//string vector
	std::vector<std::string> vecMsiStrings;
	ASSERT(getStringVector(extractor, stringDataTableIndex, stringPoolTableIndex, vecMsiStrings));

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

bool getStringVector(Ole2Extractor& extractor, const DWORD stringDataIndex, const DWORD stringPoolIndex, std::vector<std::string>& outVecStrings)
{
	bool status = false;

	BYTE* stringDataStream = nullptr;
	BYTE* stringPoolByteStream = nullptr;

	do {
		//get StringData
		DWORD stringDataStreamSize = 0;
		ASSERT_BREAK(extractor.readAndAllocateStream(stringDataIndex, &stringDataStream, stringDataStreamSize));

		if (stringDataStream)
		{
			//if you want save stream, uncomment lines
			const std::string StringData_Name = "!_StringData";
			writeToFile(StringData_Name, (const char*)stringDataStream, stringDataStreamSize);
			std::string msg = StringData_Name + " written to file";
			Log(LogLevel::Info, msg.data());
		}
		Log(LogLevel::Info, "Success of reading !_StringData table");

		//get StringPool
		DWORD stringPoolByteStreamSize = 0;
		ASSERT_BREAK(extractor.readAndAllocateStream(stringPoolIndex, &stringPoolByteStream, stringPoolByteStreamSize));

		const DWORD stringFieldsCount = stringPoolByteStreamSize / sizeof(DWORD);

		//if longStrings occur then we allocate to much size, but it should't be a problem
		outVecStrings.resize(stringFieldsCount);

		WORD* stringPoolStream = (WORD*)stringPoolByteStream;

		DWORD offset = 0;
		DWORD stringIndex = 0;
		for (DWORD i = 0; i < stringFieldsCount; i++)
		{
			WORD occuranceNumber = stringPoolStream[2 * i + 1];
			WORD stringLenght = stringPoolStream[2 * i];

			if (occuranceNumber > 0)
			{
				if (stringLenght == 0)
				{
					//there is long string
					i++;
					DWORD longStringLenght = *(((DWORD*)stringPoolStream) + i);
					outVecStrings[stringIndex].resize(longStringLenght);
					::memcpy((void*)outVecStrings[stringIndex].data(), stringDataStream + offset, longStringLenght);
					offset += longStringLenght;

				}
				else if (stringLenght > 0)
				{
					outVecStrings[stringIndex].resize(stringLenght);
					::memcpy((void*)outVecStrings[stringIndex].data(), stringDataStream + offset, stringLenght);
					offset += stringLenght;
				}
				else
				{
					//something wrong
				}
				stringIndex++;
			}
		}

		if (stringPoolByteStream)
		{
			//if you want save stream, uncomment lines
			const std::string StringPool_Name = "!_StringPool";
			writeToFile(StringPool_Name, (const char*)stringPoolByteStream, stringPoolByteStreamSize);
			std::string msg = StringPool_Name + " written to file";
			Log(LogLevel::Info, msg.data());
		}
		Log(LogLevel::Info, "Success of reading !_StringPool table");

		status = true;
	}
	while (false);

	//all deletes and clean up
	if (stringDataStream)
		delete[] stringDataStream;

	if (stringPoolByteStream)
		delete[] stringPoolByteStream;

	return status;
}