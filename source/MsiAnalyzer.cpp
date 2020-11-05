#include <fstream>
#include <filesystem>

#include "../include/Ole2Extractor.h"
#include "../include/LogHelper.h"

bool writeToFile(std::string fileName, const char* pStream, size_t streamSize);
bool getStringVector(Ole2Extractor& extractor, std::string stringData_TableName, std::string stringPool_TableName, std::vector<std::string>& outVecStrings);
bool printTablesFromMetadata(Ole2Extractor& extractor, std::string tableIndex, const std::vector<std::string>& vecStrings);

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
	szMsiName = "C:\\work\\msi\\tools\\javascript.msi";
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
	extractor.initTableNames();

	const std::string StringData_TableName = "!_StringData";
	const std::string StringPool_TableName = "!_StringPool";
	const std::string Tables_TableName = "!_Tables";

	//string vector
	std::vector<std::string> vecMsiStrings;
	ASSERT(getStringVector(extractor, StringData_TableName, StringPool_TableName, vecMsiStrings));

	//print "!_Tables" table
	ASSERT(printTablesFromMetadata(extractor, Tables_TableName, vecMsiStrings));

	Log(LogLevel::Info, "\n----------SUCCESS----------");
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

bool getStringVector(Ole2Extractor& extractor, std::string stringData_TableName, std::string stringPool_TableName, std::vector<std::string>& outVecStrings)
{
	bool status = false;

	BYTE* stringDataStream = nullptr;
	BYTE* stringPoolByteStream = nullptr;

	do {
		//get StringData
		DWORD stringDataStreamSize = 0;
		ASSERT_BREAK(extractor.readAndAllocateTable(stringData_TableName, &stringDataStream, stringDataStreamSize));

		if (stringDataStream)
		{
			//if you want save stream, uncomment lines
			writeToFile(stringData_TableName, (const char*)stringDataStream, stringDataStreamSize);
			std::string msg = stringData_TableName + " written to file";
			Log(LogLevel::Info, msg.data());
		}
		Log(LogLevel::Info, "Success of reading !_StringData table");

		//get StringPool
		DWORD stringPoolByteStreamSize = 0;
		ASSERT_BREAK(extractor.readAndAllocateTable(stringPool_TableName, &stringPoolByteStream, stringPoolByteStreamSize));

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
			}
			stringIndex++;
		}

		if (stringPoolByteStream)
		{
			//if you want save stream, uncomment lines
			writeToFile(stringPool_TableName, (const char*)stringPoolByteStream, stringPoolByteStreamSize);
			std::string msg = stringPool_TableName + " written to file";
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

bool printTablesFromMetadata(Ole2Extractor& extractor, std::string tables_TableName, const std::vector<std::string>& vecStrings)
{
	bool status = false;
	BYTE* tablesByteStream = nullptr;

	do {
		//get StringData
		DWORD tablesByteStreamSize = 0;
		ASSERT_BREAK(extractor.readAndAllocateTable(tables_TableName, &tablesByteStream, tablesByteStreamSize));

		WORD* tablesStream = (WORD*)tablesByteStream;
		std::cout << "Tables:\n";
		for (DWORD i = 0; i < tablesByteStreamSize / sizeof(WORD); i++)
		{
			WORD stringIndex = tablesStream[i];
			std::cout << vecStrings[stringIndex] << std::endl;;
		}
		std::cout << std::endl;

		if (tablesByteStream)
		{
			//if you want save stream, uncomment lines
			writeToFile(tables_TableName, (const char*)tablesByteStream, tablesByteStreamSize);
			std::string msg = tables_TableName + " written to file";
			Log(LogLevel::Info, msg.data());
		}
		Log(LogLevel::Info, "Success of reading !_Tables table");

		status = true;
	} while (false);

	return status;
}