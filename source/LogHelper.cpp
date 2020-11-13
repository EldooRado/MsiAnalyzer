#include <iostream>
#include <string>
#include <fstream>

#include "LogHelper.h"

std::ofstream LogHelper::logFile;
LogOutput LogHelper::outputType = LogOutput::Undefined;

bool LogHelper::init(const char* filePath)
{
	logFile.open(filePath);
	if (!logFile)
	{
		init();
		return false;
	}

	outputType = LogOutput::File;
	return true;
}

void LogHelper::init()
{
	outputType = LogOutput::Std;
}

void LogHelper::deinit()
{
	if (logFile)
		logFile.close();
}

void LogHelper::internalLog(const char* logLevelStr, const char* msg)
{
	if (outputType == LogOutput::File)
	{
		logFile << logLevelStr << msg << std::endl;
	}
	else if(outputType == LogOutput::Std)
	{
		std::cout<< logLevelStr << msg << std::endl;
	}
}

void LogHelper::PrintLog(LogLevel lvl, const char* msg)
{
	const char * logLevelStr = "";
	if (lvl == LogLevel::Warning)
	{
		logLevelStr = "Warning: ";
	}
	else if (lvl == LogLevel::Error)
	{
		logLevelStr = "ERROR: ";
	}

	internalLog(logLevelStr, msg);
}

void LogHelper::PrintLog(LogLevel lvl, const char* msg, int val)
{
	std::string stringMsg = msg + std::to_string(val);
	PrintLog(lvl, stringMsg.data());
}