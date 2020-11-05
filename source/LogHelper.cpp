#include <iostream>
#include <string>

#include "LogHelper.h"

void Log(LogLevel lvl, const char* msg)
{
	if (lvl == LogLevel::Warning)
	{
		std::cout << "Warning: ";
	}
	else if (lvl == LogLevel::Error)
	{
		std::cout << "ERROR: ";
	}
	std::cout << msg << std::endl;
}

void Log(LogLevel lvl, const char* msg, int val)
{
	std::string stringMsg = msg + std::to_string(val);
	Log(lvl, stringMsg.data());
}