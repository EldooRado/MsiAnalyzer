#pragma once

enum class LogOutput
{
	Undefined,
	Std,
	File,
};

enum class LogLevel
{
	Info,
	Warning,
	Error,
};

class LogHelper
{
private:
	static std::ofstream logFile;
	static LogOutput outputType;

private:
	static void internalLog(const char* logLevel, const char* msg);

public:
	static bool init(const char* path);
	static void init();
	static void deinit();

	static void PrintLog(LogLevel lvl, const char* msg);
	static void PrintLog(LogLevel lvl, const char* msg, int val);
};
