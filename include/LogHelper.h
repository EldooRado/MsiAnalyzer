#pragma once

enum class LogLevel
{
	Info,
	Warning,
	Error,
};

void Log(LogLevel lvl, const char* msg);
void Log(LogLevel lvl, const char* msg, int val);