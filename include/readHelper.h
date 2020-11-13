#pragma once
#include <fstream>
#include <cstring>

#include "common.h"
#include "LogHelper.h"

// read simple type variable from file stream
template <class T>
bool readVariable(std::ifstream& inputFile, T& data, DWORD offset = -1)
{
	if (!inputFile)
	{
		LogHelper::PrintLog(LogLevel::Error, "Stream is closed");
		return false;
	}

	if ((int)offset != -1)
	{
		inputFile.seekg(offset, std::ios::beg);
	}

	inputFile.read((char*)&data, sizeof(T));
	if (!inputFile)
	{
		LogHelper::PrintLog(LogLevel::Error, "Readed characters: ", static_cast<int>(inputFile.gcount()));
		return false;
	}
	return true;
}

// read simple type array from file stream
template <class T>
bool readArray(std::ifstream& inputFile, T* data, DWORD size, DWORD offset = -1)
{
	if (!inputFile)
	{
		LogHelper::PrintLog(LogLevel::Error, "Stream is closed");
		return false;
	}

	if ((int)offset != -1)
	{
		inputFile.seekg(offset, std::ios::beg);
	}

	inputFile.read((char*)data, sizeof(T)*size);
	if (!inputFile)
	{
		LogHelper::PrintLog(LogLevel::Error, "Readed characters: ", static_cast<int>(inputFile.gcount()));
		return false;
	}
	return true;
}

// read simple type array from chunk of data
template <class T>
bool readArray(BYTE* arrayStream, T* data, DWORD size, DWORD offset = -1)
{
	if (!arrayStream)
	{
		LogHelper::PrintLog(LogLevel::Error, "readArray - arrayStream is nullptr");
		return false;
	}

	if ((int)offset != -1)
	{
		arrayStream += offset;
	}

	::memcpy(data, arrayStream, size);

	return true;
}

/*	This function is specific for compound file binary. It helps read sections (eg. miniStream).
	It is universal function, so we can read from file stream and from array,the output can be 
	an array of different types and we have option to read from miniStream.
*/
template <typename T, typename U>
bool readChunkOfDataFromCfb(T& inputStream, U * outputStream, DWORD sectorIndex, QWORD streamToReadSize,
	DWORD sectionSize, DWORD* sectionInfoArray, DWORD sectionArraySize, bool readFromMiniStream = false)
{
	const DWORD elementsInSection = sectionSize / sizeof(U);
	DWORD streamSecCount = static_cast<DWORD>(streamToReadSize) / sectionSize;

	if (streamToReadSize % sectionSize > 0)
	{
		streamSecCount++;
	}

	DWORD bytesToEnd = static_cast<DWORD>(streamToReadSize);
	for (DWORD i = 0; i < streamSecCount; i++)
	{
		DWORD bytesToReadInThisIter = sectionSize;
		if (bytesToEnd < sectionSize)
		{
			bytesToReadInThisIter = bytesToEnd;
		}

		if (sectorIndex >= sectionArraySize)
		{
			LogHelper::PrintLog(LogLevel::Error, "\"sectorIndex\" index out of bound: ", sectorIndex);
			return false;
		}

		if (!readArray(inputStream, outputStream + i * elementsInSection, bytesToReadInThisIter / sizeof(U), sectionSize * (sectorIndex + !readFromMiniStream)))
		{
			LogHelper::PrintLog(LogLevel::Error, "readChunkOfDataFromCfb - read error. Sec Index: ", sectorIndex);
			return false;
		}

		sectorIndex = sectionInfoArray[sectorIndex];
		bytesToEnd -= sectionSize;
	}

	if (sectorIndex != ENDOFCHAIN)
	{
		LogHelper::PrintLog(LogLevel::Warning, "last index should be ENDOFCHAIN but isn't. Is: ", sectorIndex);
	}

	return true;
}