#pragma once
#include <fstream>

#include "common.h"

//templater to read from file
template <class T>
bool readType(std::ifstream& inputFile, T& data, DWORD offset = -1)
{
	if (!inputFile)
	{
		Log(LogLevel::Error, "Stream is closed");
		return false;
	}

	if (offset != -1)
	{
		inputFile.seekg(offset, std::ios::beg);
	}

	inputFile.read((char*)&data, sizeof(T));
	if (!inputFile)
	{
		Log(LogLevel::Error, "Readed characters: ", static_cast<int>(inputFile.gcount()));
		return false;
	}
	return true;
}

template <class T>
bool readArray(std::ifstream& inputFile, T* data, DWORD size, DWORD offset = -1)
{
	if (!inputFile)
	{
		Log(LogLevel::Error, "Stream is closed");
		return false;
	}

	if (offset != -1)
	{
		inputFile.seekg(offset, std::ios::beg);
	}

	inputFile.read((char*)data, sizeof(T)*size);
	if (!inputFile)
	{
		Log(LogLevel::Error, "Readed characters: ", static_cast<int>(inputFile.gcount()));
		return false;
	}
	return true;
}

template <class T>
bool readArray(BYTE* arrayStream, T* data, DWORD size, DWORD offset = -1)
{
	if (!arrayStream)
	{
		Log(LogLevel::Error, "arrayStream is nullptr");
		return false;
	}

	if (offset != -1)
	{
		arrayStream += offset;
	}

	::memcpy(data, arrayStream, size);

	return true;
}

template <typename T, typename U>
bool readChunkOfDataFromOle2(T& inputStream, U * outputStream, DWORD sectorIndex, QWORD streamToReadSize,
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
			Log(LogLevel::Error, "sectorIndex index out of bound: ", sectorIndex);
			return false;
		}

		if (!readArray(inputStream, outputStream + i * elementsInSection, bytesToReadInThisIter / sizeof(U), sectionSize * (sectorIndex + !readFromMiniStream)))
		{
			Log(LogLevel::Error, "read error: ", sectorIndex);
			return false;
		}

		sectorIndex = sectionInfoArray[sectorIndex];
		bytesToEnd -= sectionSize;
	}

	if (sectorIndex != ENDOFCHAIN)
	{
		Log(LogLevel::Warning, "last index should be ENDOFCHAIN but isn't. Is: ", sectorIndex);
	}

	return true;
}