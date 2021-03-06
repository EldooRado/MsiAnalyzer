#pragma once
#include <map>
#include <fstream>

#include "common.h"

// a whole implementation is based on: 
// [MS-CFB]: Compound File Binary File Format

//defines
#define MAX_FAT_SECTIONS_COUNT_IN_HEADER 0x6D
#define MFSCIH MAX_FAT_SECTIONS_COUNT_IN_HEADER

#define DIR_ENTRY_NAME_MAX_LENGTH 0x20
#define DENML DIR_ENTRY_NAME_MAX_LENGTH

#define CLSID_LENGTH 0X10

#define FATSECT		0xFFFFFFFD
#define ENDOFCHAIN	0xFFFFFFFE
#define FREESECT	0xFFFFFFFF

//enums
enum DirEntryType
{
	UnknownType = 0,
	Storage = 0x01,
	Stream = 0x02,
	RootStorage = 0x05
};

//structures
#pragma pack(push, 2)
struct CfbHeader
{
	QWORD cfbMagic;				//0x00, MUST be set to the value 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1.
	BYTE clsid[0x10];			//0x08, MUST be set to all zeroes
	WORD minorVer;				//0x18, SHOULD be set to 0x003E if the major version field is either 0x0003 or 0x0004.
	WORD majorVer;				//0x1A, MUST be set to either 0x0003 (version 3) or 0x0004 (version 4)
	WORD byteOrder;				//0x1C, MUST be set to 0xFFFE (little-endian)
	WORD secShift;				//0x1E, MUST be set to 0x0009 (majorVer 3, secSize 512), or 0x000c (majorVer 4, secSize 4096)
	WORD miniSecShift;			//0x20, MUST be set to 0x0006 (miniStreamSize 64)
	BYTE bFiller_0x22[0x06];	//0x22, MUST be set to all zeroes
	DWORD dirSecNum;			//0x28, count of the number of directory sectors in the compound file
	DWORD fatSecNum;			//0x2C, count of the number of FAT sectors in the compound file
	DWORD firstDirSecId;		//0x30, starting sector number for the directory stream
	BYTE bFiller_0x32[0x04];	//0x34
	DWORD minStreamSize;		//0x38, MUST be set to 0x00001000
	DWORD firstMiniSecId;		//0x3C, starting sector number for the mini FAT
	DWORD miniFatSecNum;		//0x40, count of the number of mini FAT sectors in the compound file
	DWORD firstDifatSecId;		//0x44, starting sector number for the DIFAT
	DWORD difatSecNum;			//0x48, count of the number of DIFAT sectors in the compound file
	DWORD difatArray[MFSCIH];	//0x4C, array of 32-bit integer fields contains the first 109 FAT sector locations of the compound file
};
/* important: version 4 compound files, the header size (512 bytes) is less than the sector size (4,096 bytes),
   so the remaining part of the header (3,584 bytes) MUST be filled with all zeroes */
static_assert(sizeof(CfbHeader) == 0x200, "CfbHeader incorrect size");


struct DirectoryEntry
{
	WORD dirEntryName[DENML];	//0x00, MUST contain a Unicode string and MUST be terminated with a UTF-16 null character
	WORD dirEntryNameLength;	//0x40, MUST be a multiple of 2 and include the terminating null character in the count
	BYTE objectType;			//0x42, MUST be 0x00, 0x01, 0x02, or 0x05
	BYTE colorFlag;				//0x43, MUST be 0x00 (red) or 0x01 (black)
	DWORD leftSiblingId;		//0x44, If there is no left sibling, the field MUST be set to NOSTREAM (0xFFFFFFFF)
	DWORD rightSiblingId;		//0x48, If there is no right sibling, the field MUST be set to NOSTREAM (0xFFFFFFFF)
	DWORD childId;				//0x4C, If there is no child object, the field MUST be set to NOSTREAM (0xFFFFFFFF)
	BYTE clsid[CLSID_LENGTH];	//0x50, contains an object class GUID
	DWORD stateBits;			//0x60, contains the user-defined flags 
	QWORD creationTime;			//0x64, The Windows FILETIME structure is used to represent this field in UTC
	QWORD modifiedTime;			//0x6C, The Windows FILETIME structure is used to represent this field in UTC
	DWORD startSecLocation;		//0x74, contains the first sector location if this is a stream object
	QWORD streamSize;			//0x78, contains the size of the user-defined data if this is a stream object.
								// For a root storage object, this field contains the size of the mini stream.
};
static_assert(sizeof(DirectoryEntry) == 0x80, "DirectoryEntry incorrect size");
#pragma pack(pop)

class CfbExtractor
{
private:
	std::ifstream m_input;
	CfbHeader m_cfbHeader = { 0 };
	DWORD m_fileSize = 0;
	DWORD m_sectionCount = 0;
	DWORD m_sectionSize = 0;
	DWORD m_miniSectionSize = 0;
	DWORD m_fatArraySize = 0;
	DWORD m_miniFatArraySize = 0;
	DWORD m_dirEntriesCount = 0;

	DWORD* m_fatEntries = nullptr;
	DWORD* m_miniFatEntries = nullptr;
	DirectoryEntry* m_dirEntries = nullptr;
	BYTE* m_miniStream = nullptr;
	DirectoryEntry m_rootDirEntry = { 0 };
	std::map<std::string, DWORD> m_mapStreamNameToSectionId;

public:
	CfbExtractor();
	~CfbExtractor();
	bool initialize(const std::string msiName);
	bool parseCfbHeader();
	bool loadFatEntries();
	bool loadMiniFatEntries();
	bool loadDirEntries();
	bool loadMiniStreamEntries();
	bool initRedableStreamNamesFromRawNames();
	bool readAndAllocateStream(std::string tableName, BYTE** stream, DWORD& streamSize);

	//getter
	const std::map<std::string, DWORD>& getMapStreamNameToSectionId() const;

private:
	bool convertStreamNameToReadableString(const WORD* tableNameArray, const DWORD tableNameLength, std::string& readableStreamName);
};