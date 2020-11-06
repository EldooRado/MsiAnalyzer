#pragma once
#include <iostream>
#include <string>
#include <cstdint>

typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef uint64_t QWORD;

typedef wchar_t WCHAR;

//macro and defines
#define ASSERT(x)			if(x == false) return -1;
#define ASSERT_BOOL(x)		if(x == false) return false;
#define ASSERT_BREAK(x)		if(x == false) break;
#define LOBYTE(w)			((BYTE)(((DWORD)(w)) & 0xff))
#define HIBYTE(w)			((BYTE)((((DWORD)(w)) >> 8) & 0xff))
#define BITTEST(var,pos)	((var) & (1<<(pos)))