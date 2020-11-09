#pragma once

enum class ActionSourceType
{
	BinaryData = 0x00000000,
	SourceFile = 0x00000010,
	Directory = 0x00000020,
	Property = 0x00000030,
};

enum class ActionTargetType
{
	Dll = 0x00000001,
	Exe = 0x00000002,
	Text = 0x00000003,
	JSCall = 0x00000005,
	VBSCall = 0x00000006,
	Install = 0x00000007,

	//self defined
	Error,
	JSContent,
	VBSContent,

	//feature from advancedInstaller
	PS1Call,
	PS1Content,
};

namespace ActionBitMask
{
	const DWORD Source = 0x00000030;
	const DWORD Target = 0x00000007;
};