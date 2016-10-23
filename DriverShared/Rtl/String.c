#include "common.h"

ULONG32 RtlAnsiLength(CHAR* InString)
{
	ULONG ulLength = 0;

	while (*InString != 0)
	{
		ulLength++;
		InString++;
	}

	return ulLength;
}

ULONG32 RtlUnicodeLength(WCHAR* InString)
{
	ULONG32 ulLength = 0;

	while (*InString != 0)
	{
		ulLength++;
		InString++;
	}

	return ulLength;
}