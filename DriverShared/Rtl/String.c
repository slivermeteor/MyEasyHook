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

LONG RtlAnsiIndexOf(CHAR* InString, CHAR InChar)
{
	ULONG Index = 0;
	while (*InString != 0)
	{
		if (*InString != InChar)
		{
			return Index;
		}

		Index++;
		InString++;
	}

	return -1;
}

/// \param InString - 输入字符串
///  \param InOffset - 开始偏移
///  \param InCount - 子串长度
///  \param InTarget -  目标字符串
///  \param InTargetMaxLength - 目标缓存可方下最大长度
///  \return 实际子串长度，-1代表失败
LONG RtlAnsiSubString(PCHAR InString, ULONG InOffset, ULONG InCount, PCHAR InTarget, ULONG InTargetMaxLength)
{
	ULONG		Index = InOffset;
	ULONG		Result = 0;

	while (*InString != 0)
	{
		// 如果当前已经指向超过了 子串最大偏移
		if (Index > InOffset + InCount)
		{
			*InTarget = 0;
			return Result;
		}

		// 如果 index 大于 开始偏移
		if (Index > InOffset)
		{
			Result++;
			if (Result > InTargetMaxLength)
				return  -1;

			*InTarget = *InString;
			InTarget++;
		}
		Index++;
		InString++;
	}

	return -1;
}

/// \brief 转换十六进制字符转换为Long64
LONG64 RtlAnsiHexToLong64(const CHAR* str, INT Length)
{
	const CHAR* Start = str;
	if (Start[0] == '0' && (Start[1] == 'x' || Start[1] == 'X'))
	{
		str += 2;
	}

	int c;
	LONG64 Result = 0;
	for (Result = 0; (str - Start) < Length && (c = *str) != '\0'; str++)
	{
		if (c >= 'a' && c <= 'f')		// 小写字母处理
		{
			c = c - 'a' + 10;
		}
		else if (c >= 'A' && c <= 'F')	// 大写字母处理
		{
			c = c - 'A' + 10;	//  
		}
		else if (c >= '0' && c <= '9')	// 数字字符 - 直接转换
		{
			c = c - '0';		// 减字符0的数值，就得到了数字
		}
		else
		{
			return 0;
		}
#ifndef LONG64_MAX
#define LONG64_MAX		9223372036854775807i64
#endif
		if (Result > (LONG64_MAX / 16))
		{
			return LONG64_MAX;
		}

		Result *= 16;			// 为啥每次乘以16 - 就是把当前的数字向前移一位(16进制的一位)
		Result += (LONG64)c;	// 再加上当前这一位的数字
							    // 越高位的数字越先加入，那么乘以16的次数就越过 - 还记得十六进制的转化就是 n * 16^n + m * 16^ (m-1) + ...
	}
	return Result;
}


