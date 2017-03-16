#include "common.h"
#include "udis86\udis86.h"

/*
http://udis86.sourceforge.net/
Udis86 is a disassembler for the x86 and x86-64 class of instruction set
architectures. It consists of a C library called libudis86 which
provides a clean and simple interface to decode a stream of raw binary
data, and to inspect the disassembled instructions in a structured
manner.
*/

// 得到传入地址第一条汇编指令的长度
EASYHOOK_NT_INTERNAL LhGetInstructionLength(PVOID InPtr, PULONG OutLength)
{
	ud_t ud_obj = { 0 };
	ULONG Length = -1;
	if (!IsValidPointer(OutLength, sizeof(ULONG32)))
	{
		return STATUS_INVALID_PARAMETER_2;
	}

	ud_init(&ud_obj);
#ifdef _M_X64
	ud_set_mode(&ud_obj, 64);
#else
	ud_set_mode(&ud_obj, 32);
#endif

	ud_set_input_buffer(&ud_obj, (uint8_t*)InPtr, 32);
	Length = ud_disassemble(&ud_obj);
	if (Length > 0)
	{
		*OutLength = Length;
		return STATUS_SUCCESS;;
	}

	return STATUS_INVALID_PARAMETER;
}

// 返回在InCodePtr在InCodeSize范围外，第一条指令的尾偏移
EASYHOOK_NT_INTERNAL LhRoundToNextInstruction(PVOID InCodePtr, ULONG InCodeSize, PULONG OutOffset)
{
	PUCHAR Ptr = (PUCHAR)InCodePtr;
	PUCHAR BasePtr = Ptr;
	NTSTATUS NtStatus = STATUS_SUCCESS;
	ULONG InstructionLength = 0;

	if (!IsValidPointer(OutOffset, sizeof(ULONG32)))
	{
		return STATUS_INVALID_PARAMETER_3;
	}

	// 超出 InCodeSize 退出循环
	while (Ptr < BasePtr + InCodeSize)
	{
		// 得到当前Ptr下的第一条指令长度
		FORCE(LhGetInstructionLength(Ptr, &InstructionLength));
		Ptr += InstructionLength;	//  下移
		InstructionLength = 0;
	}

	*OutOffset = (ULONG)(Ptr - BasePtr); // 正确退出循环，当前这条指令的尾偏移超出了 InCodeSize
	RETURN;

FINALLY_OUTRO:
THROW_OUTRO:
{
	return NtStatus;
}
}


EASYHOOK_NT_INTERNAL LhRelocateEntryPoint(PVOID InEntryPoint, ULONG InEPSize, PVOID Buffer, PULONG OutRelocSize)
{
	// 将InEntryPoint重新放入Buffer，并将迁移的长度放入RelocSize
	PUCHAR   OldAddr = InEntryPoint;
	PUCHAR   NewAddr = Buffer;
	UCHAR    FirstCode = 0;
	UCHAR    SecondCode = 0;
	BOOL     b16bit = FALSE;
	BOOL     bIsRIPRelatieve = FALSE;
	NTSTATUS NtStatus = STATUS_SUCCESS;
	ULONG    OpCodeLength = 0;		// 跳转指令完整长度
	ULONG    InstrLength = 0;
	LONG_PTR AbsAddr = 0;			// 函数绝对地址


	ASSERT(InEPSize < 20, L"reloc.c - InEPSize < 20");

	while (OldAddr < (PUCHAR)InEntryPoint + InEPSize)
	{
		FirstCode = *OldAddr;
		SecondCode = *(OldAddr + 1);


		// 检查前缀
		switch (FirstCode)
		{
			// 16 位的情况单独判断
		case 0x67:
		{
			b16bit = TRUE;
			OldAddr++;
			continue;
		}
		}

		// 如果是跳转指令 - 得到跳转的直接地址
		switch (FirstCode)
		{
		case 0xE9:	// jmp imm16/imm32 - jmp 指令
		{
			if (OldAddr != InEntryPoint)
			{
				THROW(STATUS_NOT_SUPPORTED, L"Hooking far jumps is only supported if they are the first instruction.");
			}
		}
		case 0xE8:	// call imm16/imm32 -- E8/E9 指令在跳转的处理上 32bit/64bit 都是没有区别的
		{
			if (b16bit)
			{
				AbsAddr = *((INT16*)(OldAddr + 1));
				OpCodeLength = 3;
			}
			else    // 经典的函数跳转
			{
				AbsAddr = *((INT32*)(OldAddr + 1));	//取原偏移
				OpCodeLength = 5;
			}
			break;
		}
		case 0xEB:	// jmp imm8
		{
			AbsAddr = *((INT8*)(OldAddr + 1));
			OpCodeLength = 2;
			break;
		}
		// 如果跳转是有条件跳转 - 不支持，报错返回
		case 0xE3: // jcxz imm8
		{
			THROW(STATUS_NOT_SUPPORTED, L"Hooking near (conditional) jumps is not supported.");
			break;
		}
		case 0x0F:
		{
			if ((SecondCode & 0xF0) == 0x80) // jcc imm16/imm32
				THROW(STATUS_NOT_SUPPORTED, L"Hooking far conditional jumps is not supported.");
			break;
		}
		}

		if ((FirstCode & 0xF0) == 0x70)     // jcc imm8
		{
			THROW(STATUS_NOT_SUPPORTED, L"Hooking near conditional jumps is not supported.");
		}

		// 如果是跳转代码 - 取出跳转最终地址
		// 构造直接跳转汇编代码
		if (OpCodeLength > 0)
		{
			// 1. 构造 mov eax(rax), AbsAddr
			// TargetAddress = EIP(当前指令地址 + 指令长度) + Offset
			AbsAddr = AbsAddr + (LONG_PTR)(OldAddr + OpCodeLength);

			// 6 位下使用 REX.W-perfix 前缀码
#ifdef _M_X64
			*NewAddr = 0x48;	// 0100(4) 1000(8) - 表示使用64位操作长度 
			NewAddr++;
#endif
			*NewAddr = 0xB8;	// mov eax
			NewAddr++;
			*((LONG_PTR*)NewAddr) = AbsAddr;

			NewAddr += sizeof(PVOID);	// 越过目标地址长度

			// 跳转的实际地址 是否有意义???
			if (((LONGLONG)NewAddr >= (LONGLONG)InEntryPoint) && (AbsAddr < (LONGLONG)InEntryPoint + InEPSize))
			{
				THROW(STATUS_NOT_SUPPORTED, L"Hooking jumps into the hooked entry point is not supported.");
			}

			// 这里只需都构造 call/jmp eax 因为前面在Reloc的时候控制了偏移不会超过 32bit。所以32位的寄存器就够用了。
			switch (FirstCode)
			{
			case 0xE8:	// call eax
			{
				*NewAddr = 0xFF;
				NewAddr++;
				*NewAddr = 0xD0;
				NewAddr++;

				break;
			}
			case 0xE9:	// jmp eax
			case 0xEB:	// jmp imm8
			{
				*NewAddr = 0xFF;
				NewAddr++;
				*NewAddr = 0xE0;
				NewAddr++;

				break;
			}
			}
			/*
				以上的转换是必须的
				就算目标函数已经被Hook或使用了防止Hook的方法或仅仅一串无效的代码。
				但是EasyHook采用的这种方法可以重复Hook同一个函数，就算有其它未知的Hook库来Hook EasyHook已经Hook的方法。
				只有当EasyHook去Hook其它Hook库已经Hook的方法可能会引发不稳定的情况。特别是一些不稳定的库以及
			*/
			*OutRelocSize = (ULONG)(NewAddr - (PUCHAR)Buffer);
		}
		else
		{	
			// 不是跳转指令 - 判断当前指令是否有跟 RIP/EIP 有关
			FORCE(LhRelocateRIPRelativeInstruction((ULONGLONG)OldAddr, (ULONGLONG)NewAddr, &bIsRIPRelatieve));
		}
		
		// 如果是16位，前面OldAddr向前移动了一位-为了进行判断。现在进行指令拷贝回退一位，进行拷贝。
		if (b16bit)
		{
			OldAddr--;
		}

		// 得到第一条指令 完整长度
		FORCE(LhGetInstructionLength(OldAddr, &InstrLength));
		// 如果不是跳转指令，并且也没有 RIP 相关 - 直接拷贝
		if (OpCodeLength == 0)
		{
			if (!bIsRIPRelatieve)
			{
				RtlCopyMemory(NewAddr, OldAddr, InstrLength);
			}

			NewAddr += InstrLength;
		}

		OldAddr += InstrLength;
		bIsRIPRelatieve = FALSE;
		b16bit = FALSE;
	}

	// 返回更变长度
	*OutRelocSize = (ULONG)(NewAddr - (PUCHAR)Buffer);
	RETURN;
FINALLY_OUTRO:
THROW_OUTRO:
	{
		return NtStatus;
	}
}

/// \brief 判断首指令是否跟RIP 相关
EASYHOOK_NT_INTERNAL LhRelocateRIPRelativeInstruction(ULONGLONG InOffset, ULONGLONG InTargetOffset, PBOOL OutWasRelocated)
{
#ifndef _M_X64
	return FALSE;
#else
#ifndef MAX_INSTR
#define MAX_INSTR 100
#endif

	ULONG32			AsmSize = 0;
	CHAR			DisassembleBuffer[MAX_INSTR] = { 0 };
	CHAR			Offset[MAX_INSTR] = { 0 };
	NTSTATUS		NtStatus = STATUS_SUCCESS;
	LONG64			MemDelta = InTargetOffset - InOffset;
	ULONG64		    NextInstr = 0;
	LONG		    Pos = 0;
	ULONG64			RelAddrOffset = 0;
	LONG64			RelAddr = 0;
	LONG64		    RelAddrSign = 1;	/// <标示操作数相对于RIP是加还是减

	// 差距应该是 31bit (第一位符号位 
	ASSERT(MemDelta == (LONG)MemDelta, L"reloc.c - MemDelta == (LONG)MemDelta");
	*OutWasRelocated = FALSE;

	// 反汇编第一条代码
	if (!RTL_SUCCESS(LhDisassembleInstruction((PVOID)InOffset, &AsmSize, DisassembleBuffer, sizeof(DisassembleBuffer), &NextInstr)))
		THROW(STATUS_INVALID_PARAMETER_1, L"Unable to disassemble entry point. ");

	// 查看 反汇编代码中 是否有 [ 符号。例如 mov rax, qword ptr [rip+0x4h]
	Pos = RtlAnsiIndexOf(DisassembleBuffer, '[');
	if (Pos < 0)
		RETURN;

	if (DisassembleBuffer[Pos + 1] == 'r' && DisassembleBuffer[Pos + 2] == 'i' && DisassembleBuffer[Pos + 3] == 'p' && 
	   (DisassembleBuffer[Pos + 4] == '+' || DisassembleBuffer[Pos + 4] == '-'))
	{
		/*
			支持 RIP 加减操作，直接修改偏移值。来直接跳转到Hook代码
			e.g 
			Entry Point:																	   Relocated:
			66 0F 2E 05 DC 25 FC FF   ucomisd xmm0, [rip-0x3da24]   IP:ffc46d4		---->	   66 0F 2E 05 10 69 F6 FF   ucomisd xmm0, [rip-0x996f0]   IP:100203a0
		*/
		if (DisassembleBuffer[Pos + 4] == '-')
		{
			RelAddrSign = -1;	// 如果是 -，Sign 就标为 -1。最后数值乘以 RelAddrSign 就转变为实际对于 RIP 的偏移值
		}

		Pos += 4;	// 迈过 RIP -/+
		// 得到子串 - 实际的操作数
		if (RtlAnsiSubString(DisassembleBuffer, Pos + 1, RtlAnsiIndexOf(DisassembleBuffer, ']' - Pos - 1), Offset, MAX_INSTR) <= 0)
		{
			RETURN;
		}

		// 将十六进制操作数转换为十进制数
		RelAddr = RtlAnsiHexToLong64(Offset, MAX_INSTR);
		if (!RelAddr)
			RETURN;

		RelAddr *= RelAddrSign;			// 与符号位相乘
		if (RelAddr != (LONG)RelAddr)	// 偏移必须是32位以内的(1位符号31位偏移
			RETURN;

		// 确保转换地址值的正确
		for (Pos = 1; Pos <= NextInstr - (InOffset + 4); Pos++)
		{
			// 找到匹配值 - 记录偏移，为后面的覆盖做准备
			if (*((LONG*)(InOffset + Pos)) == RelAddr)
			{	
				// 超过一处匹配 - 无法确定 错误退出
				if (RelAddrOffset != 0)
				{
					RelAddrOffset = 0;
					break;
				}
				RelAddrOffset = Pos;
			}
		}
		if (RelAddrOffset == 0) 
		{
			THROW(STATUS_INTERNAL_ERROR, L"The given entry point contains a RIP-relative instruction for which we can't determine the correct address offset!");
		}

		// 重值操作码
		RelAddr = RelAddr - MemDelta;	// 原偏移 - Reloc偏移 = 真正偏移 为啥是 - 符号 - 这里构造的偏移是从Reloc代码跳到原本代码要跳转的地方，那么MemDelta就是Rloc与原代码的偏移.
										// 但是计算MemDelta的时候是 Reloc - Old(Old到Reloc的相对偏移)。所以这里加减号，变为Reloc到old的相对偏移
		if (RelAddr != (LONG)RelAddr)	// 完整偏移超出了 31位 ？
			THROW(STATUS_NOT_SUPPORTED, L"The given entry point contains at least one RIP-Relative instruction that could not be relocated!");

		RtlCopyMemory((void*)InTargetOffset, (void*)InOffset, (ULONG)(NextInstr - InOffset));	// 拷贝完整指令
		*((LONG*)(InTargetOffset + RelAddrOffset)) = (LONG)RelAddr;	// 放入新操作数

		*OutWasRelocated = TRUE;
	}

	RETURN;
THROW_OUTRO:
FINALLY_OUTRO:
	{
		return NtStatus;
	}
#endif
}


///	\brief 使用 udis86库 来反汇编得到指令
/// 
///	\param InPtr - 输入缓存
/// \param Length -  长度
/// \param Buffer - 反汇编结果缓存
/// \param BufferSize - 长度
/// \param NextInstr - 下一条指令长度
///	更多可以看 https://github.com/vmt/udis86
EASYHOOK_NT_INTERNAL LhDisassembleInstruction(PVOID InPtr, PULONG Length, PSTR Buffer, LONG BufferSize, PULONG64 NextInstr)
{
	ud_t ud_obj = { 0 };
	ud_init(&ud_obj);			// 初始化

	// 设置模式
#ifdef _M_X64
	ud_set_mode(&ud_obj, 64);   
#else
	ud_set_mode(&ud_obj, 32);
#endif

	// 设置汇编类型 - intel
	ud_set_syntax(&ud_obj, UD_SYN_INTEL);
	// 设置反汇编缓存
	ud_set_asm_buffer(&ud_obj, Buffer, BufferSize);
	// 设置输入缓存
	ud_set_input_buffer(&ud_obj, (UINT8*)InPtr, 32);
	// 反汇编
	*Length = ud_disassemble(&ud_obj);

	*NextInstr = (ULONG64)InPtr + *Length;

	if (Length > 0)
		return STATUS_SUCCESS;
	else
		return STATUS_INVALID_PARAMETER;
}