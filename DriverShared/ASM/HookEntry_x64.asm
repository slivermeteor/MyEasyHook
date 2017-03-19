.CODE

public StealthStub_ASM_x64
StealthStub_ASM_x64 PROC
	sub			rsp, 8 * 6  			    ; 栈区开够 - CreateThread 一共有6参 48肯定够
	
	mov			qword ptr[rsp + 40], 0		; this code will cover the old stack data, we should sava it before call CreateThread
	mov			qword ptr[rsp + 32], 0		; 这两步会覆盖原栈的值，我们需要提前保存值
	mov			r9, qword ptr [rbx + 16]	; RemoteThreadParam
	mov			r8, qword ptr [rbx + 8]		; RemoteThreadStart
	mov			rdx, 0
	mov			rcx, 0
	call		qword ptr[rbx]				; CreateThread(0, 0, RemoteThreadStart, RemoteThreadParam, 0, 0);
	cmp			rax, 0
	
	; signal completion - 通知原函数 创建成功
	mov			rcx, qword ptr [rbx + 48]	; 把SynchronEventHandle取出来	
	mov			qword ptr [rbx + 48], rax	; 保存创建的远程线程句柄
	call		qword ptr [rbx + 56]		; SetEvent(hSyncEvent);

	; wait for completion 等待原函数Duplicate远程线程句柄
	mov			rdx, -1
	mov			rcx, qword ptr [rbx + 32]
	call		qword ptr [rbx + 24]		; WaitForSingleObject(hCompletionEvent, INFINITE)	

	; close handle  关闭所有句柄·
	mov			rcx, qword ptr [rbx + 32]		
	call		qword ptr [rbx + 40]		; CloseHandle(hCompletionEvent);
	
	; close handle  
	mov			rcx, qword ptr [rbx + 48]		
	call		qword ptr [rbx + 40]		; CloseHandle(hSyncEvent);
	
	; restore context 恢复 Context
	mov			rax, [rbx + 64 + 8 * 0]
	mov			rcx, [rbx + 64 + 8 * 1]
	mov			rdx, [rbx + 64 + 8 * 2]
	mov			rbp, [rbx + 64 + 8 * 3]
	mov			rsp, [rbx + 64 + 8 * 4]
	mov			rsi, [rbx + 64 + 8 * 5]
	mov			rdi, [rbx + 64 + 8 * 6]
	mov			r8, [rbx + 64 + 8 * 10]
	mov			r9, [rbx + 64 + 8 * 11]
	mov			r10, [rbx + 64 + 8 * 12]
	mov			r11, [rbx + 64 + 8 * 13]
	mov			r12, [rbx + 64 + 8 * 14]
	mov			r13, [rbx + 64 + 8 * 15]
	mov			r14, [rbx + 64 + 8 * 16]
	mov			r15, [rbx + 64 + 8 * 17]
	push		qword ptr[rbx + 64 + 8 * 9] ; push EFlags	
	push		qword ptr[rbx + 64 + 8 * 8]	; save old EIP
	mov			rbx, [rbx + 64 + 8 * 7]
	
	add			rsp, 8  ; 抵消一次上面的push 下面popfq再抵消一次
	popfq		; POPFQ pops 64 bits from the stack, loads the lower 32 bits into RFLAGS, and zero extends the upper bits of RFLAGS.

	; continue execution...
	jmp			qword ptr [rsp - 16]  ; 将rsp恢复为旧rsp后，上面又是两次push。保存的EIP的是第二次 所以rsp-16 就是保存的rip值
	
	; outro signature, to automatically determine code size -  硬编码 用户获得ASM-CODE 长度
	db 78h
	db 56h
	db 34h
	db 12h
StealthStub_ASM_x64 ENDP

; HookInjectionCode_ASM_x64

public Injection_ASM_x64

Injection_ASM_x64 PROC
; no registers to save, because this is the thread main function
	mov         r14, rcx ; save parameter to non-volatile register
	sub         rsp, 40  ; x64函数开栈，子函数最多参数为4，4*8 = 32，已经对16位对齐，再加上8 对齐 ReturnAddress
						 ; 函数开栈
	
; call LoadLibraryW(Inject->EasyHookPath); 加载EasyHookDll64
	mov         rcx, qword ptr [r14 + 8]
	call        qword ptr [r14 + 40] ; LoadLibraryW
	mov			r13, rax
	test		rax, rax
	je			HookInject_FAILURE_A
	
; call GetProcAddress(hModule, Inject->EntryPoint) - 调用HookCompleteInjection  真正Hook入口
	mov         rdx, qword ptr [r14 + 24] 
	mov         rcx, rax 
	call        qword ptr [r14 + 56] ; GetProcAddress 
	test		rax, rax
	je			HookInject_FAILURE_B
	
; call EasyHookEntry(Inject); - 调用HookCompleteInjection  真正Hook入口
	mov			rcx, r14
	call		rax
	mov			r15, rax ; save error code to non-volatile register

; call FreeLibrary(hEasyHookLib)
	mov			rcx, r13
	call		qword ptr [r14 + 48] ; FreeLibrary
	test		rax, rax
	je			HookInject_FAILURE_C
	
	jmp			HookInject_EXIT
	
	; 错误处理
HookInject_FAILURE_A:
	call		qword ptr [r14 + 88] ; GetLastError
	or			rax, 40000000h
	jmp			HookInject_FAILURE_E
HookInject_FAILURE_B:
	call		qword ptr [r14 + 88] ; GetLastError
	or			rax, 10000000h
	jmp			HookInject_FAILURE_E	
HookInject_FAILURE_C:
	call		qword ptr [r14 + 88] ; GetLastError
	or			rax, 30000000h
	jmp			HookInject_FAILURE_E	
HookInject_FAILURE_E:
	mov			r15, rax ; 保存错误值
	
HookInject_EXIT:

; 修改栈区读写保护 - 让栈区可写，使用栈区来返回原RIP
; call VirtualProtect(Outro, 8, PAGE_EXECUTE_READWRITE, &OldProtect)
	lea			rbx, qword ptr [rsp + 8] ; writes into register parameter stack - 得到我们要写入的栈区首地址
	mov			r9, rbx
	mov			r8, 40h
	mov			rdx, 8
	mov			rcx, rbx
	call		qword ptr [r14 + 72] ; VirtualProtect
	test		rax, rax
	
	jne HookInject_EXECUTABLE

	; failed to make stack executable -  修改栈区读写保护失败 - 按原路退出
		call		qword ptr [r14 + 88] ; GetLastError
		or			rax, 01000000h
		mov			rcx, rax
		call		qword ptr [r14 + 80] ; ExitThread
		
HookInject_EXECUTABLE:
; 为啥要在栈区里执行 - 因为在栈区才可以释放申请的代码段，不可能在代码段申请释放自己。释放完成后，再退出线程，自动清理栈区。不留任何痕迹。
; save outro to executable stack -  rbx,rbp 写入函数地址
	mov			rbx, [r14 + 64] 		; VirtualFree()
	mov			rbp, [r14 + 80] 		; ExitThread()
	
	mov			rax, 000D5FFCF8B49D3FFh ; 往栈区里写代码
		; call rbx
		; mov  rcx, r15
		; call rbp
		
	mov qword ptr [rsp + 8], rax
	
; save params for VirtualFree(Inject->RemoteEntryPoint, 0, MEM_RELEASE);
	mov r8, 8000h
	mov rdx, 0h
	mov rcx, qword ptr [r14 + 32]
	
	lea rax, qword ptr [rsp + 8]
	sub rsp, 48
	jmp rax
	
; outro signature, to automatically determine code size
	db 78h
	db 56h
	db 34h
	db 12h
	
Injection_ASM_x64 ENDP

public Trampoline_ASM_x64

Trampoline_ASM_x64 PROC
; 64位定义下面这些变量 起始是LocalHookInfo的最后几个变量，这里定义只是为了快速访问。
NETIntro:
	;void*			NETEntry; // fixed 0 (0) 
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	
OldProc:
	;BYTE*			OldProc; // fixed 4 (8)  
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	
NewProc:
	;PVOID HookProc; // fixed 8 (16) 
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	
NETOutro:
	;void*			NETOutro; // fixed 12 (24) 
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	
IsExecutedPtr:
	;size_t*		IsExecutedPtr; // fixed 16 (32) 
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0

;注意 64位 汇编函数栈区必须16位对齐
	mov rax, rsp
	push rcx ; 保存参数
	push rdx
	push r8
	push r9
	
	sub rsp, 4 * 16 ; 开辟栈区 - 保存浮点型参数
	
	movups [rsp + 3 * 16], xmm0
	movups [rsp + 2 * 16], xmm1
	movups [rsp + 1 * 16], xmm2
	movups [rsp + 0 * 16], xmm3
	
	sub rsp, 32; 为子函数调用开辟栈区
; Stack:| rcx, rdx, r8, r9 | xmm0, xmm1, xmm2, xmm3 | child functions parameters stack | rsp
;       |       32bit      |         64bit          |                32bit             |	
	lea rax, [IsExecutedPtr]
	mov rax, [rax]
	;db 0F0h 					
	lock inc qword ptr [rax]		; 锁住内存 - 汇编语法
	
;   Hook函数存在吗?
	cmp qword ptr[NewProc], 0
	db 3Eh 							; branch usually taken
	jne CALL_NET_ENTRY
	
; 没有Hook函数，直接呼叫原函数
		lea rax, [IsExecutedPtr]
		mov rax, [rax]
		;db 0F0h 				
		lock dec qword ptr [rax]	; 锁住内存 - 汇编语法
		
		lea rax, [OldProc]
		jmp TRAMPOLINE_EXIT

; 呼叫Hook函数 或者 原函数
CALL_NET_ENTRY:	

; call BarrierIntro
	lea rcx, [IsExecutedPtr + 8] ; 这里传入的是LocalHookInfo的尾部地址，在BarrierIntro里64位会自己回退到头部
	mov rdx, qword ptr [rsp + 32 + 4 * 16 + 4 * 8] ; 32 是四个参数寄存器 4*16 是四个浮点参数寄存器 32 是子函数参数栈区 - 这样就回到了当前函数栈区外第一个参数 - 也就是call当前函数放入的rip
	lea r8, qword ptr [rsp + 32 + 4 * 16 + 4 * 8]  ; 取得返回地址值的存储地址
	call qword ptr [NETIntro] ; LocalHookInfo->NETIntro(Hook, RetAddr(RIP), InitialRSP);
	
; 可以呼叫Hook函数吗? - ACL决定 (rax = RuntimeInfo->IsExecuting)
	test rax, rax
	
	db 3Eh ; branch usually taken
	jne CALL_HOOK_HANDLER
	
	; 不能呼叫hook函数 - 呼叫原函数
		lea rax, [IsExecutedPtr]
		mov rax, [rax]
		;db 0F0h ; 
		lock dec qword ptr [rax]
	
		lea rax, [OldProc]
		jmp TRAMPOLINE_EXIT
		
CALL_HOOK_HANDLER:
;   设置Hook函数返回地址 - 前往BarrierOutro呼叫入口(CALL_NET_OUTRO)
	lea rax, [CALL_NET_OUTRO]
	mov qword ptr [rsp + 32 + 4 * 16 + 4 * 8], rax

; 开始准备呼叫Hook函数
	lea rax, [NewProc]
	jmp TRAMPOLINE_EXIT 

CALL_NET_OUTRO: ; Hook函数返回地址

; call BarrierOutro
	push 0 ; 准备放返回地址
	push rax

	sub rsp, 32 + 16; shadow space for method calls and SSE registers
; 注意在这里，已经调用了Hook函数。栈区已经发生了改变,原本所有的栈区已经被回收
; Stack:| 0, rax | 	xmm0(浮点返回值)  |            |
;       |  32bit |  16bit            |    32bit   |
	movups [rsp + 32], xmm0
	
	lea rcx, [IsExecutedPtr + 8]  ; Param 1: 同样的传参方法
	lea rdx, [rsp + 56] 		  ; Param 2: 返回地址存储值 - BarrierOutro取出原返回地址 放入。
	call qword ptr [NETOutro] 	  ; Hook->BarrierOutro(Hook);
	
	lea rax, [IsExecutedPtr]
	mov rax, [rax]
	;db 0F0h 
	lock dec qword ptr [rax]
	
	add rsp, 32 + 16		; 控制rsp
	movups xmm0, [rsp - 16]	; 返回值恢复
	
	pop rax ; 保存Hook函数返回的返回值
	
;   控制住rsp 正好指向 BarrierOutro 返回的返回地址
	ret

TRAMPOLINE_EXIT:
	; 恢复参数和栈区 - 呼叫Hook函数或者原函数
	add rsp, 32 + 16 * 4

	movups xmm3, [rsp - 4 * 16]
	movups xmm2, [rsp - 3 * 16]
	movups xmm1, [rsp - 2 * 16]
	movups xmm0, [rsp - 1 * 16]
	
	pop r9
	pop r8
	pop rdx
	pop rcx
	
	jmp qword ptr[rax] ; ! 如果呼叫Hook函数，还是会返回到当前ASM中去调用Outro去清理RuntimeInfo。
					   ; 呼叫原函数，就是正常结束
	
	
; 标志位 - 计算汇编函数长度
	db 78h
	db 56h
	db 34h
	db 12h

Trampoline_ASM_x64 ENDP

END