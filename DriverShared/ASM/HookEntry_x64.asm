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
	;BYTE*			NewProc; // fixed 8 (16) 
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
	
; ATTENTION: 64-Bit requires stack alignment (RSP) of 16 bytes!!
	mov rax, rsp
	push rcx ; save not sanitized registers...
	push rdx
	push r8
	push r9
	
	sub rsp, 4 * 16 ; space for SSE registers
	
	movups [rsp + 3 * 16], xmm0
	movups [rsp + 2 * 16], xmm1
	movups [rsp + 1 * 16], xmm2
	movups [rsp + 0 * 16], xmm3
	
	sub rsp, 32; shadow space for method calls
	
	lea rax, [IsExecutedPtr]
	mov rax, [rax]
	db 0F0h ; interlocked increment execution counter
	inc qword ptr [rax]
	
; is a user handler available?
	cmp qword ptr[NewProc], 0
	
	db 3Eh ; branch usually taken
	jne CALL_NET_ENTRY
	
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; call original method
		lea rax, [IsExecutedPtr]
		mov rax, [rax]
		db 0F0h ; interlocked decrement execution counter
		dec qword ptr [rax]
		
		lea rax, [OldProc]
		jmp TRAMPOLINE_EXIT

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; call hook handler or original method...
CALL_NET_ENTRY:	

	
; call NET intro
	lea rcx, [IsExecutedPtr + 8] ; Hook handle (only a position hint)
	mov rdx, qword ptr [rsp + 32 + 4 * 16 + 4 * 8] ; push return address
	lea r8, qword ptr [rsp + 32 + 4 * 16 + 4 * 8]  ; push address of return address
	call qword ptr [NETIntro] ; Hook->NETIntro(Hook, RetAddr, InitialRSP);
	
; should call original method?
	test rax, rax
	
	db 3Eh ; branch usually taken
	jne CALL_HOOK_HANDLER
	
	; call original method
		lea rax, [IsExecutedPtr]
		mov rax, [rax]
		db 0F0h ; interlocked decrement execution counter
		dec qword ptr [rax]
	
		lea rax, [OldProc]
		jmp TRAMPOLINE_EXIT
		
CALL_HOOK_HANDLER:
; adjust return address
	lea rax, [CALL_NET_OUTRO]
	mov qword ptr [rsp + 32 + 4 * 16 + 4 * 8], rax

; call hook handler
	lea rax, [NewProc]
	jmp TRAMPOLINE_EXIT 

CALL_NET_OUTRO: ; this is where the handler returns...

; call NET outro
	push 0 ; space for return address
	push rax
	
	sub rsp, 32 + 16; shadow space for method calls and SSE registers
	movups [rsp + 32], xmm0
	
	lea rcx, [IsExecutedPtr + 8]  ; Param 1: Hook handle hint
	lea rdx, [rsp + 56] ; Param 2: Address of return address
	call qword ptr [NETOutro] ; Hook->NETOutro(Hook);
	
	lea rax, [IsExecutedPtr]
	mov rax, [rax]
	db 0F0h ; interlocked decrement execution counter
	dec qword ptr [rax]
	
	add rsp, 32 + 16
	movups xmm0, [rsp - 16]
	
	pop rax ; restore return value of user handler...
	
; finally return to saved return address - the caller of this trampoline...
	ret
	
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; generic outro for both cases...
TRAMPOLINE_EXIT:

	add rsp, 32 + 16 * 4

	movups xmm3, [rsp - 4 * 16]
	movups xmm2, [rsp - 3 * 16]
	movups xmm1, [rsp - 2 * 16]
	movups xmm0, [rsp - 1 * 16]
	
	pop r9
	pop r8
	pop rdx
	pop rcx
	
	jmp qword ptr[rax] ; ATTENTION: In case of hook handler we will return to CALL_NET_OUTRO, otherwise to the caller...
	
	
; outro signature, to automatically determine code size
	db 78h
	db 56h
	db 34h
	db 12h

Trampoline_ASM_x64 ENDP

END