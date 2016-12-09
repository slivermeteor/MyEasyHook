.CODE

public StealthStub_ASM_x64
	int 3
StealthStub_ASM_x64 PROC
	int 3;
	sub			rsp, 8 * 4   ; ??? 
	
	mov			qword ptr[rsp + 40], 0
	mov			qword ptr[rsp + 32], 0
	mov			r9, qword ptr [rbx + 16]	; RemoteThreadParam
	mov			r8, qword ptr [rbx + 8]		; RemoteThreadStart
	mov			rdx, 0
	mov			rcx, 0
	call		qword ptr[rbx]				; CreateThread
	cmp			rax, 0

; signal completion 通知原函数 创建成功
	mov			rcx, qword ptr [rbx + 48]	; 把SynchronEventHandle取出来	
	mov			qword ptr [rbx + 48], rax	; 保存创建的远程线程句柄
	call		qword ptr [rbx + 56]		; SetEvent(hSyncEvent);

; wait for completion 等待原函数Duplicate远程线程句柄
	mov			rdx, -1
	mov			rcx, qword ptr [rbx + 32]
	call		qword ptr [rbx + 24]		; WaitForSingleObject(hCompletionEvent, INFINITE)	

; close handle
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
	
; outro signature, to automatically determine code size
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
	sub         rsp, 40  ; space for register parameter stack, should be 32 bytes... no idea why it only works with 40
	
; call LoadLibraryW(Inject->EasyHookPath);
	mov         rcx, qword ptr [r14 + 8]
	call        qword ptr [r14 + 40] ; LoadLibraryW
	mov			r13, rax
	test		rax, rax
	je			HookInject_FAILURE_A
	
; call GetProcAddress(hModule, Inject->EntryPoint)
	mov         rdx, qword ptr [r14 + 24] 
	mov         rcx, rax 
	call        qword ptr [r14 + 56] ; GetProcAddress 
	test		rax, rax
	je			HookInject_FAILURE_B
	
; call EasyHookEntry(Inject);
	mov			rcx, r14
	call		rax
	mov			r15, rax ; save error code to non-volatile register

; call FreeLibrary(hEasyHookLib)
	mov			rcx, r13
	call		qword ptr [r14 + 48] ; FreeLibrary
	test		rax, rax
	je			HookInject_FAILURE_C
	
	jmp			HookInject_EXIT
	
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
	mov			r15, rax ; save error value
	
HookInject_EXIT:

; call VirtualProtect(Outro, 8, PAGE_EXECUTE_READWRITE, &OldProtect)
	lea			rbx, qword ptr [rsp + 8] ; writes into register parameter stack
	mov			r9, rbx
	mov			r8, 40h
	mov			rdx, 8
	mov			rcx, rbx
	call		qword ptr [r14 + 72] ; VirtualProtect
	test		rax, rax
	
	jne HookInject_EXECUTABLE

	; failed to make stack executable
		call		qword ptr [r14 + 88] ; GetLastError
		or			rax, 01000000h
		mov			rcx, rax
		call		qword ptr [r14 + 80] ; ExitThread
		
HookInject_EXECUTABLE:
; save outro to executable stack
	mov			rbx, [r14 + 64] ; VirtualFree()
	mov			rbp, [r14 + 80] ; ExitThread()
	
	mov			rax, 000D5FFCF8B49D3FFh
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

END