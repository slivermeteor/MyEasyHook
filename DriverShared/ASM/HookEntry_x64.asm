.CODE

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
		; mov rcx, r15
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