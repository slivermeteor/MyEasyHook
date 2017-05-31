.386
.model flat, c
.code

;StealthStub_ASM_x86
public StealthStub_ASM_x86@0
StealthStub_ASM_x86@0 PROC

; Create thread...	启动目标远程线程
	push		0
	push		0
	push		dword ptr [ebx + 16]		; 保存参数
	push		dword ptr [ebx + 8]			; RemoteThreadStart
	push		0
	push		0
	call		dword ptr [ebx + 0]			; CreateThread(0, NULL, RemoteThreadStart, RemoteThreadParam, 0, NULL);
	

; signal thread creation...	告诉注入方，远程线程已经启动
	push		dword ptr [ebx + 48]		
	mov			dword ptr [ebx + 48], eax	; 保存创建的远程线程句柄
	call		dword ptr [ebx + 56]		; SetEvent(hSyncEvent);
	
; wait for completion		等待注入方 完整线程句柄的Dup - 为啥要等待 - 如果我们不在这卡住，当前被劫持的线程可能退出，造成劫持方得不到句柄
	push		-1
	push		dword ptr [ebx + 32]
	call		dword ptr [ebx + 24]		; WaitForSingleObject(hCompletionEvent, INFINITE)

; close handle
	push		dword ptr [ebx + 32]		
	call		dword ptr [ebx + 40]		; CloseHandle(hCompletionEvent);

; close handle
	push		dword ptr [ebx + 48]		
	call		dword ptr [ebx + 40]		; CloseHandle(hSyncEvent);
	
	
; restore context							; 恢复 Context - 结束劫持
	mov			eax, [ebx + 64 + 8 * 0]
	mov			ecx, [ebx + 64 + 8 * 1]
	mov			edx, [ebx + 64 + 8 * 2]
	mov			ebp, [ebx + 64 + 8 * 3]
	mov			esp, [ebx + 64 + 8 * 4]
	mov			esi, [ebx + 64 + 8 * 5]
	mov			edi, [ebx + 64 + 8 * 6]
	push		dword ptr[ebx + 64 + 8 * 9] ; push EFlags	
	push		dword ptr[ebx + 64 + 8 * 8]	; save old EIP
	mov			ebx, [ebx + 64 + 8 * 7]
	
	add			esp, 4
	popfd

;   继续执行
	jmp			dword ptr [esp - 8]	
	
; outro signature, to automatically determine code size
	db 78h
	db 56h
	db 34h
	db 12h
StealthStub_ASM_x86@0 ENDP

;HookInjectionCode_ASM_x86
public Injection_ASM_x86@0
Injection_ASM_x86@0 PROC

	mov esi, dword ptr [esp + 4]	; 保存第一参数
	
;   加载 EasyHookDll
	push dword ptr [esi + 8]
	call dword ptr [esi + 40] ; call LoadLibraryW(Inject->EasyHookPath)
	mov ebp, eax
	test eax, eax
	je HookInject_FAILURE_A
	
;   HookCompleteInjection 才是真正的Hook函数
	push dword ptr [esi + 24]
	push ebp
	call dword ptr [esi + 56] ; call GetProcAddress(eax, Inject->EasyHookEntry)
	test eax, eax
	je HookInject_FAILURE_B
	
;	HookCompleteion 这个函数里才会去加载真正要注入的Dll
	push esi
	call eax	; call EasyHookEntry(Inject)
	push eax    ; 保存错误代码

;   释放EasyHookDll
	push ebp
	call dword ptr [esi + 48] ;  call FreeLibrary(ebp)
	test eax, eax
	je HookInject_FAILURE_C
	jmp HookInject_EXIT
	
HookInject_FAILURE_A:
	call dword ptr [esi + 88] ; GetLastError
	or eax, 40000000h
	jmp HookInject_FAILURE_E
HookInject_FAILURE_B:
	call dword ptr [esi + 88] ; GetLastError
	or eax, 10000000h
	jmp HookInject_FAILURE_E	
HookInject_FAILURE_C:
	call dword ptr [esi + 88] ; GetLastError
	or eax, 30000000h
	jmp HookInject_FAILURE_E	
HookInject_FAILURE_E:
	push eax 				  ; 保存错误值 - 有效栈操作
	
HookInject_EXIT:

	push 0
	push 0
	push 0	; 开启栈区
		    ; 开12个长度的栈区出来
;   Parameters |  eip  |  eax  | Stack Shell Code... |
;   n * 4 bit  | 4 bit | 4 bit |       12 bit        |
;			   ↑call
;   为啥是 +8 第一个四字节 是原本的 EBP 第二个四字节是 函数的第一参数 RemoteInfo
	lea ebx, dword ptr [esp + 8] ; 借用栈空间存放下值
	push ebx
	push 40h
	push 12
	lea ebx, dword ptr [esp + 12] ; 越过上面三个参数 - 取得写入的首地址
	push ebx
	call dword ptr [esi + 72] ; ; call VirtualProtect(Outro, 4, PAGE_EXECUTE_READWRITE, &OldProtect)
	test eax, eax
	
	jne HookInject_EXECUTABLE

;   失败 恢复栈区 返回
		call dword ptr [esi + 88] ; GetLastError
		or eax, 20000000h
		add esp, 16
		ret
		
HookInject_EXECUTABLE:
;  往开的栈区里写代码
	mov dword ptr [esp],	 0448BD3FFh		; call ebx [VirtualFree()]	;   VirtualFree(Inject->RemoteEntryPoint, 0, MEM_RELEASE);
	mov dword ptr [esp + 4], 05C8B0C24h		; mov eax, [esp + 12]
	mov dword ptr [esp + 8], 0E3FF1024h		; mov ebx, [esp + 16]
											; jmp ebx [exit thread]
	
	mov ebx, [esi + 64] ; VirtualFree()
	push 08000h
	push 0
	push dword ptr [esi + 16]		; 释放我们在RhInject 里在对方进程空间里申请的空间 也就是存放当前这段ShellCode的内存
	
	lea eax, dword ptr [esp + 12]	; 回到三个push 开始的地方 开始执行
	jmp eax							; 跳转到栈空间 让其释放掉当前这个ShellCode
	
;   标志位 计算asm函数大小			
	db 78h
	db 56h
	db 34h
	db 12h

Injection_ASM_x86@0 ENDP

;Trampoline_ASM_x86 
public Trampoline_ASM_x86@0
Trampoline_ASM_x86@0 PROC
; Hook方修正地址值
; Handle:		1A2B3C05h
; BarrierIntro: 1A2B3C03h
; OldProc:		1A2B3C01h
; NewProc:		1A2B3C00h
; BarrierOutro:	1A2B3C06h
; IsExecuted:	1A2B3C02h
; RetAddr:		1A2B3C04h
; Ptr:NewProc:	1A2B3C07h

;   parameters |  eip  | ecx, edx | 
;     n*4 bit  | 4 bit |   4 bit  | 

	mov  eax, esp
	push ecx 		; 保存参数(x86 fastcall - ecx, edx) -  (x84 thiscall ecx)
	push edx
	mov  ecx, eax	; 保存 esp 
	
	mov eax, 1A2B3C02h
	lock inc dword ptr [eax]
	
;   Hook函数有效吗 ? 
	mov eax, 1A2B3C07h
	cmp dword ptr[eax], 0
	
	db 3Eh 
	jne CALL_NET_ENTRY
	
;   呼叫原函数
		mov eax, 1A2B3C02h
		;db 0F0h 
		lock dec dword ptr [eax]
		mov eax, 1A2B3C01h
		jmp TRAMPOLINE_EXIT

;   调用Hook函数 或者 原函数
CALL_NET_ENTRY:	
;   call BarrierIntro
;					   ↓eax - old esp
;   parameters |  eip  | ecx, edx |  ecx  |
;     n*4 bit  | 4 bit |   8 bit  | 4 bit |
;			   ↑ 覆盖eip
	push ecx ; - esp
	push dword ptr [esp + 12] ; 压入返回地址
	push 1A2B3C05h 			  ; Hook handle - 区别64位 直接传入地址
	mov eax, 1A2B3C03h
	call eax ; LocalHookInfo->BarrierIntro(Hook, RetAddr, old esp); x86 第三参数不传
	
;   可以call原函数吗? - ACL 决定
	test eax, eax
	db 3Eh ; 分支标志
	jne CALL_HOOK_HANDLER
	
	; 呼叫原函数
		mov eax, 1A2B3C02h	; IsExecuted Address
		;db 0F0h 
		lock dec dword ptr [eax]
		mov eax, 1A2B3C01h	; OldProc 放入原函数地址
		jmp TRAMPOLINE_EXIT
		
CALL_HOOK_HANDLER:
; 调整返回地址 --- ATTENTION: this offset "83h" will also change if CALL_NET_OUTRO moves due to changes...
	mov dword ptr [esp + 8], 1A2B3C04h	; 覆盖 eip 值

; call Hook函数
	mov eax, 1A2B3C00h
	jmp TRAMPOLINE_EXIT 

CALL_NET_OUTRO: ; Hook函数将返回这里
; call BarrierOutro --- ATTENTION: Never change EAX/EDX from now on!
; 重新开辟栈区
;   parameters |  0  | eax edx |
;     n*4 bit  | Ret |  8 bit  |
	push 0 
	push eax   ; 保存返回值
	push edx   
	
	lea eax, [esp + 8]
	push eax 		; 存放返回值 
	push 1A2B3C05h  ; LocalHookInfo
	mov eax, 1A2B3C06h ; BarrierOutro
	call eax ; Hook->BarrierOutro(LocalHookInfo);
	
	mov eax, 1A2B3C02h
	;db 0F0h 
	lock dec dword ptr [eax]
	
	pop edx 
	pop eax
	
;   返回最初call地址 结束Hook
	ret
	
TRAMPOLINE_EXIT:
;   parameters |  eip  | ecx, edx | 
;     n*4 bit  | 4 bit |   8 bit  |
	pop edx
	pop ecx
	
	jmp eax ; 可能是 Hook 函数 或者 原函数
	
; 计算汇编函数长度
	db 78h
	db 56h
	db 34h
	db 12h

Trampoline_ASM_x86@0 ENDP

END