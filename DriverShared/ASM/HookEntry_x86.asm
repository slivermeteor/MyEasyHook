;
;    EasyHook - The reinvention of Windows API hooking
; 
;    Copyright (C) 2009 Christoph Husse
;
;    This library is free software; you can redistribute it and/or
;    modify it under the terms of the GNU Lesser General Public
;    License as published by the Free Software Foundation; either
;    version 2.1 of the License, or (at your option) any later version.
;
;    This library is distributed in the hope that it will be useful,
;    but WITHOUT ANY WARRANTY; without even the implied warranty of
;    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
;    Lesser General Public License for more details.
;
;    You should have received a copy of the GNU Lesser General Public
;    License along with this library; if not, write to the Free Software
;    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
;
;    Please visit http://www.codeplex.com/easyhook for more information
;    about the project and latest updates.
;

.386
.model flat, c
.code

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;	
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; StealthStub_ASM_x86
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
public StealthStub_ASM_x86@0

StealthStub_ASM_x86@0 PROC

; Create thread...			启动目标远程线程
	push		0
	push		0
	push		dword ptr [ebx + 16]		; save stealth context
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

; continue execution...
	jmp			dword ptr [esp - 8]	
	
; outro signature, to automatically determine code size
	db 78h
	db 56h
	db 34h
	db 12h
StealthStub_ASM_x86@0 ENDP

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;	
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; HookInjectionCode_ASM_x86
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
public Injection_ASM_x86@0
Injection_ASM_x86@0 PROC
; no registers to save, because this is the thread main function
; save first param (address of hook injection information)

	mov esi, dword ptr [esp + 4]
	
; call LoadLibraryW(Inject->EasyHookPath); 加载 EasyHookDll
	push dword ptr [esi + 8]
	
	call dword ptr [esi + 40] ; LoadLibraryW@4
	mov ebp, eax
	test eax, eax
	je HookInject_FAILURE_A
	
; call GetProcAddress(eax, Inject->EasyHookEntry); --- HookCompleteInjection 才是真正的Hook函数
	push dword ptr [esi + 24]
	push ebp
	call dword ptr [esi + 56] ; GetProcAddress@8
	test eax, eax
	je HookInject_FAILURE_B
	
; call EasyHookEntry(Inject);	HookCompleteion 这个函数里才会去加载真正要注入的Dll
	push esi
	call eax
	push eax ; save error code

; call FreeLibrary(ebp)
	push ebp
	call dword ptr [esi + 48] ; FreeLibrary@4
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
	push eax ; save error value
	
HookInject_EXIT:

	push 0
	push 0
	push 0; // shadow space for executable stack part...
		  ; 开12个长度的栈区出来
; call VirtualProtect(Outro, 4, PAGE_EXECUTE_READWRITE, &OldProtect)
	; 为啥是 +8 第一个四字节 是原本的 EBP 第二个四字节是 函数的第一参数 RemoteInfo
	lea ebx, dword ptr [esp + 8] ; we'll write to shadow space
	push ebx
	push 40h
	push 12
	push ebx
	call dword ptr [esi + 72] ; VirtualProtect@16 让上面开的12字节长的栈区可以写
	test eax, eax
	
	jne HookInject_EXECUTABLE

	; failed to make stack executable 失败 恢复栈区 返回
		call dword ptr [esi + 88] ; GetLastError
		or eax, 20000000h
		add esp, 16
		ret
		
HookInject_EXECUTABLE:
; save outro to executable stack 往开的栈区里写代码
	mov dword ptr [esp],	 0448BD3FFh		; call ebx [VirtualFree()]
	mov dword ptr [esp + 4], 05C8B0C24h		; mov eax, [esp + 12]
	mov dword ptr [esp + 8], 0E3FF1024h		; mov ebx, [esp + 16]
											; jmp ebx [exit thread]
	
; save params for VirtualFree(Inject->RemoteEntryPoint, 0, MEM_RELEASE);
	mov ebx, [esi + 64] ; VirtualFree()
	push 08000h
	push 0
	push dword ptr [esi + 16]	; 释放我们在RhInject 里在对方进程空间里申请的空间 也就是存放当前这段ShellCode的内存
	
	lea eax, dword ptr [esp + 12]	; 回到三个push 开始的地方 开始执行
	jmp eax							; 跳转到栈空间 让其释放掉当前这个ShellCode
	
; outro signature, to automatically determine code size
	db 78h
	db 56h
	db 34h
	db 12h

Injection_ASM_x86@0 ENDP

END