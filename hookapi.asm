;Tasm32.exe /m5 /ml *.asm
;Tlink32.exe /Tpe /aa /c /x *.obj
;	includelib import32.lib

	extrn MessageBoxA: PROC
	extrn ExitProcess: PROC
	
	.386
	.model	flat

code_size	equ	offset inject_end - offset inject_start
hook_size	equ	offset old_code - offset hook_code

	.data

szTitle         db "[API HOOK error]",0
szMessage       db "Перехват функции...",10
                db "Перехвачена функция xxx в xxx",0

kernel		db "user32.dll",0
api		db "MessageBoxA",0

szClass		db "Template_Class",0
szName		db "List Box Demo",0

	.code
start:

	call	delta
delta:	pop	ebp
	sub	ebp,offset delta

	call	GetAPIs

	mov	eax,[ebp+@WriteProcessMemory]
	mov	dword ptr [ebp+wpm_api],eax

;	call	[ebp+@GetCurrentProcess]

	push	offset szName
	push	offset szClass
	call	[ebp+@FindWindow]

	add	esp,4
	push	esp
	push	eax
	call	[ebp+@GetWindowThreadProcessId]

	pop	eax
;	mov	eax,600h

	push	eax
	push	1
	push	1F0FFFh
	call	[ebp+@OpenProcess]

	xchg	eax,esi                  ; ESI = processid
	
	push	4
	push	1000h
	push	code_size
	push	0
	push	esi
	call	[ebp+@VirtualAllocEx]

	xchg	eax,edi                  ; EDI = адрес выделенной памяти
	mov	dword ptr [hook_addr],edi

	push	offset kernel
	call	[ebp+@GetModuleHandleA]

	push	offset api
	push	eax
	call	[ebp+@GetProcAddress]

	xchg	eax,edx
	mov	dword ptr [api_addr],edx

	push	0
	push	hook_size
	push	offset old_code
	push	edx
	push	esi
	call	[ebp+@ReadProcessMemory]

	push	0
	push	code_size
	push	offset inject_start
	push	edi
	push	esi
	call	[ebp+@WriteProcessMemory]

	mov	edx,dword ptr [api_addr]

	push	0
	push	hook_size
	push	offset hook_code
	push	edx
	push	esi
	call	[ebp+@WriteProcessMemory]

_error:
        xor     eax,eax                         ; Отобpажаем MessageBox с
        push    eax                             ; глупым сообщением
        push    offset szTitle
        push    offset szMessage
        push    eax
        call    MessageBoxA

_exit:
	push	0
	call	ExitProcess
	ret
;
; код обработчика перехватываемой функции
;
inject_start	label	byte
	pushfd
	pushad
	mov	eax,offset old_code
	call	WriteData

	sub	esp,4
	xor	esi,esi
	mov	ecx,10+4
@@save:	mov	eax,[esp+esi*4+4]
	mov	[esp+esi*4],eax
	inc	esi
	loop	@@save

	mov	eax,[esp+9*4]
	mov	[esp+esi*4],eax

	popad
	popfd

	call	OriginalCall

	pushfd
	pushad
	mov	eax,offset hook_code
	call	WriteData
	popad
	popfd

	ret

OriginalCall:
	pop	dword ptr [esp]
	push	77d56476h
api_addr	equ	$-4
	ret

WriteData:
	call	_delta
_delta:	pop	ebp
	sub	ebp,offset _delta

	add	eax,ebp
	push	0
	push	hook_size
	push	eax
	push	dword ptr [ebp+api_addr]
	push	0FFFFFFFFh
	mov	eax,12345678h
wpm_api		equ	$-4
	call	eax	; WriteProcessMemory

	ret

hook_code:
	push	12345678h
hook_addr	equ	$-4
	ret

old_code	db hook_size DUP (0)

inject_end	label	byte

 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;
 ; input:
 ;      EBP - delta offset
 ;      + APITable
 ; output:
 ;      заполненная APITable

GetAPIs		proc
	lea		edi,[ebp+APITable]
_ReadSEH:
	xor		edx,edx
	mov		eax,fs:[edx]
	dec		edx
_SearchK32:
	cmp		[eax],edx
	je		_CheckK32
	mov		eax,dword [eax]
	jmp		_SearchK32

_CheckK32:
	mov		eax,[eax+4]
	xor		ax,ax

_SearchMZ:
	cmp		word ptr [eax],5A4Dh
	je		_CheckPE
	sub		eax,10000h
	jmp		_SearchMZ

_CheckPE:
	mov		edx,[eax+3ch]
	cmp		word ptr [eax+edx],4550h
	jne		_Exit

_SearchAPI:
	push	esp                   ; сохранить оригинальный esp
	mov		esi,[eax+edx+78h]     ;Export Table RVA
	add		esi,eax               ;Export Table VA
	add		esi,18h
	xchg	eax,ebx               ;EBX = Kernel32 base
	lodsd                         ;Number Of Names
	push	eax
	lodsd                         ;Address Of Functions
	push	eax
	lodsd                         ;Address Of Names 
	push	eax 
	add		eax,ebx
	push	eax                   ;Index - указатель на 1-ое имя ф-ии
	lodsd                         ;Address Of Name Ordinals 
	push	eax

_BeginSearch:
	mov		ecx,[esp+4*4]             ;Number Of Names
	xor		edx,edx

_SearchAPIName:
	mov		esi,[esp+4*1]             ;Index                                                     
	mov		esi,[esi]
	add		esi,ebx                   ;ESI = имя функции

_GetHash:
	xor		eax,eax
	push	eax
_CalcHash:
	ror		eax,7
	xor		[esp],eax
	lodsb
	test	al,al
	jnz		_CalcHash
	pop		eax

_OkHash:
	cmp		eax,dword ptr [edi]
	je		_OkAPI
	add		dword ptr [esp+4*1],4     ;I=I+4 (I--Index)
	inc		edx
	loop	_SearchAPIName 
	jmp		_Exit                     ; искомые функции не найдены :(

_OkAPI:
	shl		edx,1
	mov		ecx,[esp]                 ;OrdinalTableRVA
	add		ecx,ebx
	add		ecx,edx
	mov		ecx,[ecx]
	and		ecx,0FFFFh
	mov		edx,[esp+4*3]             ;AddressTableRVA
	add		edx,ebx
	shl		ecx,2
	add		edx,ecx
	mov		edx,[edx]
	add		edx,ebx

	add		edi,4
	mov		dword ptr [edi],edx

	add		edi,4

	cmp		word ptr [edi],00000h
	je		_nextdll

	cmp word ptr [edi],0FFFFh   ;0FFFFh-End of HeshTable
	je _Exit

_NextName:
	mov		ecx,[esp+4*2]             ;NamePointersRVA
	add		ecx,ebx
	mov		[esp+4*1],ecx             ;Index
	jmp		short _BeginSearch

_nextdll:
	mov		esp,[esp+4*5]
	add		edi,2
	push	edi
	call	[ebp+@GetModuleHandleA]
_skip:
	inc		edi
	cmp		byte ptr [edi-1],0
	jne		_skip

	jmp		_CheckPE

_Exit:
	mov		esp,[esp+4*5]
	ret

GetAPIs         endp

APITable:			; kernel32.dll
					dd 00F191CF4h
	@GetModuleHandleA		dd 0
					dd 0860B38BCh
	@CreateFileA			dd 0
					dd 0AAC2523Eh
	@GetFileSize			dd 0
					dd 03D7D6496h
	@GetFileAttributesA		dd 0
					dd 07F3545C6h
	@SetFilePointer			dd 0
					dd 0152DC5D4h
	@SetFileAttributesA		dd 0
					dd 0F867A91Eh
	@CloseHandle			dd 0
					dd 01F394C74h
	@CreateFileMappingA		dd 0
					dd 0FC6FB9EAh
	@MapViewOfFile			dd 0
					dd 0CA036058h
	@UnmapViewOfFile		dd 0
					dd 0059C5E24h
	@SetEndOfFile			dd 0
					dd 015F8EF80h
	@VirtualProtect			dd 0
					dd 0A89EA31Ah
	@GetCurrentProcess		dd 0
					dd 0FE33F9AEh
	@OpenProcess			dd 0
					dd 0632466F0h
	@VirtualAllocEx			dd 0
					dd 0B0869BCAh
	@ReadProcessMemory		dd 0
					dd 06F39E536h
	@WriteProcessMemory		dd 0
					dd 05D7574B6h
	@GetProcAddress			dd 0
					dw 0
					db "user32.dll",0
					dd 0AC8672A8h
	@GetActiveWindow		dd 0
					dd 06558FEC2h
	@GetWindowThreadProcessId	dd 0
					dd 09027F11Eh
	@FindWindow			dd 0
					dw 0FFFFh
end	start