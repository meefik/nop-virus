;Tasm32.exe /m5 /ml *.asm
;Tlink32.exe /Tpe /aa /c /x *.obj

includelib c:\tasm\lib\import32.lib
	
extrn ExitProcess: near
	
.386
.model	flat

.data
api	db	"GetActiveWindow",0

.code
start:
	mov		esi,offset api

	xor		eax,eax
	push	eax
_CalcHash:
	ror		eax,7
	xor		[esp],eax
	lodsb
	test	al,al
	jnz		_CalcHash
	pop		eax

_Exit:
	; в EAX находится hesh функции
	int		3
	push	0
	call	ExitProcess
	ret
	
end	start