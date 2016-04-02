;Tasm32.exe /m5 /ml *.asm
;Tlink32.exe /Tpe /aa /c /x *.obj
	includelib import32.lib
	
	extrn ExitProcess: near
	
	.386
	.model	flat
	.data

data1	db	011h
data2	db	022h
data3	db	033h

	.code
start:
	xor	eax,eax
	xor	ebx,ebx
	xor	ecx,ecx
	xor	edx,edx
	xor	edi,edi
	xor	esi,esi

	mov	dl,[data1]
	xor	dl,[data2]
	xor	dl,[data3]

	mov	ch,0ffh
@@1:	mov	cl,0ffh
@@2:	mov	bl,0ffh
@@3:	mov	al,ch
	xor	al,cl
	xor	al,bl

	cmp	al,dl
	jne	__skip
	inc	esi
	cmp	ch,[data1]
	jne	__skip	
	cmp	cl,[data2]
	jne	__skip
	cmp	bl,[data3]
	jne	__skip
	int	3
__skip:
	dec	bl
	jnz	@@3
	dec	cl
	jnz	@@2
	dec	ch
	jnz	@@1

	int	3

	push	0
	call	ExitProcess

end	start