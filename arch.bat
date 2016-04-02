@echo off

if exist arch.obj del arch.obj
if exist arch.exe del arch.exe

C:\LNG\ASM\TASM\bin\Tasm32.exe /m5 /ml arch.asm
C:\LNG\ASM\TASM\bin\Tlink32.exe /Tpe /aa /c /x arch.obj

pause