@echo off

if exist nop.obj del nop.obj
if exist nop.exe del nop.exe

C:\LNG\ASM\TASM\bin\tasm32 /ml /m5 nop,,
C:\LNG\ASM\TASM\bin\tlink32 /Tpe /aa /c /x nop,nop,,C:\LNG\ASM\TASM\lib\import32.lib,

pause