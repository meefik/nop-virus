@echo off

if exist infect.obj del infect.obj
if exist infect.exe del infect.exe

C:\LNG\ASM\TASM\bin\tasm32 /ml /m5 infect,,
C:\LNG\ASM\TASM\bin\tlink32 /Tpe /aa /c /x infect,infect,,C:\LNG\ASM\TASM\lib\import32.lib,

pause