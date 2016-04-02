@echo off

if exist hookapi.obj del hookapi.obj
if exist hookapi.exe del hookapi.exe

C:\LNG\ASM\TASM\bin\Tasm32.exe /m5 /ml hookapi
C:\LNG\ASM\TASM\bin\Tlink32.exe /Tpe /aa /c /x hookapi,hookapi,,C:\LNG\ASM\TASM\lib\import32.lib,

pause