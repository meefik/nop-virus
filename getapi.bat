@echo off

if exist getapi.obj del getapi.obj
if exist getapi.exe del getapi.exe

C:\TASM\bin\Tasm32.exe /m5 /ml getapi.asm
C:\TASM\bin\Tlink32.exe /Tpe /aa /c /x getapi.obj

pause