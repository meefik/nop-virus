@echo off

if exist gethash.obj del gethash.obj
if exist gethash.exe del gethash.exe

C:\TASM\bin\Tasm32.exe /m5 /ml gethash.asm
C:\TASM\bin\Tlink32.exe /Tpe /aa /c /x gethash.obj

pause
