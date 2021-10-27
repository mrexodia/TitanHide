@echo off
rmdir /S /Q bin
mkdir bin\x32
mkdir bin\x64

xcopy /s /q Release\* bin\x32\
xcopy /s /q x64\Release\* bin\x64\