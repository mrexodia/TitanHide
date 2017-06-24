@echo off
rmdir /S /Q bin
mkdir bin\x32\plugins
mkdir bin\x64\plugins

copy Win7Release\*.* bin\x32\
copy Release\*.exe bin\x32\
copy Release\*.dll bin\x32\plugins\
copy Release\TitanHide.dp32 bin\x32\plugins\
copy x64\Win7Release\*.* bin\x64\
copy x64\Release\*.exe bin\x64\
copy x64\Release\*.dll bin\x64\plugins\
copy x64\Release\TitanHide.dp64 bin\x64\plugins\