cd /d %~dp0
@echo off

rem Some cleanup
del /Q ppc2asm.bin ppc2asm.elf

if not exist ppc2asm.S goto NOFILE1
echo Calling assembler
kxam\xenon-as.exe -be -many ppc2asm.S -o ppc2asm.elf

if not exist ppc2asm.elf goto NOFILE2
echo Calling objcopy
kxam\xenon-objcopy.exe ppc2asm.elf -O binary ppc2asm.bin
del /q ppc2asm.elf

if not exist ppc2asm.bin goto NOFILE2

:NONP
echo.
echo ** SUCCESS! Patches Complete **
goto EXIT

:NOFILE1
echo.
echo ppc2asm.bin missing, cannot proceed
goto EXIT

:NOFILE2
echo.
echo ppc2asm.elf did not assemble, cannot proceed
goto EXIT

:NOFILE3
echo.
echo ppc2asm.bin did not build
goto EXIT

:EXIT
exit
