# sysbootstrap
Bootstrap full IAT unhooking of ntdll within kernel32. As most EDRs only hook ntdll functions and not kernel32, this code allows you to effectively fully unhook all kernel32 functions without modifying any executable memory regions, increasing stealth. By using IAT unhooking, this also avoids EDRs that scan for any changes to their hooks, as EDRs tend to rely mostly on inline hooks.

Compiled in x64 with mingw using `x86_64-w64-mingw32-gcc iat.c rop.S -masm=intel -O0 -s`

Note this code may break for functions that do not follow standard `mov r10, rcx; mov eax, [syscall]` convention. However, I have not observed any such issues.
