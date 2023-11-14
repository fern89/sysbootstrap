# sysbootstrap
Bootstrap full IAT unhooking of ntdll within kernel32. As most EDRs only hook ntdll functions and not kernel32, this code allows you to effectively fully unhook all kernel32 functions without modifying any executable memory regions, increasing stealth. By using IAT unhooking, this also avoids EDRs that scan for any changes to their hooks, as EDRs tend to rely mostly on inline hooks.

Compiled in x64 with mingw using `x86_64-w64-mingw32-gcc iat.c rop.S -masm=intel -O0 -s`

Note this code may break for functions that do not follow standard `mov r10, rcx; mov eax, [syscall]` convention. However, I have not observed any such issues, and am able to successfully dump lsass.exe without any crash.

I have also opted to include all possible syscalls within `rop.S`, as while I am aware that it is very easy to allocate all the memory and generate everything dynamically, non-SEC_IMAGE executable memory is suspicious, possible IOC, so rather not do that. The size increase is ~5kb for hardcoded syscalls.
