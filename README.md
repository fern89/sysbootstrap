# sysbootstrap
Bootstrap full IAT unhooking of ntdll within kernel32. As most EDRs only hook ntdll functions and not kernel32, this code allows you to effectively fully unhook all kernel32 functions without modifying any executable memory regions, increasing stealth. By using IAT unhooking, this also avoids EDRs that scan for any changes to their hooks, as EDRs tend to rely mostly on inline hooks.

Compiled in x64 with mingw using `x86_64-w64-mingw32-gcc main.c rop.S -masm=intel -O0 -s`. Built to work only in x64 systems as you can't syscall from WOW64, and very few physical x86 machines are left.

Note this code may break for functions that do not follow standard `mov r10, rcx; mov eax, [syscall]` convention. However, I have not observed any such issues, and am able to successfully dump lsass.exe without any crash.

I have also opted to include all possible syscalls within `rop.S`, as while I am aware that it is very easy to allocate all the memory and generate everything dynamically, non-SEC_IMAGE executable memory is suspicious, possible IOC, so rather not do that. The size increase is ~5kb for hardcoded syscalls.

Full thread stack analysis will also not lead to any detections, as no early stack termination will occur. Shown is the thread stack of a `Sleep()` call:

![image](https://github.com/lemond69/sysbootstrap/assets/139056562/f13275f9-fb3a-43c7-8c5b-9c7baa597506)

`NtMapUserPhysicalPagesScatter` is shown as that is the first occurrence of the `syscall` opcode in ntdll, so that is used. It is perfectly possible to select a completely different syscall location from within ntdll.

If you are unable to modify your code for some reason, it is also easy to do unhooking of the process via DLL, using `dll.c`. DLL can be made with `x86_64-w64-mingw32-gcc dll.c rop.S -masm=intel -O0 -s -Wl,--exclude-all-symbols -shared -o [dll].dll`, then you can easily unhook the process either by a `LoadLibraryA` or a DLL injection.
