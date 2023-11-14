#include <windows.h>
#include <winternl.h>
char* names[10000]={0};
int totalFns=0;
unsigned long long int rop = 0;
void bubbleSort(long long int arr[], char* nm[], int n){ 
    int i, j; 
    for (i = 0; i < n - 1; i++){
        for (j = 0; j < n - i - 1; j++){
            if (arr[j] > arr[j + 1]){
                long long int tmp = arr[j];
                arr[j]=arr[j+1];
                arr[j+1]=tmp;
                char* tmp2 = nm[j];
                nm[j]=nm[j+1];
                nm[j+1]=tmp2;
            }
        }
    }
}
void* getDllAddr(const wchar_t * DllNameToSearch){
    PLDR_DATA_TABLE_ENTRY pDataTableEntry = 0;
    PVOID DLLAddress = 0;
    PPEB pPEB = (PPEB) __readgsqword(0x60);
    PPEB_LDR_DATA pLdr = pPEB->Ldr;
    PLIST_ENTRY AddressFirstPLIST = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY AddressFirstNode = AddressFirstPLIST->Flink;
    for (PLIST_ENTRY Node = AddressFirstNode; Node != AddressFirstPLIST ;Node = Node->Flink){
        Node = Node - 1;
        pDataTableEntry = (PLDR_DATA_TABLE_ENTRY)Node;
        wchar_t * FullDLLName = (wchar_t *)pDataTableEntry->FullDllName.Buffer;
        for(int size = wcslen(FullDLLName), cpt = 0; cpt < size ; cpt++){
    		FullDLLName[cpt] = tolower(FullDLLName[cpt]);
    	}
        if(wcsstr(FullDLLName, DllNameToSearch) != NULL){
            DLLAddress = (PVOID)pDataTableEntry->DllBase;
            return DLLAddress;
        }
        Node = Node + 1;
    }

    return DLLAddress;
}
int hunt(){
    long long int ps[10000]={0};
    HMODULE peBase = getDllAddr(L"ntdll.dll");//LoadLibraryA("ntdll.dll");
    PIMAGE_DOS_HEADER imageDosHeader = (PIMAGE_DOS_HEADER)peBase;
    PIMAGE_NT_HEADERS imageNtHeaders = (PIMAGE_NT_HEADERS)((unsigned char*)imageDosHeader + imageDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER imageOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&imageNtHeaders->OptionalHeader;
    PIMAGE_DATA_DIRECTORY imageExportDataDirectory = &(imageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((unsigned char*)peBase + imageExportDataDirectory->VirtualAddress);
    DWORD numberOfNames = imageExportDirectory->NumberOfNames;
    PDWORD exportAddressTable = (PDWORD)((unsigned char*)peBase + imageExportDirectory->AddressOfFunctions);
    PWORD nameOrdinalsPointer = (PWORD)((unsigned char*)peBase + imageExportDirectory->AddressOfNameOrdinals);
    PDWORD exportNamePointerTable = (PDWORD)((unsigned char*)peBase + imageExportDirectory->AddressOfNames);
    int c=0;
    int nameIndex = 0;
    for (nameIndex = 0; nameIndex < numberOfNames; nameIndex++){
        char* name = (char*)((unsigned char*)peBase + exportNamePointerTable[nameIndex]);
        if(memcmp(name, "Nt", 2)==0 && memcmp(name, "Ntdll", 5)!=0 && strcmp(name, "NtGetTickCount")!=0){
            WORD ordinal = nameOrdinalsPointer[nameIndex];
            unsigned char* targetFunctionAddress = ((unsigned char*)peBase + exportAddressTable[ordinal]);
            ps[c] = (long long int)targetFunctionAddress;
            names[c] = calloc(strlen(name)+1,1);
            strcpy(names[c], name);
            c++;
        }
    }
    bubbleSort(ps, names, c);
    totalFns=c;
    //now rophunt
    unsigned char* va = (unsigned char*)ps[0];
    unsigned char* vmax = (unsigned char*)ps[c-1];
    while (va <= vmax && (va[0]!='\x0f' || memcmp(va, "\x0f\x05\xc3", 3)!=0)) va++;
    if (va!=vmax) rop = (unsigned long long int)va;
    return 0;
}
int getSysId(const char* name){
    for(int i=0;i<totalFns;i++){
        if(strcmp(name, names[i])==0) return i;
    }
    return -1;
}