#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include "iat.h"

int main(){
    unhook();
    printf("Unhooked, sleeping...\n");
    Sleep(10000);
    printf("Done\n");
    getchar();
    return 0;
}
