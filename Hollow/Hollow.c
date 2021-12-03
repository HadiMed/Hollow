// 
#include <windows.h>
#include <stdio.h>


DWORD kernel32_base, ntdll_base; 


void DLL_bases()
{
	__asm {
		xor eax, eax
		mov eax, fs:[eax + 0x30] //PEB
		mov eax , [eax+0xc] // pointer LDR 
		mov eax , [eax+0x14] // InMemoryOrderModuleList
		mov eax, [eax]	// image base of ntdll
		mov ecx , [eax+0x10]
		mov [ntdll_base] , ecx
		mov eax , [eax] // kernel32.dll
		mov ecx , [eax+0x10]
		mov [kernel32_base] , ecx
	}

}



int wmain()
{
	DLL_bases(); 

	printf("ntdll base : %x\nkernel32_Base : %x\n", ntdll_base ,kernel32_base);

}