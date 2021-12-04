// 
#include <windows.h>
#include <stdio.h>


DWORD kernel32_base, ntdll_base; 


void Kernel32_NTdll_bases()
{
	__asm {
		xor eax, eax
		mov eax, fs:[eax + 0x30] //PEB
		mov eax , [eax+0xc] // pointer LDR 
		mov eax , [eax+0x14] // InMemoryOrderModuleList
		mov eax, [eax]	 
		mov ecx , [eax+0x10] // image base of ntdll 
		mov [ntdll_base] , ecx
		mov eax , [eax] // kernel32.dll
		mov ecx , [eax+0x10]
		mov [kernel32_base] , ecx // image base of kernel32.dll
	}

}



int wmain()
{
	Kernel32_NTdll_bases(); 
	printf("ntdll base : %x\nkernel32_Base : %x\n", ntdll_base ,kernel32_base);

}