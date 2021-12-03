// 
#include <windows.h>

DWORD kernel32base()
{
	__asm {
		xor eax, eax
		mov eax, fs:[eax + 0x30] //PEB
		mov eax , [eax+0xc] // Load
	}

}



int wmain()
{
	return 0;
}