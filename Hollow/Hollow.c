#include <windows.h>
#include <stdio.h>

typedef  DWORD(__stdcall *_GetProcAddress)(DWORD, LPCSTR);
typedef DWORD(__stdcall* _WinExec)(LPCSTR, u_int);
typedef NTSTATUS(WINAPI* _NtUnmapViewOfSection)(HANDLE, PVOID); 
 

DWORD kernel32_base, ntdll_base; 


void Kernel32_NTdll_bases()
{
	__asm {
		pushad
		xor eax , eax
		mov eax , fs:[eax + 0x30] //PEB
		mov eax , [eax+0xc] // pointer LDR 
		mov eax , [eax+0x14] // InMemoryOrderModuleList
		mov eax , [eax]	 
		mov ecx , [eax+0x10] // image base of ntdll 
		mov [ntdll_base] , ecx
		mov eax , [eax] // kernel32.dll
		mov ecx , [eax+0x10]
		mov [kernel32_base] , ecx // image base of kernel32.dll
		popad
	}

}

DWORD find_function_address(DWORD base , char * function_name)
{

	__asm {
		/* Virtual addresses to (exported , name , ordinal) tables*/
		mov eax, base
		mov edx, [eax + 0x3c] // RVA PE signature
		add edx, eax // address of PE signature
		mov edx, [edx + 0x78] // RVA of export table  
		/* mov eax , [eax+0x14]  number of exported functions*/
		add edx, eax // address export table
		mov ebx, [edx + 0x1c] // RVA exported functions
		add ebx, eax // EBX  = va of exported functions
		mov esi, [edx + 0x20] // RVA name_pointer_table
		add esi, eax // ESI = va of name_pointer_table
		mov edx, [edx + 0x24] // RVA of ordinal table
		add edx, eax // EDX = va of ordinal table

		/*length function name*/
		push eax /* saving base address on the stack*/
		xor ecx , ecx
		mov edi, function_name
		xor eax, eax
		repp:
		inc ecx
			cmp [edi + ecx], 0
			jz compare_names
			inc ecx
			jmp repp
			/*Function address*/
		
		compare_names:
			cld // Direction flag , process string from left to right
			push esi
			mov esi, [esi + eax * 4]
			add esi, [esp+4]
			push ecx // save value (repe cmpsb change it)
			push edi
			repe cmpsb // is [edi]==[esi] ?
			pop edi
			pop ecx
			pop esi
			jz name_found
			inc eax
			jmp compare_names
		name_found:
			pop esi // base
			mov ax, [edx + eax * 2] // function ordinal
			mov edx , [ebx + eax * 4] // RVA of function
			add edx , esi
		 
		xchg eax , edx
	}
}



int wmain()
{
	Kernel32_NTdll_bases();
	_GetProcAddress GetProcAddr= find_function_address(kernel32_base, "GetProcAddress");
	printf("GetProcAddr @0x%x\n" , GetProcAddr);
	_WinExec Winex= GetProcAddr(kernel32_base, "WinExec"); 
	printf("Winexec at : @0x%x\n", Winex);
	Winex("cmd.exe", 0);
	_NtUnmapViewOfSection NtUnmapViewOfSe = find_function_address(ntdll_base, "NtUnmapViewOfSection");
	_NtUnmapViewOfSection NtUnmapViewOfTrue = GetProcAddr(ntdll_base, "NtUnmapViewOfSection");

	printf("_NtUnmapViewOfSection at @0x%x", NtUnmapViewOfSe); 
	//printf("ntdll base : @0x%x\nkernel32_Base : @0x%x\n", ntdll_base ,kernel32_base);
}