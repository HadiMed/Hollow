# Documentation
## Process hollowing
- According to MITRE 

```
Process hollowing is commonly performed by creating a process in a suspended state then 
unmapping/hollowing its memory, which can then be replaced with malicious code. A victim
process can be created with native Windows API calls such as CreateProcess, which includes
a flag to suspend the processes primary thread. At this point the process can be unmapped
using APIs calls such as ZwUnmapViewOfSection or NtUnmapViewOfSection before being written 
to, realigned to the injected code, and resumed via VirtualAllocEx, WriteProcessMemory, 
SetThreadContext, then ResumeThread respectively . 
```
- for me process hollowing is learning how to write a windows loader :blush: .
## Imlementation 
Since I dont't use header files (Idk how to :p) ,I think i owe the reader an explanation , I believe 3 components should be explained in this implementation
- ***Kernel32_NTdll_bases :***
  - this function will try to resolve ***kernel32.dll*** and ***ntdll.dll*** bases using the <br/>
  ```TEB->PEB->InMemoryOrderList->base_of_exe->base_ntdll->base_kernelbase->basekernel32```
- ***find-function-address :***
  - this function will try to resolve addresses of functions used without passing via ***GetProcAddress*** , using the export table of loaded modules (ntdll,kernel32)
- ***Relocations :***
  - reloc section on PE , is basicly you have 2 structs :</br>
```
typedef struct BASE_RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;
```
this will give information about Page address plage for example : 0x1000 to 0x2000 and the block size , it's like a header of block , each block contains<br/>
multiple entries that need to be reallocated , the offset will be added to the pageAddress to locate the variable that needs to be updated . 
  - entry :
```
typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY
```
offset points to the variable that needs to be reallocated , 4 bits for the type of that variable basicly 
the loader will reloc all the variables refrenced by the binary that depends on it's prefered base address
by calculating the difference between the prefered base address and the actual base address the loader mapped that binary , that's what the last
loop in the code is good for  .
## Note 
- Purpose of this projet : Learning more about windows internals , manipulating PE files on memory , thinking of ways to obfuscate native code and apply them .
this was not intended for malicious pupose , use it on your own reponsibility :blush: .
- Things can be added and will be added for example obfuscating more the code by crypting the strings passed to find_function_address , decrypt them on runtime (done) .
