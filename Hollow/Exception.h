/*#ifndef _EXCEPTION_OUTPUT 
typedef enum _EXCEPTION_OUTPUT {
    ExceptionContinueExecution,
    ExceptionContinueSearch,
    ExceptionNestedException,
    ExceptionCollidedUnwind
} EXCEPTION_OUTPUT;

typedef struct _EXCEPTION_RECORD {
    DWORD                    ExceptionCode;
    DWORD                    ExceptionFlags;
    struct _EXCEPTION_RECORD* ExceptionRecord;
    PVOID                    ExceptionAddress;
    DWORD                    NumberParameters;
    ULONG_PTR                ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD;
#endif*/