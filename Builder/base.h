/*
 *  ~ base.h ~
 * Common macros and function definitions
 * Author: jakobfriedl
 */

#pragma once
#include <windows.h>
#include <stdio.h>

#include "aes.h"

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

/// Function prototypes
// From io.c
BOOL ReadFromFile(OUT PBYTE* pShellcode, OUT SIZE_T* sSize); 
BOOL WriteToFile(IN PBYTE pShellcode, IN SIZE_T sSize); 

// From utils.c (mainly https://github.com/vxunderground/VX-API/tree/main/VX-API) 
PVOID CopyMemoryEx(IN OUT PVOID Destination, IN CONST PVOID Source, IN SIZE_T Length);
VOID ZeroMemoryEx(IN OUT PVOID Destination, IN SIZE_T Size);
VOID PrintByteArray(IN PBYTE pBytes, IN SIZE_T sSize);
VOID ByteArrayToC(LPCSTR Name, PBYTE Data, SIZE_T Size); 

// From crypt.c
BOOL PaddBuffer(IN PBYTE pInputBuffer, IN SIZE_T sInputBufferSize, OUT PBYTE * pOutputBuffer, OUT SIZE_T * sOutputBufferSize); 
VOID GenerateRandomBytes(PBYTE* pByte, SIZE_T sSize); 
VOID GenerateProtectedKey(IN SIZE_T sSize, OUT BYTE * pbHintByte, OUT PBYTE * ppOriginalKey, OUT PBYTE * ppProtectedKey); 