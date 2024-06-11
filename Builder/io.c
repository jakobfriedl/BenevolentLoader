/*
 *  ~ io.c ~
 * IO functions
 * Author: jakobfriedl
 */

#include "base.h"

#define FILENAME_BASE L"payload.bin"
#define FILENAME_ENC L"enc.bin"

 /*
  * Read binary shellcode data from file "payload.bin"
  *
  * @param pShellcode: Pointer to the shellcode read from file
  * @param sSize: Size of the shellcode read
  *
  * @returns: TRUE/FALSE if succeeded/failed
  */
BOOL ReadFromFile(OUT PBYTE* pShellcode, OUT SIZE_T* sSize) {

    BOOL bState = TRUE;
    FILE* fp = NULL;

    WCHAR CurrDr[MAX_PATH * 2];
    WCHAR InPath[MAX_PATH * 2];

    GetCurrentDirectoryW(MAX_PATH * 2, CurrDr);
    swprintf_s(InPath, MAX_PATH * 2, L"%s\\%s", CurrDr, FILENAME_BASE);
    INFO_W(L"Input file path: %s.", InPath);

    if (_wfopen_s(&fp, InPath, L"rb") != 0) {
        PRINT_ERROR("_wfopen_s");
        bState = FALSE;
        goto CLEANUP;
    }
    OKAY("[ 0x%p ] Opened file for reading.", fp);

    fseek(fp, 0, SEEK_END);
    *sSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    *pShellcode = (PBYTE)malloc(*sSize);
    if (*pShellcode == NULL) {
        PRINT_ERROR("malloc");
        bState = FALSE;
        goto CLEANUP;
    }

    if (fread(*pShellcode, sizeof(BYTE), *sSize, fp) != *sSize) {
        PRINT_ERROR("fread");
        bState = FALSE;
        goto CLEANUP;
    }
    OKAY("[ 0x%p ] %d bytes read.", fp, *sSize);

CLEANUP:

    if (fp) {
        fclose(fp);
    }

    if (!bState && *pShellcode) {
        free(*pShellcode);
        *pShellcode = NULL;
        *sSize = 0;
    }

    return bState;
}

/*
 * Write binary shellcode data to file "enc.bin"
 *
 * @param pShellcode: Shellcode to write to file
 * @param sSize: Size of the shellcode to write
 *
 * @returns: TRUE/FALSE if succeeded/failed
 */
BOOL WriteToFile(IN PBYTE pShellcode, IN SIZE_T sSize) {

    BOOL bState = TRUE;

    WCHAR CurrDr[MAX_PATH * 2];
    WCHAR OutPath[MAX_PATH * 2];
    FILE* fp = NULL;
    SIZE_T sBytesWritten = NULL;

    GetCurrentDirectoryW(MAX_PATH * 2, CurrDr);
    swprintf_s(OutPath, MAX_PATH * 2, L"%s\\%s", CurrDr, FILENAME_ENC);
    INFO_W(L"Output file path: %s.", OutPath);

    if (_wfopen_s(&fp, OutPath, L"wb") != 0) {
        PRINT_ERROR("_wfopen_s");
        bState = FALSE;
        goto CLEANUP;
    }
    OKAY("[ 0x%p ] Opened file for writing.", fp);

    sBytesWritten = fwrite(pShellcode, sizeof(BYTE), sSize, fp);
    OKAY("[ 0x%p ] %d bytes written.", fp, sBytesWritten);

CLEANUP:

    if (fp) {
        fclose(fp);
    }

    return bState;
}