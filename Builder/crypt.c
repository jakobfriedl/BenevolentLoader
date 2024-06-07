/*
 *  ~ crypt.c ~
 * Additional encryption functions and utils
 * Author: jakobfriedl
 */

#include "base.h"

BOOL PaddBuffer(IN PBYTE pInputBuffer, IN SIZE_T sInputBufferSize, OUT PBYTE* pOutputBuffer, OUT SIZE_T* sOutputBufferSize) {

    PRINTA("[~~~] Padding base shellcode since it's length is not a multiple of 16.\n");

    PBYTE pPaddedBuffer = NULL; 
    SIZE_T sPaddedSize = NULL; 

    // calculate the nearest number that is multiple of 16 and saving it to PaddedSize
    sPaddedSize = sInputBufferSize + 16 - (sInputBufferSize & 16); 
    
    // Allocate buffer of size sPaddedSize
    pPaddedBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sPaddedSize); 
    if (!pPaddedBuffer) {
        PRINT_ERROR("HeapAlloc");
        return FALSE;
    }

    // Clean up buffer
    ZeroMemoryEx(pPaddedBuffer, sPaddedSize); 
    // Move unpadded buffer to new padded buffer
    CopyMemoryEx(pPaddedBuffer, pInputBuffer, sInputBufferSize); 

    // Store results
    *pOutputBuffer = pPaddedBuffer; 
    *sOutputBufferSize = sPaddedSize; 

    return TRUE; 
}

// Generate random bytes of size sSize
VOID GenerateRandomBytes(PBYTE* pByte, SIZE_T sSize) {

    PBYTE pTmpBytes = (PBYTE)malloc(sSize);;

    for (int i = 0; i < sSize; i++) {
        pTmpBytes[i] = (BYTE)rand() % 0xFF;
    }

    *pByte = pTmpBytes; 
}

VOID GenerateProtectedKey(IN SIZE_T sSize, OUT BYTE* pbHintByte, OUT PBYTE* ppOriginalKey, OUT PBYTE* ppProtectedKey) {
    
    srand(time(NULL) * sSize);

    BYTE bHintByte = (BYTE)((rand() % 0xFF) * 2);
    *pbHintByte = bHintByte; 

    BYTE b = rand() % 0xFF; // Random byte
    PBYTE pKey = (PBYTE)malloc(sSize);
    PBYTE pProtectedKey = (PBYTE)malloc(sSize);

    if (!pKey || !pProtectedKey)
        return;

    srand(time(NULL) * 2);

    // Generate the encryption key with HintByte at the first index
    pKey[0] = bHintByte;
    for (int i = 1; i < sSize; i++) {
        pKey[i] = (BYTE)rand() % 0xFF;
    }

    *ppOriginalKey = pKey; 

    // Perform XOR encryption on the key to get the protected key
    for (int i = 0; i < sSize; i++) {
        pProtectedKey[i] = (BYTE)((pKey[i] + i) ^ b);
    }

    *ppProtectedKey = pProtectedKey;
}