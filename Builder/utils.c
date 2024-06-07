/*
 *  ~ utils.c ~
 * Function implementations for different features
 * Author: jakobfriedl
 */

#include "base.h"

 // https://github.com/vxunderground/VX-API/blob/main/VX-API/CopyMemoryEx.cpp
PVOID CopyMemoryEx(IN OUT PVOID Destination, IN CONST PVOID Source, IN SIZE_T Length) {
    PBYTE D = (PBYTE)Destination;
    PBYTE S = (PBYTE)Source;

    while (Length--)
        *D++ = *S++;

    return Destination;
}

// https://github.com/vxunderground/VX-API/blob/main/VX-API/ZeroMemoryEx.cpp
VOID ZeroMemoryEx(IN OUT PVOID Destination, IN SIZE_T Size) {
    PULONG Dest = (PULONG)Destination;
    SIZE_T Count = Size / sizeof(ULONG);

    while (Count > 0) {
        *Dest = 0;
        Dest++;
        Count--;
    }

    return;
}

VOID PrintByteArray(IN PBYTE pBytes, IN SIZE_T sSize) {
    PRINTA("\n    ");
    for (SIZE_T i = 0; i < sSize; ++i) {
        PRINTA("%02X", pBytes[i]);
        if (i < sSize - 1) {
            PRINTA(" ");
        }
        if ((i + 1) % 20 == 0) {
            PRINTA("\n    ");
        }
    }
    PRINTA("\n\n");
}

VOID ByteArrayToC(LPCSTR Name, PBYTE Data, SIZE_T Size) {

    PRINTA("unsigned char %s[] = {", Name);
    for (int i = 0; i < Size; i++) {
        if (i % 16 == 0) {
            PRINTA("\n\t");
        }
        if (i < Size - 1) {
            PRINTA("0x%0.2X, ", Data[i]);
        }
        else {
            PRINTA("0x%0.2X ", Data[i]);
        }
    }
    PRINTA("};\n\n"); 
}