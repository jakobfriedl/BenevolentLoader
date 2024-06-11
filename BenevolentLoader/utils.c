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

// https://github.com/vxunderground/VX-API/blob/main/VX-API/StringLength.cpp
SIZE_T StringLengthA(_In_ LPCSTR String) {
    LPCSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

SIZE_T StringLengthW(_In_ LPCWSTR String) {
    LPCWSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

// https://github.com/vxunderground/VX-API/blob/main/VX-API/RtlInitUnicodeString.cpp
VOID RtlInitUnicodeString(IN OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString) {
    SIZE_T DestSize;

    if (SourceString) {
        DestSize = StringLengthW(SourceString) * sizeof(WCHAR);
        DestinationString->Length = (USHORT)DestSize;
        DestinationString->MaximumLength = (USHORT)DestSize + sizeof(WCHAR);
    }
    else {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
    }

    DestinationString->Buffer = (PWCHAR)SourceString;
}