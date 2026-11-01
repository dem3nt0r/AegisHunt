#ifndef HUNTINGTOOLS_REGISTRY_H
#define HUNTINGTOOLS_REGISTRY_H

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>

// Registry paths start with HKLM, HKU, HKCU, HKCR, or HKCC.
// Remote operations support HKLM and HKU. ComputerName may be DC01 or \\DC01.
// View is 0, KEY_WOW64_32KEY, or KEY_WOW64_64KEY.
// A null ValueName selects the default value.

LSTATUS
RegistryReadValue(
    _In_ LPCWSTR Path,
    _In_opt_ LPCWSTR ValueName,
    _Out_opt_ LPDWORD Type,
    _Out_opt_ LPBYTE Data,
    _Inout_ LPDWORD DataSize,
    _In_opt_ LPCWSTR ComputerName = NULL,
    _In_ REGSAM View = 0
);

LSTATUS
RegistryReadDword(
    _In_ LPCWSTR Path,
    _In_opt_ LPCWSTR ValueName,
    _Out_ LPDWORD Value,
    _In_opt_ LPCWSTR ComputerName = NULL,
    _In_ REGSAM View = 0
);

// The returned string is allocated from the process heap. Release it with
// RegistryFreeString.
LSTATUS
RegistryReadString(
    _In_ LPCWSTR Path,
    _In_opt_ LPCWSTR ValueName,
    _Out_ LPWSTR* Value,
    _In_opt_ LPCWSTR ComputerName = NULL,
    _In_ REGSAM View = 0
);

void
RegistryFreeString(
    _In_opt_ LPWSTR Value
);

LSTATUS
RegistryGetKeyOwner(
    _In_ LPCWSTR Path,
    _Out_writes_(BufferChars) LPWSTR Buffer,
    _In_ DWORD BufferChars,
    _In_opt_ LPCWSTR ComputerName = NULL,
    _In_ REGSAM View = 0
);

LSTATUS
RegistryQueryKey(
    _In_ LPCWSTR Path,
    _Out_opt_ LPDWORD SubKeyCount,
    _Out_opt_ LPDWORD ValueCount,
    _Out_opt_ PFILETIME LastWriteTime,
    _In_opt_ LPCWSTR ComputerName = NULL,
    _In_ REGSAM View = 0
);

LSTATUS
RegistryEnumSubKey(
    _In_ LPCWSTR Path,
    _In_ DWORD Index,
    _Out_ LPWSTR Name,
    _Inout_ LPDWORD NameChars,
    _In_opt_ LPCWSTR ComputerName = NULL,
    _In_ REGSAM View = 0
);

LSTATUS
RegistryEnumValue(
    _In_ LPCWSTR Path,
    _In_ DWORD Index,
    _Out_ LPWSTR Name,
    _Inout_ LPDWORD NameChars,
    _Out_opt_ LPDWORD Type,
    _Out_opt_ LPBYTE Data,
    _Inout_opt_ LPDWORD DataSize,
    _In_opt_ LPCWSTR ComputerName = NULL,
    _In_ REGSAM View = 0
);

// Returns a Win32 error code. Local NTSTATUS values are converted.
DWORD
RegistryLastWriteTime(
    _In_ LPCWSTR Path,
    _Out_ PFILETIME LastWriteTime,
    _In_opt_ LPCWSTR ComputerName = NULL,
    _In_ REGSAM View = 0
);

// Uses NtQueryKey on a local key handle and converts NTSTATUS to a Win32 error.
DWORD
RegistryLastWriteTimeNative(
    _In_ LPCWSTR Path,
    _Out_ PFILETIME LastWriteTime,
    _In_ REGSAM View = 0
);

LSTATUS
RegistryKeyExists(
    _In_ LPCWSTR Path,
    _Out_ PBOOL Exists,
    _In_opt_ LPCWSTR ComputerName = NULL,
    _In_ REGSAM View = 0
);

LSTATUS
RegistryWriteValue(
    _In_ LPCWSTR Path,
    _In_opt_ LPCWSTR ValueName,
    _In_ DWORD Type,
    _In_opt_ const BYTE* Data,
    _In_ DWORD DataSize,
    _In_ BOOL CreateKey = FALSE,
    _In_opt_ LPCWSTR ComputerName = NULL,
    _In_ REGSAM View = 0
);

LSTATUS
RegistryWriteDword(
    _In_ LPCWSTR Path,
    _In_opt_ LPCWSTR ValueName,
    _In_ DWORD Value,
    _In_ BOOL CreateKey = FALSE,
    _In_opt_ LPCWSTR ComputerName = NULL,
    _In_ REGSAM View = 0
);

LSTATUS
RegistryDeleteValue(
    _In_ LPCWSTR Path,
    _In_opt_ LPCWSTR ValueName,
    _In_opt_ LPCWSTR ComputerName = NULL,
    _In_ REGSAM View = 0
);

#endif // HUNTINGTOOLS_REGISTRY_H
