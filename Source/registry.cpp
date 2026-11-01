#include "registry.h"

#include <aclapi.h>

#include <cstring>
#include <cwchar>

typedef struct _REGISTRY_PATH_PARTS
{
    HKEY Root;
    LPCWSTR SubKey;
} REGISTRY_PATH_PARTS;

typedef struct _REGISTRY_CACHED_KEY_INFORMATION
{
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG SubKeys;
    ULONG MaxNameLen;
    ULONG Values;
    ULONG MaxValueNameLen;
    ULONG MaxValueDataLen;
    ULONG NameLength;
} REGISTRY_CACHED_KEY_INFORMATION;

typedef LONG(NTAPI* PFN_NT_QUERY_KEY)(HANDLE, INT, PVOID, ULONG, PULONG);
typedef ULONG(NTAPI* PFN_RTL_NT_STATUS_TO_DOS_ERROR)(LONG);

static BOOL RegistryHiveEquals(LPCWSTR Hive, size_t Length, LPCWSTR Expected)
{
    size_t index = 0;
    WCHAR left = 0;
    WCHAR right = 0;

    for (index = 0; index < Length; ++index) {
        if (Expected[index] == L'\0') {
            return FALSE;
        }
        left = Hive[index];
        right = Expected[index];
        if (left >= L'a' && left <= L'z') {
            left -= L'a' - L'A';
        }
        if (right >= L'a' && right <= L'z') {
            right -= L'a' - L'A';
        }
        if (left != right) {
            return FALSE;
        }
    }
    return Expected[index] == L'\0' ? TRUE : FALSE;
}

static DWORD RegistryParsePath(LPCWSTR Path, REGISTRY_PATH_PARTS* Parts)
{
    LPCWSTR separator = NULL;
    size_t length = 0;

    if (Path == NULL || Path[0] == L'\0' || Parts == NULL) {
        return ERROR_INVALID_PARAMETER;
    }

    separator = wcschr(Path, L'\\');
    length = separator == NULL ? wcslen(Path) : static_cast<size_t>(separator - Path);
    if (RegistryHiveEquals(Path, length, L"HKLM") ||
        RegistryHiveEquals(Path, length, L"HKEY_LOCAL_MACHINE")) {
        Parts->Root = HKEY_LOCAL_MACHINE;
    }
    else if (RegistryHiveEquals(Path, length, L"HKU") ||
        RegistryHiveEquals(Path, length, L"HKEY_USERS")) {
        Parts->Root = HKEY_USERS;
    }
    else if (RegistryHiveEquals(Path, length, L"HKCU") ||
        RegistryHiveEquals(Path, length, L"HKEY_CURRENT_USER")) {
        Parts->Root = HKEY_CURRENT_USER;
    }
    else if (RegistryHiveEquals(Path, length, L"HKCR") ||
        RegistryHiveEquals(Path, length, L"HKEY_CLASSES_ROOT")) {
        Parts->Root = HKEY_CLASSES_ROOT;
    }
    else if (RegistryHiveEquals(Path, length, L"HKCC") ||
        RegistryHiveEquals(Path, length, L"HKEY_CURRENT_CONFIG")) {
        Parts->Root = HKEY_CURRENT_CONFIG;
    }
    else {
        return ERROR_INVALID_PARAMETER;
    }

    Parts->SubKey = separator == NULL ? L"" : separator + 1;
    return ERROR_SUCCESS;
}

static LSTATUS RegistryOpenPath(LPCWSTR Path, LPCWSTR ComputerName, REGSAM Rights, REGSAM View,
    BOOL CreateKey, PHKEY Opened)
{
    LSTATUS status = ERROR_SUCCESS;
    LSTATUS close_status = ERROR_SUCCESS;
    HKEY root = NULL;
    HKEY remote = NULL;
    REGISTRY_PATH_PARTS parts = {};
    WCHAR machine[260] = {};
    LPCWSTR remote_name = NULL;
    size_t name_length = 0;

    if (Opened == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    *Opened = NULL;

    if (View != 0 && View != KEY_WOW64_32KEY && View != KEY_WOW64_64KEY) {
        return ERROR_INVALID_PARAMETER;
    }

    status = RegistryParsePath(Path, &parts);
    if (status != ERROR_SUCCESS) {
        return status;
    }

    if (CreateKey && parts.SubKey[0] == L'\0') {
        return ERROR_INVALID_PARAMETER;
    }

    root = parts.Root;
    if (ComputerName != NULL && ComputerName[0] != L'\0') {
        if (root != HKEY_LOCAL_MACHINE && root != HKEY_USERS) {
            return ERROR_INVALID_PARAMETER;
        }

        remote_name = ComputerName;
        if (ComputerName[0] != L'\\' || ComputerName[1] != L'\\') {
            if (ComputerName[0] == L'\\') {
                return ERROR_INVALID_PARAMETER;
            }

            name_length = wcslen(ComputerName);
            if (name_length > 257) {
                return ERROR_BAD_NET_NAME;
            }

            machine[0] = L'\\';
            machine[1] = L'\\';
            memcpy(machine + 2, ComputerName, (name_length + 1) * sizeof(WCHAR));
            remote_name = machine;
        }

        status = RegConnectRegistryW(remote_name, root, &remote);
        if (status != ERROR_SUCCESS) {
            return status;
        }
        root = remote;
    }

    if (CreateKey) {
        status = RegCreateKeyExW(root, parts.SubKey, 0, NULL, REG_OPTION_NON_VOLATILE,
            Rights | View, NULL, Opened, NULL);
    }
    else {
        status = RegOpenKeyExW(root, parts.SubKey[0] == L'\0' ? NULL : parts.SubKey, 0,
            Rights | View, Opened);
    }

    if (remote != NULL) {
        close_status = RegCloseKey(remote);
        if (status == ERROR_SUCCESS && close_status != ERROR_SUCCESS) {
            RegCloseKey(*Opened);
            *Opened = NULL;
            return close_status;
        }
    }

    return status;
}

static LSTATUS RegistryClosePath(HKEY Key, LSTATUS OperationStatus)
{
    LSTATUS close_status = ERROR_SUCCESS;

    close_status = RegCloseKey(Key);
    return OperationStatus == ERROR_SUCCESS ? close_status : OperationStatus;
}

LSTATUS RegistryReadValue(LPCWSTR Path, LPCWSTR ValueName, LPDWORD Type, LPBYTE Data,
    LPDWORD DataSize, LPCWSTR ComputerName, REGSAM View)
{
    HKEY key = NULL;
    LSTATUS status = ERROR_SUCCESS;

    if (DataSize == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    status = RegistryOpenPath(Path, ComputerName, KEY_QUERY_VALUE, View, FALSE, &key);
    if (status != ERROR_SUCCESS) {
        return status;
    }
    status = RegQueryValueExW(key, ValueName, NULL, Type, Data, DataSize);
    return RegistryClosePath(key, status);
}

LSTATUS RegistryReadDword(LPCWSTR Path, LPCWSTR ValueName, LPDWORD Value, LPCWSTR ComputerName,
    REGSAM View)
{
    DWORD type = REG_NONE;
    DWORD size = sizeof(DWORD);
    DWORD data = 0;
    LSTATUS status = ERROR_SUCCESS;

    if (Value == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    status = RegistryReadValue(Path, ValueName, &type, reinterpret_cast<LPBYTE>(&data), &size,
        ComputerName, View);
    if (status != ERROR_SUCCESS) {
        return status;
    }
    if (type != REG_DWORD || size != sizeof(DWORD)) {
        return ERROR_INVALID_DATA;
    }
    *Value = data;
    return ERROR_SUCCESS;
}

void RegistryFreeString(LPWSTR Value)
{
    if (Value != NULL) {
        HeapFree(GetProcessHeap(), 0, Value);
    }
}

LSTATUS RegistryReadString(LPCWSTR Path, LPCWSTR ValueName, LPWSTR* Value,
    LPCWSTR ComputerName, REGSAM View)
{
    DWORD type = REG_NONE;
    DWORD size = 0;
    LSTATUS status = ERROR_SUCCESS;
    LPWSTR buffer = NULL;

    if (Path == NULL || Value == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    *Value = NULL;
    status = RegistryReadValue(Path, ValueName, &type, NULL, &size,
        ComputerName, View);
    if (status != ERROR_SUCCESS) {
        return status;
    }
    if (type != REG_SZ && type != REG_EXPAND_SZ) {
        return ERROR_INVALID_DATA;
    }
    if (size > MAXDWORD - sizeof(WCHAR)) {
        return ERROR_ARITHMETIC_OVERFLOW;
    }
    buffer = static_cast<LPWSTR>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
        size + sizeof(WCHAR)));
    if (buffer == NULL) {
        return ERROR_OUTOFMEMORY;
    }
    status = RegistryReadValue(Path, ValueName, &type,
        reinterpret_cast<LPBYTE>(buffer), &size,
        ComputerName, View);
    if (status != ERROR_SUCCESS) {
        RegistryFreeString(buffer);
        return status;
    }
    if ((size & 1) != 0 || (type != REG_SZ && type != REG_EXPAND_SZ)) {
        RegistryFreeString(buffer);
        return ERROR_INVALID_DATA;
    }
    buffer[size / sizeof(WCHAR)] = L'\0';
    *Value = buffer;
    return ERROR_SUCCESS;
}

LSTATUS RegistryGetKeyOwner(LPCWSTR Path, LPWSTR Buffer, DWORD BufferChars,
    LPCWSTR ComputerName, REGSAM View)
{
    HKEY key = NULL;
    PSID owner = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    WCHAR account[128] = {};
    WCHAR domain[128] = {};
    DWORD account_chars = 128;
    DWORD domain_chars = 128;
    SID_NAME_USE use = SidTypeUnknown;
    INT formatted = 0;
    LSTATUS status = ERROR_SUCCESS;

    if (Path == NULL || Buffer == NULL || BufferChars == 0) {
        return ERROR_INVALID_PARAMETER;
    }
    Buffer[0] = L'\0';
    status = RegistryOpenPath(Path, ComputerName, READ_CONTROL, View, FALSE, &key);
    if (status != ERROR_SUCCESS) {
        return status;
    }
    status = GetSecurityInfo(reinterpret_cast<HANDLE>(key), SE_REGISTRY_KEY,
        OWNER_SECURITY_INFORMATION, &owner, NULL, NULL, NULL,
        &descriptor);
    if (status == ERROR_SUCCESS &&
        !LookupAccountSidW(NULL, owner, account, &account_chars,
            domain, &domain_chars, &use)) {
        status = GetLastError();
    }
    if (status == ERROR_SUCCESS) {
        formatted = swprintf(Buffer, BufferChars, L"%ls\\%ls", domain, account);
        if (formatted < 0) {
            status = ERROR_INSUFFICIENT_BUFFER;
        }
    }
    if (descriptor != NULL) {
        LocalFree(descriptor);
    }
    return RegistryClosePath(key, status);
}

LSTATUS RegistryQueryKey(LPCWSTR Path, LPDWORD SubKeyCount, LPDWORD ValueCount,
    PFILETIME LastWriteTime, LPCWSTR ComputerName, REGSAM View)
{
    HKEY key = NULL;
    LSTATUS status = ERROR_SUCCESS;

    status = RegistryOpenPath(Path, ComputerName, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, View,
        FALSE, &key);
    if (status != ERROR_SUCCESS) {
        return status;
    }
    status = RegQueryInfoKeyW(key, NULL, NULL, NULL, SubKeyCount, NULL, NULL, ValueCount, NULL,
        NULL, NULL, LastWriteTime);
    return RegistryClosePath(key, status);
}

LSTATUS RegistryEnumSubKey(LPCWSTR Path, DWORD Index, LPWSTR Name, LPDWORD NameChars,
    LPCWSTR ComputerName, REGSAM View)
{
    HKEY key = NULL;
    LSTATUS status = ERROR_SUCCESS;

    if (Name == NULL || NameChars == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    status = RegistryOpenPath(Path, ComputerName, KEY_ENUMERATE_SUB_KEYS, View, FALSE, &key);
    if (status != ERROR_SUCCESS) {
        return status;
    }
    status = RegEnumKeyExW(key, Index, Name, NameChars, NULL, NULL, NULL, NULL);
    return RegistryClosePath(key, status);
}

LSTATUS RegistryEnumValue(LPCWSTR Path, DWORD Index, LPWSTR Name, LPDWORD NameChars, LPDWORD Type,
    LPBYTE Data, LPDWORD DataSize, LPCWSTR ComputerName, REGSAM View)
{
    HKEY key = NULL;
    LSTATUS status = ERROR_SUCCESS;

    if (Name == NULL || NameChars == NULL || (Data != NULL && DataSize == NULL)) {
        return ERROR_INVALID_PARAMETER;
    }
    status = RegistryOpenPath(Path, ComputerName, KEY_QUERY_VALUE, View, FALSE, &key);
    if (status != ERROR_SUCCESS) {
        return status;
    }
    status = RegEnumValueW(key, Index, Name, NameChars, NULL, Type, Data, DataSize);
    return RegistryClosePath(key, status);
}

DWORD RegistryLastWriteTime(LPCWSTR Path, PFILETIME LastWriteTime, LPCWSTR ComputerName,
    REGSAM View)
{
    if (LastWriteTime == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    if (ComputerName == NULL || ComputerName[0] == L'\0') {
        return RegistryLastWriteTimeNative(Path, LastWriteTime, View);
    }
    return RegistryQueryKey(Path, NULL, NULL, LastWriteTime, ComputerName, View);
}

DWORD RegistryLastWriteTimeNative(LPCWSTR Path, PFILETIME LastWriteTime, REGSAM View)
{
    HKEY key = NULL;
    DWORD status = ERROR_SUCCESS;
    LSTATUS close_status = ERROR_SUCCESS;
    HMODULE module = NULL;
    FARPROC query_proc = NULL;
    FARPROC convert_proc = NULL;
    PFN_NT_QUERY_KEY query = NULL;
    PFN_RTL_NT_STATUS_TO_DOS_ERROR convert = NULL;
    REGISTRY_CACHED_KEY_INFORMATION info = {};
    ULONG returned = 0;
    LONG nt_status = 0;
    ULONGLONG ticks = 0;

    if (LastWriteTime == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    status = RegistryOpenPath(Path, NULL, KEY_QUERY_VALUE, View, FALSE, &key);
    if (status != ERROR_SUCCESS) {
        return status;
    }

    module = GetModuleHandleW(L"ntdll.dll");
    if (module == NULL) {
        status = GetLastError();
        RegCloseKey(key);
        return status;
    }
    query_proc = GetProcAddress(module, "NtQueryKey");
    if (query_proc == NULL) {
        status = GetLastError();
        RegCloseKey(key);
        return status;
    }
    convert_proc = GetProcAddress(module, "RtlNtStatusToDosError");
    if (convert_proc == NULL) {
        status = GetLastError();
        RegCloseKey(key);
        return status;
    }

    static_assert(sizeof(FARPROC) == sizeof(PFN_NT_QUERY_KEY), "function pointer size mismatch");
    static_assert(sizeof(FARPROC) == sizeof(PFN_RTL_NT_STATUS_TO_DOS_ERROR),
        "function pointer size mismatch");
    memcpy(&query, &query_proc, sizeof(query));
    memcpy(&convert, &convert_proc, sizeof(convert));

    nt_status = query(key, 4, &info, sizeof(info), &returned);
    if (nt_status < 0) {
        status = convert(nt_status);
    }
    else if (returned < sizeof(info)) {
        status = ERROR_INVALID_DATA;
    }
    else {
        ticks = static_cast<ULONGLONG>(info.LastWriteTime.QuadPart);
        LastWriteTime->dwLowDateTime = static_cast<DWORD>(ticks);
        LastWriteTime->dwHighDateTime = static_cast<DWORD>(ticks >> 32);
    }
    close_status = RegCloseKey(key);
    return status == ERROR_SUCCESS ? static_cast<DWORD>(close_status) : status;
}

LSTATUS RegistryKeyExists(LPCWSTR Path, PBOOL Exists, LPCWSTR ComputerName, REGSAM View)
{
    HKEY key = NULL;
    LSTATUS status = ERROR_SUCCESS;

    if (Exists == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    *Exists = FALSE;
    status = RegistryOpenPath(Path, ComputerName, KEY_READ, View, FALSE, &key);
    if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND) {
        return ERROR_SUCCESS;
    }
    if (status != ERROR_SUCCESS) {
        return status;
    }
    status = RegistryClosePath(key, ERROR_SUCCESS);
    if (status == ERROR_SUCCESS) {
        *Exists = TRUE;
    }
    return status;
}

LSTATUS RegistryWriteValue(LPCWSTR Path, LPCWSTR ValueName, DWORD Type, const BYTE* Data,
    DWORD DataSize, BOOL CreateKey, LPCWSTR ComputerName, REGSAM View)
{
    HKEY key = NULL;
    LSTATUS status = ERROR_SUCCESS;

    if (Data == NULL && DataSize != 0) {
        return ERROR_INVALID_PARAMETER;
    }
    status = RegistryOpenPath(Path, ComputerName, KEY_SET_VALUE, View, CreateKey, &key);
    if (status != ERROR_SUCCESS) {
        return status;
    }
    status = RegSetValueExW(key, ValueName, 0, Type, Data, DataSize);
    return RegistryClosePath(key, status);
}

LSTATUS RegistryWriteDword(LPCWSTR Path, LPCWSTR ValueName, DWORD Value, BOOL CreateKey,
    LPCWSTR ComputerName, REGSAM View)
{
    return RegistryWriteValue(Path, ValueName, REG_DWORD, reinterpret_cast<const BYTE*>(&Value),
        sizeof(Value), CreateKey, ComputerName, View);
}

LSTATUS RegistryDeleteValue(LPCWSTR Path, LPCWSTR ValueName, LPCWSTR ComputerName, REGSAM View)
{
    HKEY key = NULL;
    LSTATUS status = ERROR_SUCCESS;

    status = RegistryOpenPath(Path, ComputerName, KEY_SET_VALUE, View, FALSE, &key);
    if (status != ERROR_SUCCESS) {
        return status;
    }
    status = RegDeleteValueW(key, ValueName);
    return RegistryClosePath(key, status);
}