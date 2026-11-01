#ifndef HUNTINGTOOLS_FILE_H
#define HUNTINGTOOLS_FILE_H

#include <Windows.h>

typedef struct _FILE_INFORMATION
{
    FILETIME CreationTime;
    FILETIME AccessTime;
    FILETIME WriteTime;
    WCHAR Owner[256];
    WCHAR Signature[256];
    WCHAR Md5[33];
    DWORD OwnerStatus;
    LONG SignatureStatus;
    DWORD HashStatus;
} FILE_INFORMATION, * PFILE_INFORMATION;

typedef DWORD(*FILE_WALK_CALLBACK)(
    _In_ LPCWSTR Path,
    _In_ const WIN32_FIND_DATAW* Entry,
    _In_opt_ PVOID Context
    );

DWORD FileInspect(_In_ LPCWSTR Path, _Out_ PFILE_INFORMATION Result);
DWORD FileFormatTime(_In_ const FILETIME* Time,
    _Out_writes_(BufferChars) LPWSTR Buffer,
    _In_ DWORD BufferChars);
DWORD FileJoinPath(_In_ LPCWSTR Directory, _In_ LPCWSTR Child,
    _Out_ LPWSTR* Joined);
DWORD FileResolvePath(_In_ LPCWSTR RawPath, _In_opt_ LPCWSTR BaseDirectory,
    _Out_ LPWSTR* Resolved);
DWORD FileGetProfilesRoot(_Out_ LPWSTR* Directory);
DWORD FileWalkDirectory(_In_ LPCWSTR Directory, _In_ BOOL Recursive,
    _In_ FILE_WALK_CALLBACK Callback, _In_opt_ PVOID Context);
void FileFree(_In_opt_ PVOID Memory);

#endif // HUNTINGTOOLS_FILE_H
