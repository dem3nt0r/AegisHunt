#ifndef HUNTINGTOOLS_SID_HISTORY_H
#define HUNTINGTOOLS_SID_HISTORY_H

#include <Windows.h>

typedef struct _SID_HISTORY_RESULT
{
    DWORD UserCount;
    DWORD SidCount;
} SID_HISTORY_RESULT, * PSID_HISTORY_RESULT;

DWORD
CheckSidHistory(
    _In_opt_ LPCWSTR LdapServer,
    _In_ LPCWSTR OutputDirectory,
    _Out_ PSID_HISTORY_RESULT Result
);

#endif // HUNTINGTOOLS_SID_HISTORY_H
