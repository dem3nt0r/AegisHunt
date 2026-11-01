#ifndef HUNTINGTOOLS_PARAM_PARSE_H
#define HUNTINGTOOLS_PARAM_PARSE_H

#include <Windows.h>

typedef struct _POPTIONS
{
    BOOL CheckDsrm;
    BOOL CheckSidHistory;
    BOOL HuntPersistence;
    BOOL ShowHelp;
    LPCWSTR ComputerName;
    LPCWSTR LdapServer;
    LPCWSTR OutputDirectory;
} OPTIONS, * POPTIONS;

DWORD
ParseParameters(
    _In_ int ArgumentCount,
    _In_reads_(ArgumentCount) wchar_t* ArgumentValues[],
    _Out_ POPTIONS Options
);

#endif // HUNTINGTOOLS_PARAM_PARSE_H
