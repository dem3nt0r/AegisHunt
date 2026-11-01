#include "ParamParse.h"

#include <cwchar>

DWORD ParseParameters(int ArgumentCount, wchar_t* ArgumentValues[], POPTIONS Options)
{
    int index = 0;
    LPCWSTR argument = NULL;

    if (Options == NULL || ArgumentValues == NULL || ArgumentCount < 1) {
        return ERROR_INVALID_PARAMETER;
    }

    *Options = {};

    for (index = 1; index < ArgumentCount; ++index) {
        argument = ArgumentValues[index];
        if (argument == NULL) {
            return ERROR_INVALID_PARAMETER;
        }

        if (!_wcsicmp(argument, L"--help") || !_wcsicmp(argument, L"-h")) {
            Options->ShowHelp = TRUE;
        }
        else if (!_wcsicmp(argument, L"--check-dsrm")) {
            if (Options->CheckDsrm) {
                return ERROR_INVALID_PARAMETER;
            }

            Options->CheckDsrm = TRUE;
        }
        else if (!_wcsicmp(argument, L"--check-sid-history")) {
            if (Options->CheckSidHistory) {
                return ERROR_INVALID_PARAMETER;
            }
            Options->CheckSidHistory = TRUE;
        }
        else if (!_wcsicmp(argument, L"--ldap-server")) {
            if (Options->LdapServer != NULL || index + 1 >= ArgumentCount) {
                return ERROR_INVALID_PARAMETER;
            }
            ++index;
            if (ArgumentValues[index] == NULL || ArgumentValues[index][0] == L'\0' ||
                ArgumentValues[index][0] == L'-') {
                return ERROR_INVALID_PARAMETER;
            }
            Options->LdapServer = ArgumentValues[index];
        }
        else if (!_wcsicmp(argument, L"--hunt-persistence")) {
            if (Options->HuntPersistence) {
                return ERROR_INVALID_PARAMETER;
            }
            Options->HuntPersistence = TRUE;
        }
        else if (!_wcsicmp(argument, L"--output-dir")) {
            if (Options->OutputDirectory != NULL || index + 1 >= ArgumentCount) {
                return ERROR_INVALID_PARAMETER;
            }
            ++index;
            if (ArgumentValues[index] == NULL || ArgumentValues[index][0] == L'\0') {
                return ERROR_INVALID_PARAMETER;
            }
            Options->OutputDirectory = ArgumentValues[index];
        }
        else if (!_wcsicmp(argument, L"--computer")) {

            if (Options->ComputerName != NULL || index + 1 >= ArgumentCount) {
                return ERROR_INVALID_PARAMETER;
            }

            ++index;
            if (ArgumentValues[index] == NULL || ArgumentValues[index][0] == L'\0' || ArgumentValues[index][0] == L'-') {
                return ERROR_INVALID_PARAMETER;
            }
            Options->ComputerName = ArgumentValues[index];
        }
        else {
            return ERROR_INVALID_PARAMETER;
        }
    }

    if (!Options->ShowHelp && !Options->CheckDsrm &&
        !Options->CheckSidHistory && !Options->HuntPersistence) {
        return ERROR_INVALID_PARAMETER;
    }
    if (!Options->ShowHelp && (Options->HuntPersistence || Options->CheckSidHistory) &&
        Options->OutputDirectory == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    if (!Options->ShowHelp && Options->OutputDirectory != NULL &&
        !Options->HuntPersistence && !Options->CheckSidHistory) {
        return ERROR_INVALID_PARAMETER;
    }
    if (!Options->ShowHelp && Options->ComputerName != NULL && !Options->CheckDsrm) {
        return ERROR_INVALID_PARAMETER;
    }
    if (!Options->ShowHelp && Options->LdapServer != NULL && !Options->CheckSidHistory) {
        return ERROR_INVALID_PARAMETER;
    }

    return ERROR_SUCCESS;
}
