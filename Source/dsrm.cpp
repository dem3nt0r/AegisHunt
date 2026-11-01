#include "dsrm.h"

DWORD CheckDsrmPersistence(LPCWSTR ComputerName, PDSRM_CHECK_RESULT Result, REGSAM View)
{
    LPCWSTR path = L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa";
    DWORD status = ERROR_SUCCESS;
    DWORD behavior = 0;

    if (Result == NULL) {
        return ERROR_INVALID_PARAMETER;
    }

    *Result = {};
    status = RegistryLastWriteTime(path, &Result->LsaKeyLastWriteTime, ComputerName, View);
    if (status != ERROR_SUCCESS) {
        return status;
    }

    status = RegistryReadDword(path, L"DsrmAdminLogonBehavior", &behavior, ComputerName, View);
    if (status == ERROR_FILE_NOT_FOUND) {
        return ERROR_SUCCESS;
    }
    if (status != ERROR_SUCCESS) {
        return status;
    }

    Result->ValuePresent = TRUE;
    Result->LogonBehavior = behavior;
    Result->AllowsLogonWithAdDsRunning = behavior == 2 ? TRUE : FALSE;
    Result->RequiresAdDsStopped = behavior == 1 ? TRUE : FALSE;
    Result->UnexpectedValue = behavior > 2 ? TRUE : FALSE;
    return ERROR_SUCCESS;
}
