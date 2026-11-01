#ifndef HUNTINGTOOLS_DSRM_H
#define HUNTINGTOOLS_DSRM_H

#include "registry.h"

typedef struct _DSRM_CHECK_RESULT
{
    BOOL ValuePresent;
    DWORD LogonBehavior;
    BOOL AllowsLogonWithAdDsRunning;
    BOOL RequiresAdDsStopped;
    BOOL UnexpectedValue;
    FILETIME LsaKeyLastWriteTime;
} DSRM_CHECK_RESULT, * PDSRM_CHECK_RESULT;

// Checks only the DSRM logon policy registry value. It does not verify the
// DSRM password, account use, or past registry changes.
DWORD
CheckDsrmPersistence(
    _In_opt_ LPCWSTR ComputerName,
    _Out_ PDSRM_CHECK_RESULT Result,
    _In_ REGSAM View = 0
);

#endif // HUNTINGTOOLS_DSRM_H
