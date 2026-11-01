#include "Persistence.h"
#include "NetshHelpers.h"
#include "TimeProviders.h"
//#include "BitsJobs.h"
//#include "CorProfiler.h"
//#include "PrintProcessors.h"
//#include "PowerShellProfiles.h"
//#include "Shortcuts.h"
//#include "FileAssociations.h"

#include <cstdio>
#include <cwchar>

typedef DWORD(*PERSISTENCE_COLLECTOR)(LPCWSTR OutputDirectory);

typedef struct _PERSISTENCE_CHECK
{
    LPCWSTR Name;
    PERSISTENCE_COLLECTOR Collect;
} PERSISTENCE_CHECK, * PPERSISTENCE_CHECK;

DWORD CollectAllPersistence(LPCWSTR OutputDirectory)
{
    /*PERSISTENCE_CHECK checks[] = {
        {L"BITS jobs", CollectBitsJobs},
        {L"COR profiler", CollectCorProfiler},
        {L"Netsh helpers", CollectNetshHelpers},
        {L"Time providers", CollectTimeProviders},
        {L"Print processors", CollectPrintProcessors},
        {L"PowerShell profiles", CollectPowerShellProfiles},
        {L"Shortcuts", CollectShortcuts},
        {L"File associations", CollectFileAssociations}
    };*/

    PERSISTENCE_CHECK checks[] = {
        {L"Netsh helpers", CollectNetshHelpers},
        {L"Time providers", CollectTimeProviders}
    };
    DWORD first_error = ERROR_SUCCESS;
    DWORD status = ERROR_SUCCESS;
    DWORD index = 0;

    if (OutputDirectory == NULL || OutputDirectory[0] == L'\0') {
        return ERROR_INVALID_PARAMETER;
    }
    for (index = 0; index < sizeof(checks) / sizeof(checks[0]); ++index) {
        status = checks[index].Collect(OutputDirectory);
        if (status != ERROR_SUCCESS) {
            std::fwprintf(stderr, L"%ls failed (error 0x%08lX).\n", checks[index].Name, status);
            if (first_error == ERROR_SUCCESS) {
                first_error = status;
            }
        }
    }
    return first_error;
}
