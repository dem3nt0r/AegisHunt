/*
* The project is under development
*/


#include "ParamParse.h"
#include "dsrm.h"
#include "Persistence.h"
#include "SidHistory.h"

#include <cstdio>
#include <cwchar>

static void PrintUsage()
{
    std::wprintf(L"Usage: AegisHunt.exe --check-dsrm [--computer DC01]\n");
    std::wprintf(L"       AegisHunt.exe --hunt-persistence --output-dir C:\\Reports\n");
    std::wprintf(L"       AegisHunt.exe --check-sid-history --output-dir C:\\Reports [--ldap-server DC01]\n");
    std::wprintf(L"       AegisHunt.exe --help\n");
}

int wmain(int argc, wchar_t* argv[])
{
    OPTIONS options = {};
    DSRM_CHECK_RESULT result = {};
    SID_HISTORY_RESULT sid_history = {};
    SYSTEMTIME utc = {};
    DWORD status = ERROR_SUCCESS;
    DWORD last_error = ERROR_SUCCESS;

    status = ParseParameters(argc, argv, &options);
    if (status != ERROR_SUCCESS) {
        std::fwprintf(stderr, L"Invalid arguments (error %lu).\n", status);
        PrintUsage();
        return 2;
    }
    if (options.ShowHelp) {
        PrintUsage();
        return 0;
    }

    if (options.HuntPersistence) {
        status = CollectAllPersistence(options.OutputDirectory);
        if (status != ERROR_SUCCESS) {
            std::fwprintf(stderr, L"Persistence collection failed (error 0x%08lX).\n", status);
            return 1;
        }
    }
    if (options.CheckSidHistory) {
        status = CheckSidHistory(options.LdapServer, options.OutputDirectory, &sid_history);
        if (status != ERROR_SUCCESS) {
            std::fwprintf(stderr, L"SID History check failed (error 0x%08lX).\n", status);
            return 1;
        }
        std::wprintf(L"SID History: %lu users, %lu historical SIDs. See SID_History.csv.\n",
            sid_history.UserCount, sid_history.SidCount);
    }
    if (!options.CheckDsrm) {
        return 0;
    }

    status = CheckDsrmPersistence(options.ComputerName, &result);
    if (status != ERROR_SUCCESS) {
        std::fwprintf(stderr, L"DSRM check failed (error %lu).\n", status);
        return 1;
    }

    if (!result.ValuePresent) {
        std::wprintf(L"DsrmAdminLogonBehavior: absent (default)\n");
    }
    else {
        std::wprintf(L"DsrmAdminLogonBehavior: %lu\n", result.LogonBehavior);
    }

    if (result.AllowsLogonWithAdDsRunning) {
        std::wprintf(L"Finding: DSRM logon is allowed while AD DS runs.\n");
    }
    else if (result.RequiresAdDsStopped) {
        std::wprintf(L"DSRM logon requires AD DS to be stopped.\n");
    }
    else if (result.UnexpectedValue) {
        std::wprintf(L"Finding: unexpected DSRM logon behavior value.\n");
    }

    if (!FileTimeToSystemTime(&result.LsaKeyLastWriteTime, &utc)) {
        last_error = GetLastError();
        std::fwprintf(stderr, L"Could not convert LSA key timestamp (error %lu).\n",
            last_error);
        return 1;
    }
    std::wprintf(L"LSA key last write (UTC): %04u-%02u-%02u %02u:%02u:%02u\n",
        static_cast<unsigned int>(utc.wYear), static_cast<unsigned int>(utc.wMonth),
        static_cast<unsigned int>(utc.wDay), static_cast<unsigned int>(utc.wHour),
        static_cast<unsigned int>(utc.wMinute), static_cast<unsigned int>(utc.wSecond));

    return 0;
}
