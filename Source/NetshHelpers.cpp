#include "NetshHelpers.h"

#include "file.h"
#include "Report.h"
#include "registry.h"

#include <cstdio>
#include <cwchar>

DWORD CollectNetshHelpers(LPCWSTR OutputDirectory)
{
    LPCWSTR keys[2] = { L"HKLM\\SOFTWARE\\Microsoft\\NetSh",
                       L"HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\NetSh" };
    HANDLE report = INVALID_HANDLE_VALUE;
    DWORD status = ERROR_SUCCESS;
    DWORD key_index = 0;
    DWORD index = 0;
    DWORD name_chars = 0;
    DWORD system_length = 0;
    WCHAR name[16384] = {};
    WCHAR system_dir[MAX_PATH] = {};
    LPWSTR value = NULL;
    LPWSTR target = NULL;

    status = ReportOpenPersistence(OutputDirectory, L"T1546_007_NetshHelperDLL.csv", &report);
    if (status != ERROR_SUCCESS) {
        return status;
    }
    system_length = GetSystemDirectoryW(system_dir, MAX_PATH);
    if (system_length == 0 || system_length >= MAX_PATH) {
        status = system_length == 0 ? GetLastError() : ERROR_INSUFFICIENT_BUFFER;
        ReportClose(report);
        return status;
    }
    for (key_index = 0; key_index < 2; ++key_index) {
        for (index = 0;; ++index) {
            name_chars = 16384;
            status = RegistryEnumValue(keys[key_index], index, name, &name_chars,
                NULL, NULL, NULL, NULL, KEY_WOW64_64KEY);
            if (status == ERROR_FILE_NOT_FOUND || status == ERROR_NO_MORE_ITEMS) {
                status = ERROR_SUCCESS;
                break;
            }
            if (status != ERROR_SUCCESS) {
                ReportClose(report);
                return status;
            }
            value = NULL;
            target = NULL;
            status = RegistryReadString(keys[key_index], name, &value,
                NULL, KEY_WOW64_64KEY);
            if (status == ERROR_INVALID_DATA) {
                continue;
            }
            if (status != ERROR_SUCCESS) {
                ReportClose(report);
                return status;
            }
            status = FileResolvePath(value, system_dir, &target);
            if (status == ERROR_SUCCESS) {
                status = ReportWritePersistenceRecord(report, L"T1546.007", keys[key_index], name,
                    value, target, NULL, NULL);
            }
            RegistryFreeString(value);
            FileFree(target);
            if (status != ERROR_SUCCESS) {
                ReportClose(report);
                return status;
            }
        }
    }
    return ReportClose(report);
}
