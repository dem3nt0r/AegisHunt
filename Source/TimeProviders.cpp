#include "TimeProviders.h"

#include "file.h"
#include "Report.h"
#include "registry.h"

#include <cstdio>
#include <cwchar>

DWORD CollectTimeProviders(LPCWSTR OutputDirectory)
{
    LPCWSTR base = L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders";
    HANDLE report = INVALID_HANDLE_VALUE;
    DWORD status = ERROR_SUCCESS;
    DWORD index = 0;
    DWORD name_chars = 0;
    DWORD enabled = 0;
    DWORD input = 0;
    DWORD system_length = 0;
    DWORD enabled_status = ERROR_SUCCESS;
    DWORD input_status = ERROR_SUCCESS;
    WCHAR name[512] = {};
    WCHAR details[96] = {};
    WCHAR enabled_text[16] = {};
    WCHAR input_text[16] = {};
    WCHAR system_dir[MAX_PATH] = {};
    LPWSTR key = NULL;
    LPWSTR value = NULL;
    LPWSTR target = NULL;

    status = ReportOpenPersistence(OutputDirectory, L"T1547_003_TimeProviders.csv", &report);
    if (status != ERROR_SUCCESS) {
        return status;
    }
    system_length = GetSystemDirectoryW(system_dir, MAX_PATH);
    if (system_length == 0 || system_length >= MAX_PATH) {
        status = system_length == 0 ? GetLastError() : ERROR_INSUFFICIENT_BUFFER;
        ReportClose(report);
        return status;
    }
    for (index = 0;; ++index) {
        name_chars = 512;
        status = RegistryEnumSubKey(base, index, name, &name_chars);
        if (status == ERROR_NO_MORE_ITEMS || status == ERROR_FILE_NOT_FOUND) {
            status = ERROR_SUCCESS;
            break;
        }
        if (status != ERROR_SUCCESS) {
            break;
        }
        key = NULL;
        value = NULL;
        target = NULL;
        status = FileJoinPath(base, name, &key);
        if (status == ERROR_SUCCESS) {
            status = RegistryReadString(key, L"DllName", &value);
        }
        if (status == ERROR_FILE_NOT_FOUND) {
            status = ERROR_SUCCESS;
        }
        else if (status == ERROR_SUCCESS) {
            enabled = 0;
            input = 0;
            enabled_status = RegistryReadDword(key, L"Enabled", &enabled);
            input_status = RegistryReadDword(key, L"InputProvider", &input);
            if ((enabled_status != ERROR_SUCCESS && enabled_status != ERROR_FILE_NOT_FOUND) ||
                (input_status != ERROR_SUCCESS && input_status != ERROR_FILE_NOT_FOUND)) {
                status = enabled_status != ERROR_SUCCESS && enabled_status != ERROR_FILE_NOT_FOUND ?
                    enabled_status : input_status;
            }
            if (status == ERROR_SUCCESS) {
                if (enabled_status == ERROR_SUCCESS) {
                    swprintf(enabled_text, 16, L"%lu", enabled);
                }
                else {
                    wcscpy_s(enabled_text, 16, L"absent");
                }
                if (input_status == ERROR_SUCCESS) {
                    swprintf(input_text, 16, L"%lu", input);
                }
                else {
                    wcscpy_s(input_text, 16, L"absent");
                }
                swprintf(details, 96, L"Enabled=%ls; InputProvider=%ls",
                    enabled_text, input_text);
            }
            if (status == ERROR_SUCCESS) {
                status = FileResolvePath(value, system_dir, &target);
            }
            if (status == ERROR_SUCCESS) {
                status = ReportWritePersistenceRecord(report, L"T1547.003", key, L"DllName", value,
                    target, NULL, details);
            }
        }
        FileFree(key);
        RegistryFreeString(value);
        FileFree(target);
        if (status != ERROR_SUCCESS) {
            break;
        }
    }
    ReportClose(report);
    return status;
}
