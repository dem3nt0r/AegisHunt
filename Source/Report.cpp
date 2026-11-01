#include "Report.h"
#include "file.h"
#include "registry.h"

#include <cwchar>
#include <cstring>

static DWORD ReportWriteBytes(HANDLE File, const BYTE* Data, DWORD Length)
{
    DWORD written = 0;
    DWORD remaining = Length;
    const BYTE* cursor = Data;

    while (remaining != 0) {
        written = 0;
        if (!WriteFile(File, cursor, remaining, &written, NULL)) {
            return GetLastError();
        }
        if (written == 0) {
            return ERROR_WRITE_FAULT;
        }
        remaining -= written;
        cursor += written;
    }
    return ERROR_SUCCESS;
}

DWORD ReportWriteRow(HANDLE File, LPCWSTR const* Fields, DWORD ColumnCount)
{
    SIZE_T capacity = 3;
    SIZE_T position = 0;
    SIZE_T index = 0;
    SIZE_T character = 0;
    SIZE_T length = 0;
    LPWSTR row = NULL;
    LPSTR utf8 = NULL;
    INT bytes = 0;
    DWORD status = ERROR_SUCCESS;
    LPCWSTR field = NULL;

    if (File == NULL || File == INVALID_HANDLE_VALUE || Fields == NULL || ColumnCount == 0) {
        return ERROR_INVALID_PARAMETER;
    }

    for (index = 0; index < ColumnCount; ++index) {
        field = Fields[index] == NULL ? L"" : Fields[index];
        length = wcslen(field);
        if (length > (static_cast<SIZE_T>(INT_MAX) - capacity) / 2) {
            return ERROR_ARITHMETIC_OVERFLOW;
        }
        capacity += length * 2 + 3;
    }
    if (capacity > INT_MAX) {
        return ERROR_ARITHMETIC_OVERFLOW;
    }

    row = static_cast<LPWSTR>(HeapAlloc(GetProcessHeap(), 0, capacity * sizeof(WCHAR)));
    if (row == NULL) {
        return ERROR_OUTOFMEMORY;
    }
    for (index = 0; index < ColumnCount; ++index) {
        field = Fields[index] == NULL ? L"" : Fields[index];
        row[position++] = L'"';
        for (character = 0; field[character] != L'\0'; ++character) {
            if (field[character] == L'"') {
                row[position++] = L'"';
            }
            row[position++] = field[character];
        }
        row[position++] = L'"';
        if (index + 1 != ColumnCount) {
            row[position++] = L',';
        }
    }
    row[position++] = L'\r';
    row[position++] = L'\n';

    bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, row,
        static_cast<INT>(position), NULL, 0, NULL, NULL);
    if (bytes == 0) {
        status = GetLastError();
        HeapFree(GetProcessHeap(), 0, row);
        return status;
    }
    utf8 = static_cast<LPSTR>(HeapAlloc(GetProcessHeap(), 0, bytes));
    if (utf8 == NULL) {
        HeapFree(GetProcessHeap(), 0, row);
        return ERROR_OUTOFMEMORY;
    }
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, row,
        static_cast<INT>(position), utf8, bytes, NULL, NULL) == 0) {
        status = GetLastError();
    }
    else {
        status = ReportWriteBytes(File, reinterpret_cast<const BYTE*>(utf8),
            static_cast<DWORD>(bytes));
    }
    HeapFree(GetProcessHeap(), 0, utf8);
    HeapFree(GetProcessHeap(), 0, row);
    return status;
}

DWORD ReportOpen(LPCWSTR Directory, LPCWSTR FileName, LPCWSTR const* Columns,
    DWORD ColumnCount, PHANDLE File)
{
    SIZE_T directory_length = 0;
    SIZE_T file_length = 0;
    LPWSTR path = NULL;
    DWORD status = ERROR_SUCCESS;
    DWORD attributes = INVALID_FILE_ATTRIBUTES;
    const BYTE bom[3] = { 0xEF, 0xBB, 0xBF };

    if (Directory == NULL || Directory[0] == L'\0' || FileName == NULL ||
        FileName[0] == L'\0' || File == NULL || Columns == NULL || ColumnCount == 0) {
        return ERROR_INVALID_PARAMETER;
    }
    *File = INVALID_HANDLE_VALUE;
    if (!CreateDirectoryW(Directory, NULL)) {
        status = GetLastError();
        if (status != ERROR_ALREADY_EXISTS) {
            return status;
        }
        attributes = GetFileAttributesW(Directory);
        if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
            return ERROR_DIRECTORY;
        }
    }

    directory_length = wcslen(Directory);
    file_length = wcslen(FileName);
    if (directory_length > SIZE_MAX - file_length - 2) {
        return ERROR_ARITHMETIC_OVERFLOW;
    }
    path = static_cast<LPWSTR>(HeapAlloc(GetProcessHeap(), 0,
        (directory_length + file_length + 2) * sizeof(WCHAR)));
    if (path == NULL) {
        return ERROR_OUTOFMEMORY;
    }
    memcpy(path, Directory, directory_length * sizeof(WCHAR));
    path[directory_length] = L'\\';
    memcpy(path + directory_length + 1, FileName, (file_length + 1) * sizeof(WCHAR));
    *File = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, NULL);
    status = *File == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    HeapFree(GetProcessHeap(), 0, path);
    if (status != ERROR_SUCCESS) {
        return status;
    }

    status = ReportWriteBytes(*File, bom, sizeof(bom));
    if (status == ERROR_SUCCESS) {
        status = ReportWriteRow(*File, Columns, ColumnCount);
    }
    if (status != ERROR_SUCCESS) {
        CloseHandle(*File);
        *File = INVALID_HANDLE_VALUE;
    }
    return status;
}

DWORD ReportClose(HANDLE File)
{
    if (File == NULL || File == INVALID_HANDLE_VALUE) {
        return ERROR_INVALID_HANDLE;
    }
    return CloseHandle(File) ? ERROR_SUCCESS : GetLastError();
}

static LPCWSTR const REPORT_COLUMNS[] = {
    L"Technique", L"RegistryKey", L"Name", L"Value", L"TargetPath", L"Arguments",
    L"KeyLastWriteUtc", L"KeyOwner", L"FileCreatedUtc", L"FileAccessedUtc",
    L"FileModifiedUtc", L"FileOwner", L"Signature", L"MD5", L"FileStatus", L"Details"
};

DWORD ReportOpenPersistence(LPCWSTR OutputDirectory, LPCWSTR FileName, PHANDLE Report)
{
    return ReportOpen(OutputDirectory, FileName, REPORT_COLUMNS,
        sizeof(REPORT_COLUMNS) / sizeof(REPORT_COLUMNS[0]), Report);
}

DWORD ReportWritePersistenceRecord(HANDLE Report, LPCWSTR Technique, LPCWSTR RegistryKey,
    LPCWSTR Name, LPCWSTR Value, LPCWSTR TargetPath,
    LPCWSTR Arguments, LPCWSTR Details)
{
    FILE_INFORMATION file = {};
    FILETIME key_time = {};
    WCHAR key_time_text[32] = {};
    WCHAR created[32] = {};
    WCHAR accessed[32] = {};
    WCHAR modified[32] = {};
    WCHAR key_owner[256] = {};
    WCHAR file_status_text[24] = {};
    LPCWSTR fields[16] = {};
    DWORD file_status = ERROR_SUCCESS;
    DWORD key_status = ERROR_SUCCESS;

    if (Technique == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    if (RegistryKey != NULL && RegistryKey[0] != L'\0') {
        key_status = RegistryLastWriteTime(RegistryKey, &key_time);
        if (key_status == ERROR_SUCCESS) {
            FileFormatTime(&key_time, key_time_text, 32);
        }
        RegistryGetKeyOwner(RegistryKey, key_owner, 256);
    }
    if (TargetPath != NULL && TargetPath[0] != L'\0') {
        file_status = FileInspect(TargetPath, &file);
        if (file_status == ERROR_SUCCESS) {
            FileFormatTime(&file.CreationTime, created, 32);
            FileFormatTime(&file.AccessTime, accessed, 32);
            FileFormatTime(&file.WriteTime, modified, 32);
        }
        else {
            swprintf(file_status_text, 24, L"%lu", file_status);
        }
    }

    fields[0] = Technique;
    fields[1] = RegistryKey;
    fields[2] = Name;
    fields[3] = Value;
    fields[4] = TargetPath;
    fields[5] = Arguments;
    fields[6] = key_time_text;
    fields[7] = key_owner;
    fields[8] = created;
    fields[9] = accessed;
    fields[10] = modified;
    fields[11] = file.Owner;
    fields[12] = file.Signature;
    fields[13] = file.Md5;
    fields[14] = file_status_text;
    fields[15] = Details;
    return ReportWriteRow(Report, fields, 16);
}

