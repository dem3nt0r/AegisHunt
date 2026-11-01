#ifndef HUNTINGTOOLS_REPORT_H
#define HUNTINGTOOLS_REPORT_H

#include <Windows.h>

DWORD
ReportOpen(
    _In_ LPCWSTR Directory,
    _In_ LPCWSTR FileName,
    _In_reads_(ColumnCount) LPCWSTR const* Columns,
    _In_ DWORD ColumnCount,
    _Out_ PHANDLE File
);

DWORD
ReportWriteRow(
    _In_ HANDLE File,
    _In_reads_(ColumnCount) LPCWSTR const* Fields,
    _In_ DWORD ColumnCount
);

DWORD
ReportClose(
    _In_ HANDLE File
);

DWORD
ReportOpenPersistence(
    _In_ LPCWSTR OutputDirectory,
    _In_ LPCWSTR FileName,
    _Out_ PHANDLE Report
);

DWORD
ReportWritePersistenceRecord(
    _In_ HANDLE Report,
    _In_ LPCWSTR Technique,
    _In_opt_ LPCWSTR RegistryKey,
    _In_opt_ LPCWSTR Name,
    _In_opt_ LPCWSTR Value,
    _In_opt_ LPCWSTR TargetPath,
    _In_opt_ LPCWSTR Arguments,
    _In_opt_ LPCWSTR Details
);

#endif // HUNTINGTOOLS_REPORT_H
