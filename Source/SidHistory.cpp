#include "SidHistory.h"

#include "ldap.h"
#include "Report.h"

#include <sddl.h>

typedef struct _SID_HISTORY_CONTEXT
{
    HANDLE Report;
    PSID_HISTORY_RESULT Result;
} SID_HISTORY_CONTEXT, * PSID_HISTORY_CONTEXT;

static DWORD SidHistoryFormatSid(const berval* Value, LPWSTR* StringSid)
{
    const BYTE* bytes = NULL;
    DWORD required = 0;

    if (Value == NULL || StringSid == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    *StringSid = NULL;
    if (Value->bv_val == NULL || Value->bv_len < 8) {
        return ERROR_INVALID_SID;
    }
    bytes = reinterpret_cast<const BYTE*>(Value->bv_val);
    if (bytes[1] > 15) {
        return ERROR_INVALID_SID;
    }
    required = 8 + static_cast<DWORD>(bytes[1]) * sizeof(DWORD);
    if (Value->bv_len < required || !IsValidSid(Value->bv_val)) {
        return ERROR_INVALID_SID;
    }
    if (!ConvertSidToStringSidW(Value->bv_val, StringSid)) {
        return GetLastError();
    }
    return ERROR_SUCCESS;
}

static DWORD SidHistoryWriteEntry(LDAP* Connection, LDAPMessage* Entry, PVOID Context)
{
    PSID_HISTORY_CONTEXT context = static_cast<PSID_HISTORY_CONTEXT>(Context);
    LPWSTR dn = NULL;
    PWCHAR* names = NULL;
    berval** current_sids = NULL;
    berval** history_sids = NULL;
    LPWSTR current_sid = NULL;
    LPWSTR history_sid = NULL;
    LPCWSTR fields[4] = {};
    DWORD status = ERROR_SUCCESS;
    DWORD index = 0;
    BOOL found_user = FALSE;

    if (Connection == NULL || Entry == NULL || context == NULL ||
        context->Result == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    status = LdapGetEntryDn(Connection, Entry, &dn);
    if (status == ERROR_SUCCESS) {
        status = LdapGetStringValues(Connection, Entry, L"sAMAccountName", &names);
        if (status == LDAP_NO_SUCH_ATTRIBUTE) {
            status = ERROR_SUCCESS;
        }
    }
    if (status == ERROR_SUCCESS) {
        status = LdapGetBinaryValues(Connection, Entry, L"objectSid", &current_sids);
    }
    if (status == ERROR_SUCCESS) {
        status = LdapGetBinaryValues(Connection, Entry, L"sIDHistory", &history_sids);
    }
    if (status == ERROR_SUCCESS) {
        status = SidHistoryFormatSid(current_sids[0], &current_sid);
    }
    if (status == ERROR_SUCCESS) {
        for (index = 0; history_sids[index] != NULL; ++index) {
            history_sid = NULL;
            status = SidHistoryFormatSid(history_sids[index], &history_sid);
            if (status != ERROR_SUCCESS) {
                break;
            }
            fields[0] = dn;
            fields[1] = names != NULL ? names[0] : L"";
            fields[2] = current_sid;
            fields[3] = history_sid;
            status = ReportWriteRow(context->Report, fields, 4);
            LocalFree(history_sid);
            history_sid = NULL;
            if (status != ERROR_SUCCESS) {
                break;
            }
            found_user = TRUE;
            ++context->Result->SidCount;
        }
    }
    if (found_user) {
        ++context->Result->UserCount;
    }
    if (history_sid != NULL) {
        LocalFree(history_sid);
    }
    if (current_sid != NULL) {
        LocalFree(current_sid);
    }
    LdapFreeBinaryValues(history_sids);
    LdapFreeBinaryValues(current_sids);
    LdapFreeStringValues(names);
    LdapFreeString(dn);
    return status;
}

DWORD CheckSidHistory(LPCWSTR LdapServer, LPCWSTR OutputDirectory,
    PSID_HISTORY_RESULT Result)
{
    LPCWSTR columns[4] = { L"DistinguishedName", L"SamAccountName",
                           L"ObjectSid", L"SidHistory" };
    LPCWSTR attributes[3] = { L"sAMAccountName", L"objectSid", L"sIDHistory" };
    LDAP* connection = NULL;
    LPWSTR base_dn = NULL;
    HANDLE report = INVALID_HANDLE_VALUE;
    SID_HISTORY_CONTEXT context = {};
    DWORD status = ERROR_SUCCESS;
    DWORD close_status = ERROR_SUCCESS;

    if (OutputDirectory == NULL || OutputDirectory[0] == L'\0' || Result == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    *Result = {};

    status = LdapOpenConnection(LdapServer, &connection);
    if (status == ERROR_SUCCESS) {
        status = LdapGetDefaultNamingContext(connection, &base_dn);
    }

    if (status == ERROR_SUCCESS) {
        status = ReportOpen(OutputDirectory, L"SID_History.csv", columns, 4, &report);
    }

    if (status == ERROR_SUCCESS) {
        context.Report = report;
        context.Result = Result;
        status = LdapSearchPaged(
            connection, base_dn, LDAP_SCOPE_SUBTREE,
            L"(&(objectCategory=person)(objectClass=user)(sIDHistory=*))",
            attributes, 3, 1000, SidHistoryWriteEntry, &context);
    }
    if (report != INVALID_HANDLE_VALUE) {
        close_status = ReportClose(report);
        if (status == ERROR_SUCCESS && close_status != ERROR_SUCCESS) {
            status = close_status;
        }
    }
    LdapFreeString(base_dn);
    if (connection != NULL) {
        close_status = LdapCloseConnection(connection);
        if (status == ERROR_SUCCESS && close_status != ERROR_SUCCESS) {
            status = close_status;
        }
    }
    return status;
}
