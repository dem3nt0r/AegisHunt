#include "ldap.h"

#include <cwchar>
#include <cstring>

#pragma comment(lib, "Wldap32.lib")

static DWORD LdapLastErrorCode()
{
    DWORD status = LDAP_SUCCESS;

    status = LdapGetLastError();
    if (status == LDAP_SUCCESS) {
        return LDAP_LOCAL_ERROR;
    }

    return status;
}

static DWORD LdapCopyString(LPCWSTR Source, LPWSTR* Copy)
{
    SIZE_T length = 0;
    LPWSTR buffer = NULL;

    if (Source == NULL || Copy == NULL) {
        return ERROR_INVALID_PARAMETER;
    }

    *Copy = NULL;
    length = wcslen(Source);
    if (length > (SIZE_MAX / sizeof(WCHAR)) - 1) {
        return ERROR_ARITHMETIC_OVERFLOW;
    }

    buffer = static_cast<LPWSTR>(HeapAlloc(GetProcessHeap(), 0, (length + 1) * sizeof(WCHAR)));
    if (buffer == NULL) {
        return ERROR_OUTOFMEMORY;
    }
    memcpy(buffer, Source, (length + 1) * sizeof(WCHAR));
    *Copy = buffer;
    return ERROR_SUCCESS;
}

void LdapFreeString(LPWSTR Value)
{
    if (Value != NULL) {
        HeapFree(GetProcessHeap(), 0, Value);
    }
}

void LdapFreeStringValues(PWCHAR* Values)
{
    if (Values != NULL) {
        ldap_value_freeW(Values);
    }
}

void LdapFreeBinaryValues(berval** Values)
{
    if (Values != NULL) {
        ldap_value_free_len(Values);
    }
}

DWORD LdapOpenConnection(LPCWSTR Server, LDAP** Connection)
{
    LDAP* connection = NULL;
    ULONG version = LDAP_VERSION3;
    DWORD status = LDAP_SUCCESS;

    if (Connection == NULL) {
        return ERROR_INVALID_PARAMETER;
    }

    *Connection = NULL;

    connection = ldap_initW(const_cast<PWSTR>(Server), LDAP_PORT);
    if (connection == NULL) {
        return LdapLastErrorCode();
    }

    status = ldap_set_optionW(connection, LDAP_OPT_PROTOCOL_VERSION, &version);
    if (status == LDAP_SUCCESS) {
        status = ldap_set_optionW(connection, LDAP_OPT_ENCRYPT, LDAP_OPT_ON);
    }

    if (status == LDAP_SUCCESS) {
        status = ldap_bind_sW(connection, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    }

    if (status != LDAP_SUCCESS) {
        ldap_unbind(connection);
        return status;
    }

    *Connection = connection;
    return LDAP_SUCCESS;
}

DWORD LdapCloseConnection(LDAP* Connection)
{
    if (Connection == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    return ldap_unbind(Connection);
}

DWORD LdapGetStringValues(LDAP* Connection, LDAPMessage* Entry,
    LPCWSTR Attribute, PWCHAR** Values)
{
    if (Connection == NULL || Entry == NULL || Attribute == NULL || Values == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    *Values = ldap_get_valuesW(Connection, Entry, const_cast<PWCHAR>(Attribute));
    if (*Values == NULL || (*Values)[0] == NULL) {
        if (*Values != NULL) {
            ldap_value_freeW(*Values);
            *Values = NULL;
        }
        return LDAP_NO_SUCH_ATTRIBUTE;
    }
    return LDAP_SUCCESS;
}

DWORD LdapGetBinaryValues(LDAP* Connection, LDAPMessage* Entry,
    LPCWSTR Attribute, berval*** Values)
{
    if (Connection == NULL || Entry == NULL || Attribute == NULL || Values == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    *Values = ldap_get_values_lenW(Connection, Entry, const_cast<PWCHAR>(Attribute));
    if (*Values == NULL || (*Values)[0] == NULL) {
        if (*Values != NULL) {
            ldap_value_free_len(*Values);
            *Values = NULL;
        }
        return LDAP_NO_SUCH_ATTRIBUTE;
    }
    return LDAP_SUCCESS;
}

DWORD LdapGetEntryDn(LDAP* Connection, LDAPMessage* Entry, LPWSTR* DistinguishedName)
{
    PWCHAR dn = NULL;
    DWORD status = LDAP_SUCCESS;

    if (Connection == NULL || Entry == NULL || DistinguishedName == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    *DistinguishedName = NULL;
    dn = ldap_get_dnW(Connection, Entry);
    if (dn == NULL) {
        return LdapLastErrorCode();
    }
    status = LdapCopyString(dn, DistinguishedName);
    ldap_memfreeW(dn);
    return status;
}

DWORD LdapGetDefaultNamingContext(LDAP* Connection, LPWSTR* BaseDn)
{
    LDAPMessage* message = NULL;
    LDAPMessage* entry = NULL;
    PWCHAR* values = NULL;
    PWCHAR attributes[2] = { const_cast<PWCHAR>(L"defaultNamingContext"), NULL };
    DWORD status = LDAP_SUCCESS;

    if (Connection == NULL || BaseDn == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    *BaseDn = NULL;
    status = ldap_search_sW(Connection, const_cast<PWCHAR>(L""), LDAP_SCOPE_BASE,
        const_cast<PWCHAR>(L"(objectClass=*)"), attributes, 0,
        &message);
    if (status != LDAP_SUCCESS) {
        return status;
    }
    if (message == NULL) {
        return LDAP_NO_SUCH_OBJECT;
    }
    entry = ldap_first_entry(Connection, message);
    if (entry == NULL) {
        status = LDAP_NO_SUCH_OBJECT;
    }
    else {
        status = LdapGetStringValues(Connection, entry, L"defaultNamingContext", &values);
        if (status == LDAP_SUCCESS) {
            if (values[0][0] == L'\0') {
                status = LDAP_NO_SUCH_ATTRIBUTE;
            }
            else {
                status = LdapCopyString(values[0], BaseDn);
            }
        }
    }
    LdapFreeStringValues(values);
    ldap_msgfree(message);
    return status;
}

DWORD LdapSearchPaged(LDAP* Connection, LPCWSTR BaseDn, ULONG Scope, LPCWSTR Filter,
    LPCWSTR const* Attributes, DWORD AttributeCount,
    ULONG PageSize, LDAP_ENTRY_CALLBACK Callback, PVOID Context)
{
    PWCHAR* attributes = NULL;
    LDAPSearch* search = NULL;
    LDAPMessage* page = NULL;
    LDAPMessage* entry = NULL;
    ULONG returned_count = 0;
    DWORD status = LDAP_SUCCESS;
    DWORD page_status = LDAP_SUCCESS;
    DWORD abandon_status = LDAP_SUCCESS;
    DWORD index = 0;
    BOOL finished = FALSE;

    if (Connection == NULL || BaseDn == NULL || Filter == NULL ||
        Attributes == NULL || AttributeCount == 0 || PageSize == 0 ||
        Callback == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    if (Scope != LDAP_SCOPE_BASE && Scope != LDAP_SCOPE_ONELEVEL &&
        Scope != LDAP_SCOPE_SUBTREE) {
        return ERROR_INVALID_PARAMETER;
    }
    if (AttributeCount > (SIZE_MAX / sizeof(PWCHAR)) - 1) {
        return ERROR_ARITHMETIC_OVERFLOW;
    }
    attributes = static_cast<PWCHAR*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
        (static_cast<SIZE_T>(AttributeCount) + 1) *
        sizeof(PWCHAR)));
    if (attributes == NULL) {
        return ERROR_OUTOFMEMORY;
    }
    for (index = 0; index < AttributeCount; ++index) {
        if (Attributes[index] == NULL) {
            HeapFree(GetProcessHeap(), 0, attributes);
            return ERROR_INVALID_PARAMETER;
        }
        attributes[index] = const_cast<PWCHAR>(Attributes[index]);
    }
    search = ldap_search_init_pageW(Connection, const_cast<PWCHAR>(BaseDn),
        Scope, const_cast<PWCHAR>(Filter),
        attributes, 0, NULL, NULL, 0, 0, NULL);
    if (search == NULL) {
        status = LdapLastErrorCode();
        HeapFree(GetProcessHeap(), 0, attributes);
        return status;
    }
    for (;;) {
        page = NULL;
        returned_count = 0;
        page_status = ldap_get_next_page_s(Connection, search, NULL, PageSize,
            &returned_count, &page);
        finished = page_status == LDAP_NO_RESULTS_RETURNED;
        if (page_status != LDAP_SUCCESS && !finished) {
            status = page_status;
            if (page != NULL) {
                ldap_msgfree(page);
            }
            break;
        }
        if (page != NULL) {
            for (entry = ldap_first_entry(Connection, page);
                entry != NULL;
                entry = ldap_next_entry(Connection, entry)) {
                status = Callback(Connection, entry, Context);
                if (status != ERROR_SUCCESS) {
                    break;
                }
            }
            ldap_msgfree(page);
        }
        if (status != LDAP_SUCCESS) {
            break;
        }
        if (finished) {
            break;
        }
    }
    abandon_status = ldap_search_abandon_page(Connection, search);
    if (status == LDAP_SUCCESS && abandon_status != LDAP_SUCCESS) {
        status = abandon_status;
    }
    HeapFree(GetProcessHeap(), 0, attributes);
    return status;
}
