#ifndef HUNTINGTOOLS_LDAP_H
#define HUNTINGTOOLS_LDAP_H

#include <Windows.h>
#include <winldap.h>

typedef DWORD(*LDAP_ENTRY_CALLBACK)(
    _In_ LDAP* Connection,
    _In_ LDAPMessage* Entry,
    _In_opt_ PVOID Context
    );

DWORD
LdapOpenConnection(
    _In_opt_ LPCWSTR Server,
    _Out_ LDAP** Connection
);

DWORD
LdapCloseConnection(
    _In_ LDAP* Connection
);

DWORD
LdapGetDefaultNamingContext(
    _In_ LDAP* Connection,
    _Out_ LPWSTR* BaseDn
);

DWORD
LdapSearchPaged(
    _In_ LDAP* Connection,
    _In_ LPCWSTR BaseDn,
    _In_ ULONG Scope,
    _In_ LPCWSTR Filter,
    _In_reads_(AttributeCount) LPCWSTR const* Attributes,
    _In_ DWORD AttributeCount,
    _In_ ULONG PageSize,
    _In_ LDAP_ENTRY_CALLBACK Callback,
    _In_opt_ PVOID Context
);

DWORD
LdapGetEntryDn(
    _In_ LDAP* Connection,
    _In_ LDAPMessage* Entry,
    _Out_ LPWSTR* DistinguishedName
);

DWORD
LdapGetStringValues(
    _In_ LDAP* Connection,
    _In_ LDAPMessage* Entry,
    _In_ LPCWSTR Attribute,
    _Out_ PWCHAR** Values
);

DWORD
LdapGetBinaryValues(
    _In_ LDAP* Connection,
    _In_ LDAPMessage* Entry,
    _In_ LPCWSTR Attribute,
    _Out_ berval*** Values
);

void
LdapFreeString(
    _In_opt_ LPWSTR Value
);

void
LdapFreeStringValues(
    _In_opt_ PWCHAR* Values
);

void
LdapFreeBinaryValues(
    _In_opt_ berval** Values
);

#endif // HUNTINGTOOLS_LDAP_H
