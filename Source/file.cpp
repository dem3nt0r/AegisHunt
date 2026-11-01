#include "file.h"

#include <aclapi.h>
#include <softpub.h>
#include <userenv.h>
#include <wincrypt.h>
#include <wintrust.h>

#include <cstdio>
#include <cstring>
#include <cwchar>

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "WinTrust.lib")
#pragma comment(lib, "Userenv.lib")


void FileFree(PVOID Memory)
{
    if (Memory != NULL) {
        HeapFree(GetProcessHeap(), 0, Memory);
    }
}

DWORD FileJoinPath(LPCWSTR Directory, LPCWSTR Child, LPWSTR* Joined)
{
    SIZE_T directory_length = 0;
    SIZE_T child_length = 0;
    SIZE_T separator_length = 0;
    LPWSTR buffer = NULL;

    if (Directory == NULL || Child == NULL || Joined == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    *Joined = NULL;
    directory_length = wcslen(Directory);
    child_length = wcslen(Child);
    separator_length = directory_length != 0 && Directory[directory_length - 1] != L'\\' ? 1 : 0;
    if (directory_length > SIZE_MAX - child_length - separator_length - 1) {
        return ERROR_ARITHMETIC_OVERFLOW;
    }
    buffer = static_cast<LPWSTR>(HeapAlloc(GetProcessHeap(), 0,
        (directory_length + child_length +
            separator_length + 1) * sizeof(WCHAR)));
    if (buffer == NULL) {
        return ERROR_OUTOFMEMORY;
    }
    memcpy(buffer, Directory, directory_length * sizeof(WCHAR));
    if (separator_length != 0) {
        buffer[directory_length] = L'\\';
    }
    memcpy(buffer + directory_length + separator_length, Child,
        (child_length + 1) * sizeof(WCHAR));
    *Joined = buffer;
    return ERROR_SUCCESS;
}


DWORD FileResolvePath(LPCWSTR RawPath, LPCWSTR BaseDirectory, LPWSTR* Resolved)
{
    DWORD required = 0;
    DWORD copied = 0;
    LPWSTR expanded = NULL;
    DWORD status = ERROR_SUCCESS;

    if (RawPath == NULL || Resolved == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    *Resolved = NULL;
    required = ExpandEnvironmentStringsW(RawPath, NULL, 0);
    if (required == 0) {
        return GetLastError();
    }
    expanded = static_cast<LPWSTR>(HeapAlloc(GetProcessHeap(), 0,
        static_cast<SIZE_T>(required) * sizeof(WCHAR)));
    if (expanded == NULL) {
        return ERROR_OUTOFMEMORY;
    }
    copied = ExpandEnvironmentStringsW(RawPath, expanded, required);
    if (copied == 0) {
        status = GetLastError();
        FileFree(expanded);
        return status;
    }
    if (copied > required) {
        FileFree(expanded);
        return ERROR_MORE_DATA;
    }
    if (expanded[0] != L'\\' &&
        !(expanded[0] != L'\0' && expanded[1] == L':') && BaseDirectory != NULL) {
        status = FileJoinPath(BaseDirectory, expanded, Resolved);
        FileFree(expanded);
        return status;
    }
    *Resolved = expanded;
    return ERROR_SUCCESS;
}

DWORD FileGetProfilesRoot(LPWSTR* Directory)
{
    DWORD chars = 0;
    DWORD status = ERROR_SUCCESS;
    LPWSTR buffer = NULL;

    if (Directory == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    *Directory = NULL;
    GetProfilesDirectoryW(NULL, &chars);
    status = GetLastError();
    if (status != ERROR_INSUFFICIENT_BUFFER || chars == 0) {
        return status;
    }
    buffer = static_cast<LPWSTR>(HeapAlloc(GetProcessHeap(), 0,
        static_cast<SIZE_T>(chars) * sizeof(WCHAR)));
    if (buffer == NULL) {
        return ERROR_OUTOFMEMORY;
    }
    if (!GetProfilesDirectoryW(buffer, &chars)) {
        status = GetLastError();
        FileFree(buffer);
        return status;
    }
    *Directory = buffer;
    return ERROR_SUCCESS;
}

DWORD FileWalkDirectory(LPCWSTR Directory, BOOL Recursive,
    FILE_WALK_CALLBACK Callback, PVOID Context)
{
    LPWSTR pattern = NULL;
    LPWSTR child = NULL;
    HANDLE search = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATAW entry = {};
    DWORD status = ERROR_SUCCESS;
    DWORD end_status = ERROR_SUCCESS;
    BOOL next = FALSE;

    if (Directory == NULL || Callback == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    status = FileJoinPath(Directory, L"*", &pattern);
    if (status != ERROR_SUCCESS) {
        return status;
    }
    search = FindFirstFileW(pattern, &entry);
    FileFree(pattern);
    if (search == INVALID_HANDLE_VALUE) {
        status = GetLastError();
        return status == ERROR_FILE_NOT_FOUND ? ERROR_SUCCESS : status;
    }
    do {
        if (wcscmp(entry.cFileName, L".") == 0 || wcscmp(entry.cFileName, L"..") == 0) {
            next = FindNextFileW(search, &entry);
            continue;
        }
        child = NULL;
        status = FileJoinPath(Directory, entry.cFileName, &child);
        if (status != ERROR_SUCCESS) {
            break;
        }
        if (entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (Recursive && !(entry.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
                status = FileWalkDirectory(child, Recursive, Callback, Context);
                if (status == ERROR_ACCESS_DENIED) {
                    status = ERROR_SUCCESS;
                }
            }
        }
        else {
            status = Callback(child, &entry, Context);
        }
        FileFree(child);
        if (status != ERROR_SUCCESS) {
            break;
        }
        next = FindNextFileW(search, &entry);
    } while (next);
    if (status == ERROR_SUCCESS) {
        end_status = GetLastError();
        if (end_status != ERROR_NO_MORE_FILES) {
            status = end_status;
        }
    }
    FindClose(search);
    return status;
}

static DWORD FileLookupOwner(PSID Sid, LPWSTR Buffer, DWORD BufferChars)
{
    WCHAR account[128] = {};
    WCHAR domain[128] = {};
    DWORD account_chars = 128;
    DWORD domain_chars = 128;
    SID_NAME_USE use = SidTypeUnknown;
    INT formatted = 0;

    if (Sid == NULL || Buffer == NULL || BufferChars == 0) {
        return ERROR_INVALID_PARAMETER;
    }
    Buffer[0] = L'\0';
    if (!LookupAccountSidW(NULL, Sid, account, &account_chars, domain, &domain_chars, &use)) {
        return GetLastError();
    }
    formatted = swprintf(Buffer, BufferChars, L"%ls\\%ls", domain, account);
    return formatted < 0 ? ERROR_INSUFFICIENT_BUFFER : ERROR_SUCCESS;
}

static DWORD FileGetOwner(LPCWSTR Path, LPWSTR Buffer, DWORD BufferChars)
{
    PSID owner = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    DWORD status = ERROR_SUCCESS;

    status = GetNamedSecurityInfoW(const_cast<LPWSTR>(Path), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION, &owner, NULL, NULL,
        NULL, &descriptor);
    if (status == ERROR_SUCCESS) {
        status = FileLookupOwner(owner, Buffer, BufferChars);
    }
    if (descriptor != NULL) {
        LocalFree(descriptor);
    }
    return status;
}

static DWORD FileHashMd5(LPCWSTR Path, LPWSTR Buffer, DWORD BufferChars)
{
    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;
    HANDLE file = INVALID_HANDLE_VALUE;
    BYTE chunk[65536] = {};
    BYTE digest[16] = {};
    DWORD digest_size = sizeof(digest);
    DWORD read = 0;
    DWORD status = ERROR_SUCCESS;
    DWORD index = 0;
    BOOL read_success = FALSE;
    const WCHAR digits[] = L"0123456789ABCDEF";

    if (Path == NULL || Buffer == NULL || BufferChars < 33) {
        return ERROR_INVALID_PARAMETER;
    }
    Buffer[0] = L'\0';
    file = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return GetLastError();
    }
    if (!CryptAcquireContextW(&provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        status = GetLastError();
        CloseHandle(file);
        return status;
    }
    if (!CryptCreateHash(provider, CALG_MD5, 0, 0, &hash)) {
        status = GetLastError();
    }
    else {
        for (;;) {
            read_success = ReadFile(file, chunk, sizeof(chunk), &read, NULL);
            if (!read_success) {
                status = GetLastError();
                break;
            }
            if (read == 0) {
                break;
            }
            if (!CryptHashData(hash, chunk, read, 0)) {
                status = GetLastError();
                break;
            }
        }
        if (status == ERROR_SUCCESS && !CryptGetHashParam(hash, HP_HASHVAL, digest,
            &digest_size, 0)) {
            status = GetLastError();
        }
        if (status == ERROR_SUCCESS && digest_size == 16) {
            for (index = 0; index < 16; ++index) {
                Buffer[index * 2] = digits[digest[index] >> 4];
                Buffer[index * 2 + 1] = digits[digest[index] & 0x0F];
            }
            Buffer[32] = L'\0';
        }
    }
    if (hash != 0) {
        CryptDestroyHash(hash);
    }
    CryptReleaseContext(provider, 0);
    CloseHandle(file);
    return status;
}

static void FileSignerOrganization(LPCWSTR Path, LPWSTR Buffer, DWORD BufferChars)
{
    HCERTSTORE store = NULL;
    HCRYPTMSG message = NULL;
    DWORD encoding = 0;
    DWORD content = 0;
    DWORD format = 0;
    DWORD signer_size = 0;
    PCMSG_SIGNER_INFO signer = NULL;
    CERT_INFO cert_info = {};
    PCCERT_CONTEXT certificate = NULL;

    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, Path,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY, 0, &encoding, &content, &format,
        &store, &message, NULL)) {
        return;
    }
    if (CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, NULL, &signer_size)) {
        signer = static_cast<PCMSG_SIGNER_INFO>(HeapAlloc(GetProcessHeap(), 0, signer_size));
        if (signer != NULL && CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0,
            signer, &signer_size)) {
            cert_info.Issuer = signer->Issuer;
            cert_info.SerialNumber = signer->SerialNumber;
            certificate = CertFindCertificateInStore(store, encoding, 0,
                CERT_FIND_SUBJECT_CERT, &cert_info, NULL);
            if (certificate != NULL) {
                CertGetNameStringW(certificate, CERT_NAME_ATTR_TYPE, 0,
                    const_cast<LPSTR>(szOID_ORGANIZATION_NAME),
                    Buffer, BufferChars);
                CertFreeCertificateContext(certificate);
            }
        }
    }
    if (signer != NULL) {
        HeapFree(GetProcessHeap(), 0, signer);
    }
    CertCloseStore(store, 0);
    CryptMsgClose(message);
}

static LONG FileVerifySignature(LPCWSTR Path, LPWSTR Buffer, DWORD BufferChars)
{
    WINTRUST_FILE_INFO file_info = {};
    WINTRUST_DATA trust = {};
    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG result = 0;

    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = Path;
    trust.cbStruct = sizeof(trust);
    trust.dwUIChoice = WTD_UI_NONE;
    trust.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust.dwUnionChoice = WTD_CHOICE_FILE;
    trust.pFile = &file_info;
    trust.dwStateAction = WTD_STATEACTION_VERIFY;
    result = WinVerifyTrust(NULL, &policy, &trust);
    if (result == ERROR_SUCCESS) {
        if (BufferChars > 11) {
            wcscpy_s(Buffer, BufferChars, L"(Verified) ");
            FileSignerOrganization(Path, Buffer + 11, BufferChars - 11);
        }
    }
    trust.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policy, &trust);
    return result;
}

DWORD FileFormatTime(const FILETIME* Time, LPWSTR Buffer, DWORD BufferChars)
{
    SYSTEMTIME utc = {};
    INT formatted = 0;

    if (Time == NULL || Buffer == NULL || BufferChars == 0) {
        return ERROR_INVALID_PARAMETER;
    }
    Buffer[0] = L'\0';
    if (!FileTimeToSystemTime(Time, &utc)) {
        return GetLastError();
    }
    formatted = swprintf(Buffer, BufferChars, L"%04u-%02u-%02u %02u:%02u:%02u",
        static_cast<unsigned int>(utc.wYear),
        static_cast<unsigned int>(utc.wMonth),
        static_cast<unsigned int>(utc.wDay),
        static_cast<unsigned int>(utc.wHour),
        static_cast<unsigned int>(utc.wMinute),
        static_cast<unsigned int>(utc.wSecond));
    return formatted < 0 ? ERROR_INSUFFICIENT_BUFFER : ERROR_SUCCESS;
}

DWORD FileInspect(LPCWSTR Path, PFILE_INFORMATION Result)
{
    WIN32_FILE_ATTRIBUTE_DATA attributes = {};

    if (Path == NULL || Result == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    *Result = {};
    if (!GetFileAttributesExW(Path, GetFileExInfoStandard, &attributes)) {
        return GetLastError();
    }
    Result->CreationTime = attributes.ftCreationTime;
    Result->AccessTime = attributes.ftLastAccessTime;
    Result->WriteTime = attributes.ftLastWriteTime;
    Result->OwnerStatus = FileGetOwner(Path, Result->Owner, 256);
    Result->SignatureStatus = FileVerifySignature(Path, Result->Signature, 256);
    Result->HashStatus = FileHashMd5(Path, Result->Md5, 33);
    return ERROR_SUCCESS;
}
