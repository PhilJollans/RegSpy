/*
*
* $RCSfile: rgsymlnk.c,v $
* $Source: /cvs/rgsymlnk/rgsymlnk.c,v $
* $Author: cvs $
* $Revision: 1.8 $
* $Date: 2005/10/16 12:14:54 $
* $State: Exp $
* Copyright (c) Stefan Kuhr
*
*
*
* $Log: rgsymlnk.c,v $
* Revision 1.8  2005/10/16 12:14:54  cvs
* Added SetSymLink flags
*
* Revision 1.7  2005/10/16 11:31:38  cvs
* Removed warning in x64 builds
*
* Revision 1.6  2005/10/07 16:58:37  cvs
* Added dwFlags to functions, made a couple functions easier, added VERIFY, removed _alloca
*
* Revision 1.5  2005/10/06 20:02:01  cvs
* Adapted to new signature of CreateSymLinkKey
*
* Revision 1.4  2005/10/06 19:08:01  cvs
* Made adaptions for x86 Builds
*
* Revision 1.3  2005/10/05 18:15:45  cvs
* Changed signature of CreateSymLink to use only one string instead of two, made ANSI functions mere stubs to the UNICODE functions
*
* Revision 1.2  2005/10/04 16:14:01  cvs
* Added pragmas for newer PlatSDKs, added standard header
*
*/

#pragma warning (disable: 4305 4505) // we disable 4505, because most probably for Win32 x86 Builds, IsRunningUnderWow64 will never be called
#include <windows.h>
#pragma warning (default: 4305)
#include <crtdbg.h>
#include "rgsymlnk.h"
#include "wow64hlp.h"

///
/// define VERIFY if not yet defined:
///
#ifndef VERIFY
#ifdef _DEBUG
#define VERIFY(exp)   (void)((exp) || (_CrtDbgReport(_CRT_ASSERT, __FILE__, __LINE__, NULL, NULL),0))
#else  // _DEBUG
#define VERIFY(a)  ((void)(a))
#endif // _DEBUG
#endif // VERIFY


#define dimof(a) (sizeof(a)/sizeof(a[0]))

#define MACHINE_REG_PATHW L"\\Registry\\MACHINE\\"
#define USER_REG_PATHW L"\\Registry\\USER\\"
#define CURUSER_REG_PATHW L"\\Registry\\USER\\CurrentUser\\"
#define X64_MACHINE_SOFTWARE_REG_PATHW L"\\Registry\\MACHINE\\Software\\Wow6432Node\\"
#define SOFTWARE_START_KEYW L"Software\\"
#define SOFTWARE_CLASSES_START_KEYW L"Software\\Classes\\"
#define X64_MACHINE_CLASSES_REG_PATHW L"\\Registry\\MACHINE\\Software\\Classes\\Wow6432Node\\"


///
/// local prototypes as necessary:
///
static LPWSTR GetGurrentUserRegPath(void);
static LPWSTR GetClassesRootSubPath(LPCWSTR pszBaseKey);




//---------------------------------------------------------
// Excerpts from wdm.h or ntddk.h
//---------------------------------------------------------

typedef LONG NTSTATUS;

#if !defined(_NTSYSTEM_)
#define NTSYSAPI     DECLSPEC_IMPORT
#else
#define NTSYSAPI
#endif

NTSYSAPI
NTSTATUS
NTAPI
ZwDeleteKey(
    IN HANDLE KeyHandle
    );

typedef NTSYSAPI NTSTATUS  (NTAPI *ZW_DELETE_KEY_PROTO)(HANDLE);




LONG CreateSymLinkKeyA(HKEY   hLinkRootKey,
                       LPCSTR pszLinkKey,
                       PHKEY  phLinkKey,
                       DWORD dwFlags)
{
    LONG lStatus = ERROR_SUCCESS;
    size_t stSrcLen = 0;
    LPWSTR szKeyW = NULL;
    if(!pszLinkKey)
        return ERROR_INVALID_PARAMETER;

    stSrcLen = strlen(pszLinkKey)+1;
    szKeyW = LocalAlloc(LPTR, stSrcLen*sizeof(WCHAR));
    if(!szKeyW)
    {
        lStatus = GetLastError();
        goto CLEANUP;
    }

    if (!MultiByteToWideChar(GetACP(), 0L, pszLinkKey, -1, szKeyW, (int)stSrcLen))
    {
        lStatus = GetLastError();
        goto CLEANUP;
    }

    lStatus = CreateSymLinkKeyW(hLinkRootKey, szKeyW, phLinkKey, dwFlags);

CLEANUP:

    if(szKeyW)
        VERIFY(!LocalFree(szKeyW));

    return lStatus;
}




LONG CreateSymLinkKeyW(HKEY   hLinkRootKey,
                       LPCWSTR pszLinkKey,
                       PHKEY  phLinkKey,
                       DWORD dwFlags)
{
    LONG lStatus = 0;
    DWORD dwOptions = 0L;
    DWORD dwAccess = 0L;

    if(dwFlags&CSL_VOLATILE_LINK)
        dwOptions |= REG_OPTION_VOLATILE;

#ifndef WIN64
    if(dwFlags&CSL_WOW64_64KEY && IsRunningUnderWow64())
        dwAccess|=KEY_WOW64_64KEY;
#endif

    //
    // Create a "link" key under base subkey opened above
    //
    lStatus = RegCreateKeyExW(hLinkRootKey, pszLinkKey, 0, NULL,
                            REG_OPTION_CREATE_LINK | dwOptions,
                            dwAccess|KEY_ALL_ACCESS | KEY_CREATE_LINK,
                            NULL, phLinkKey, NULL);

    //
    // the symbolic link key has been created but it doesn't link
    // to anything, yet.
    //
    return lStatus;
}






#define STRINGSTARTSWITHW(a,b) (!wcsnicmp(a, b, (sizeof(b)-sizeof(wchar_t))/sizeof(wchar_t)))
#define STRINGSTARTSWITHA(a,b) (!strnicmp(a, b, sizeof(b)-sizeof(char)))


LONG SetSymLinkA(HKEY   hLinkKey,
                 HKEY   hBaseRootKey,
                 LPCSTR pszBaseKey,
                 DWORD dwFlags)
{
    LONG lStatus = ERROR_SUCCESS;
    size_t stSrcLen = 0;
    LPWSTR szKeyW = NULL;
    if(!pszBaseKey)
        return ERROR_INVALID_PARAMETER;

    stSrcLen = strlen(pszBaseKey)+1;
    szKeyW = LocalAlloc(LPTR, stSrcLen*sizeof(WCHAR));
    if(!szKeyW)
    {
        lStatus = GetLastError();
        goto CLEANUP;
    }

    if (!MultiByteToWideChar(GetACP(), 0L, pszBaseKey, -1, szKeyW, (int)stSrcLen))
    {
        lStatus = GetLastError();
        goto CLEANUP;
    }

    lStatus = SetSymLinkW(hLinkKey, hBaseRootKey, szKeyW, dwFlags);

CLEANUP:

    if(szKeyW)
        VERIFY(!LocalFree(szKeyW));

    return lStatus;
}















LONG SetSymLinkW(HKEY   hLinkKey,
                 HKEY   hBaseRootKey,
                 LPCWSTR pszBaseKey,
                 DWORD dwFlags)
{
    LONG lStatus = 0;
    LPWSTR sz = NULL;
    LPWSTR szPath = MACHINE_REG_PATHW;
    LPWSTR szAdditionalPath = NULL;
    size_t stLen = sizeof(MACHINE_REG_PATHW);
    int iBaseKeyLen = 0;
    size_t stAlloc = 0;


    if (!hLinkKey ||
        HKEY_LOCAL_MACHINE!=hBaseRootKey && HKEY_USERS!=hBaseRootKey && HKEY_CURRENT_USER!=hBaseRootKey  && HKEY_CLASSES_ROOT!=hBaseRootKey ||
        !pszBaseKey)
        return ERROR_INVALID_PARAMETER;

    if (HKEY_USERS == hBaseRootKey)
    {
        stLen = sizeof(USER_REG_PATHW);
        szPath = USER_REG_PATHW;
    }
    else if (HKEY_CURRENT_USER == hBaseRootKey)
    {
        hBaseRootKey = HKEY_USERS;

        szPath = szAdditionalPath = GetGurrentUserRegPath();
        if(!szPath)
        {
            lStatus = GetLastError();
            goto CLEANUP;
        }
        stLen = (wcslen(szPath)+1) * sizeof(WCHAR);
    }
    else if (HKEY_CLASSES_ROOT == hBaseRootKey)
    {
        hBaseRootKey = HKEY_LOCAL_MACHINE;
        pszBaseKey = szAdditionalPath = GetClassesRootSubPath(pszBaseKey);
    }


#ifndef WIN64
    if (!(dwFlags&SSL_IGNORE_WOW6432NODE_HANDLING) && hBaseRootKey == HKEY_LOCAL_MACHINE && IsRunningUnderWow64())

    {
        if (STRINGSTARTSWITHW(pszBaseKey, SOFTWARE_CLASSES_START_KEYW))
        {
            pszBaseKey = &pszBaseKey[(sizeof(SOFTWARE_CLASSES_START_KEYW)-sizeof(wchar_t))/sizeof(wchar_t)];
            szPath = X64_MACHINE_CLASSES_REG_PATHW;
            stLen = sizeof(X64_MACHINE_CLASSES_REG_PATHW);
        }
        else if (STRINGSTARTSWITHW(pszBaseKey,SOFTWARE_START_KEYW))
        {
            pszBaseKey = &pszBaseKey[(sizeof(SOFTWARE_START_KEYW)-sizeof(wchar_t))/sizeof(wchar_t)];
            szPath = X64_MACHINE_SOFTWARE_REG_PATHW;
            stLen = sizeof(X64_MACHINE_SOFTWARE_REG_PATHW);
        }
    }
#else
    dwFlags; // prevent C4100
#endif

    iBaseKeyLen = lstrlenW(pszBaseKey);

    // Form the path to link to using kernel mode registry syntax

    stAlloc = stLen + iBaseKeyLen*sizeof(wchar_t);
    sz = LocalAlloc(LPTR, stAlloc);
    if(!sz)
    {
        lStatus = GetLastError();
        goto CLEANUP;
    }

    memcpy(sz, szPath, stLen);

    stLen = stLen/sizeof(wchar_t) - 1;

    memcpy(&sz[stLen], pszBaseKey, (iBaseKeyLen+1)*sizeof(wchar_t));

    // Store the link target in the special "SymbolicLinkValue"
    // REG_LINK value in the special link key to form the link.

    stAlloc -= sizeof(wchar_t);
#pragma warning (disable:4127)
    _ASSERT(stAlloc==(lstrlenW(sz)*sizeof(wchar_t)));
#pragma warning (default:4127)

    lStatus = RegSetValueExW(hLinkKey, L"SymbolicLinkValue", 0,
                           REG_LINK, (LPBYTE)sz,
                           (DWORD)stAlloc);


CLEANUP:

    if(szAdditionalPath)
        VERIFY(!LocalFree(szAdditionalPath));

    if(sz)
        VERIFY(!LocalFree(sz));

    return lStatus;

}


LONG OpenSymLinkA(HKEY   hRootKey,
                  LPCSTR pszKey,
                  PHKEY  phLinkKey,
                  DWORD dwFlags)
{
    LONG lStatus = ERROR_SUCCESS;
    size_t stSrcLen = 0;
    LPWSTR szKeyW = NULL;
    if(!pszKey)
        return ERROR_INVALID_PARAMETER;

    stSrcLen = strlen(pszKey)+1;
    szKeyW = LocalAlloc(LPTR, stSrcLen*sizeof(WCHAR));
    if(!szKeyW)
    {
        lStatus = GetLastError();
        goto CLEANUP;
    }

    if (!MultiByteToWideChar(GetACP(), 0L, pszKey, -1, szKeyW, (int)stSrcLen))
    {
        lStatus = GetLastError();
        goto CLEANUP;
    }

    lStatus = OpenSymLinkW(hRootKey, szKeyW, phLinkKey, dwFlags);

CLEANUP:

    if(szKeyW)
        VERIFY(!LocalFree(szKeyW));

    return lStatus;
}


LONG OpenSymLinkW(HKEY   hRootKey,
                  LPCWSTR pszKey,
                  PHKEY  phLinkKey,
                  DWORD dwFlags)
{
    LONG lStatus = ERROR_SUCCESS;
    LPCWSTR szKey = pszKey;
    DWORD dwAccess = 0L;

    if(!pszKey)
        return ERROR_INVALID_PARAMETER;

#ifndef WIN64
    if(dwFlags&CSL_WOW64_64KEY && IsRunningUnderWow64())
        dwAccess|=KEY_WOW64_64KEY;
#else
    dwFlags; // prevent C4100
#endif

    if(HKEY_CLASSES_ROOT==hRootKey)
    {
        hRootKey = HKEY_LOCAL_MACHINE;
        szKey = GetClassesRootSubPath(pszKey);
        if(!szKey)
        {
            lStatus = GetLastError();
            goto CLEANUP;
        }
    }

    lStatus = RegOpenKeyExW(hRootKey, szKey, REG_OPTION_OPEN_LINK,
                          dwAccess|KEY_ALL_ACCESS, phLinkKey);


CLEANUP:

    if(szKey && szKey!=pszKey)
        VERIFY(!LocalFree((LPWSTR)szKey));

    return lStatus;
}




static LONG ClearSymLink(HKEY hLinkKey)
{
    //
    // Clear the link target from the special "SymbolicLinkValue"
    // REG_LINK value.
    //
    return RegDeleteValueW(hLinkKey, L"SymbolicLinkValue");

}




static LONG DynZwDeleteKey(HKEY hKey)
{
    LONG lStatus = ERROR_SUCCESS;
    HMODULE hNTDll = LoadLibraryW( L"ntdll.dll" );
    if (hNTDll)
    {
      ZW_DELETE_KEY_PROTO lpfnZwDeleteKey =  (ZW_DELETE_KEY_PROTO)GetProcAddress(hNTDll, "ZwDeleteKey");
      if (lpfnZwDeleteKey)
        lStatus = lpfnZwDeleteKey(hKey);
      else
        lStatus = GetLastError();

      VERIFY(FreeLibrary(hNTDll));
    }
    else
        lStatus = GetLastError();

    return lStatus;
}


LONG DeleteSymLinkA(HKEY hRootKey, LPCSTR pszKey, DWORD dwFlags)
{
    LONG lStatus = ERROR_SUCCESS;
    size_t stSrcLen = 0;
    LPWSTR szKeyW = NULL;
    if(!pszKey)
        return ERROR_INVALID_PARAMETER;

    stSrcLen = strlen(pszKey)+1;
    szKeyW = LocalAlloc(LPTR, stSrcLen*sizeof(WCHAR));
    if(!szKeyW)
    {
        lStatus = GetLastError();
        goto CLEANUP;
    }

    if (!MultiByteToWideChar(GetACP(), 0L, pszKey, -1, szKeyW, (int)stSrcLen))
    {
        lStatus = GetLastError();
        goto CLEANUP;
    }

    lStatus = DeleteSymLinkW(hRootKey, szKeyW, dwFlags);

CLEANUP:

    if(szKeyW)
        VERIFY(!LocalFree(szKeyW));

    return lStatus;
}


LONG DeleteSymLinkW(HKEY hRootKey, LPCWSTR pszKey, DWORD dwFlags)
{
    LONG lStatus = ERROR_SUCCESS;
    HKEY hKey = NULL;

    if (HKEY_LOCAL_MACHINE!=hRootKey && HKEY_USERS!=hRootKey && HKEY_CURRENT_USER!=hRootKey && HKEY_CLASSES_ROOT!=hRootKey || !pszKey)
        return ERROR_INVALID_PARAMETER;


    // Open the symbolic link, clear the SymbolicLinkValue,
    // and delete the symbolic link key. We can't use the
    // normal user-mode RegDeleteKey routine because we have
    // to open the key a special way and the RegDeleteKey
    // performs the open internally. Use the ZwDeleteKey
    // routine instead.

    lStatus = OpenSymLinkW(hRootKey, pszKey, &hKey, dwFlags);
    if (lStatus == ERROR_SUCCESS)
    {
        ClearSymLink(hKey);
        lStatus = DynZwDeleteKey(hKey);
    }

    return lStatus;
}






static BOOL FreeUserSid(PSID pSid)
{
    return HeapFree(GetProcessHeap(), 0, (LPVOID)pSid);
}


static BOOL ObtainUserSid(HANDLE hToken, PSID *ppSid)
{
    DWORD                   dwReturnLength     = 0;
    DWORD                   dwTokenUserLength  = 0;

    TOKEN_INFORMATION_CLASS tic                = TokenUser;
    TOKEN_USER              *ptu               = NULL;

    if (!ppSid)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *ppSid = NULL;



    //
    // query info in the token
    //
    if (!GetTokenInformation(hToken, tic, (LPVOID)ptu, dwTokenUserLength,&dwReturnLength))
    {
        // GetTokenInformation is intended to fail intentionally, because we passed zero return length
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            BOOL bReturn = FALSE;
            // dwReturnLength now holds the required size.
            DWORD dwError = ERROR_SUCCESS;
            ptu = (TOKEN_USER *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwReturnLength);
            if (ptu == NULL)
                return bReturn;


            dwTokenUserLength = dwReturnLength;
            dwReturnLength    = 0;

            if (!GetTokenInformation(hToken, tic, (LPVOID)ptu, dwTokenUserLength, &dwReturnLength))
            {
                dwError = GetLastError();
                bReturn = FALSE;
            }
            else if (IsValidSid((ptu->User).Sid)) /// paranoia
            {
                PSID pSrcSid = (ptu->User).Sid;
                DWORD dwLen = GetLengthSid(pSrcSid);
                PSID pDestSid = (PSID)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLen);
                if (pDestSid)
                {
                    if (CopySid(dwLen, pDestSid, pSrcSid))
                    {
                        *ppSid = pDestSid;
                        bReturn = TRUE;
                    }
                    else
                    {
                        dwError = GetLastError();
                        VERIFY(FreeUserSid(pDestSid));
                    }
                }
                else
                    dwError = GetLastError();
            }
            else
                dwError = GetLastError();

            if (!HeapFree(GetProcessHeap(), 0, (LPVOID)ptu))
            {
                if (bReturn) // if everything succeeded up to now, we want *this* error's rteason,
                    dwError = GetLastError();/// otherwise the reason when the real error happened

                bReturn = FALSE;
            }

            SetLastError(dwError);

            return bReturn;
        }
        else
            return FALSE;
    }
    else
        return FALSE;
}


static BOOL ConvertSid(PSID pSid, LPWSTR pszSidText, LPDWORD dwBufferLen)
{
    PSID_IDENTIFIER_AUTHORITY psia;
    DWORD dwSubAuthorities;
    DWORD dwSidRev=SID_REVISION;
    DWORD dwCounter;
    DWORD dwSidSize;

    //
    // test if Sid passed in is valid
    //
    if(!IsValidSid(pSid))
        return FALSE;

    // obtain SidIdentifierAuthority
    psia=GetSidIdentifierAuthority(pSid);

    // obtain sidsubauthority count
    dwSubAuthorities=*GetSidSubAuthorityCount(pSid);

    //
    // compute buffer length
    // S-SID_REVISION- + identifierauthority- + subauthorities- + NULL
    //
    dwSidSize=(15 + 12 + (12 * dwSubAuthorities) + 1) * sizeof(WCHAR);

    //
    // check provided buffer length.
    // If not large enough, indicate proper size and setlasterror
    //
    if (*dwBufferLen < dwSidSize)
    {
        *dwBufferLen = dwSidSize;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    //
    // prepare S-SID_REVISION-
    //
    dwSidSize=wsprintfW(pszSidText, L"S-%lu-", dwSidRev );

    //
    // prepare SidIdentifierAuthority
    //
    if ( (psia->Value[0] != 0) || (psia->Value[1] != 0) )
    {
        dwSidSize+=wsprintfW(pszSidText + lstrlenW(pszSidText),
            L"0x%02hx%02hx%02hx%02hx%02hx%02hx",
            (USHORT)psia->Value[0],
            (USHORT)psia->Value[1],
            (USHORT)psia->Value[2],
            (USHORT)psia->Value[3],
            (USHORT)psia->Value[4],
            (USHORT)psia->Value[5]);
    }
    else
    {
        dwSidSize+=wsprintfW(pszSidText + lstrlenW(pszSidText),
            L"%lu",
            (ULONG)(psia->Value[5]      )   +
            (ULONG)(psia->Value[4] <<  8)   +
            (ULONG)(psia->Value[3] << 16)   +
            (ULONG)(psia->Value[2] << 24)   );
    }

    //
    // loop through SidSubAuthorities
    //
    for (dwCounter=0 ; dwCounter < dwSubAuthorities ; dwCounter++)
    {
        dwSidSize+=wsprintfW(pszSidText + dwSidSize, L"-%lu",
        *GetSidSubAuthority(pSid, dwCounter) );
    }

    return TRUE;
}

static LPWSTR GetCurrentUserSidAsWideChar(void)
{
    HANDLE hCurThreadTok = NULL;
    PSID pSid = NULL;
    DWORD dwLastError = ERROR_SUCCESS;
    LPWSTR szReturn = NULL;
    DWORD dwBufferLen = 0L;
    HANDLE hCurThread = GetCurrentThread();

    if (!OpenThreadToken(hCurThread, TOKEN_QUERY, FALSE, &hCurThreadTok))
    {
        if (!OpenThreadToken(hCurThread, TOKEN_QUERY, TRUE, &hCurThreadTok))
        {
            if(!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hCurThreadTok))
                return NULL;
        }
    }


    if (!ObtainUserSid(hCurThreadTok, &pSid))
    {
        dwLastError = GetLastError();
        goto CLEANUP;
    }

    ConvertSid(pSid, szReturn, &dwBufferLen);

    szReturn = LocalAlloc(LPTR, dwBufferLen*sizeof(WCHAR));
    if(!szReturn)
    {
        dwLastError = GetLastError();
        goto CLEANUP;
    }

    if(!ConvertSid(pSid, szReturn, &dwBufferLen))
    {
        dwLastError = GetLastError();
        goto CLEANUP;
    }


CLEANUP:

    if(hCurThreadTok)
        VERIFY(CloseHandle(hCurThreadTok));

    if(pSid)
        VERIFY(FreeUserSid(pSid));

    if(ERROR_SUCCESS==dwLastError)
        return szReturn;

    if(szReturn)
        VERIFY(!LocalFree(szReturn));

    SetLastError(dwLastError);
    return NULL;
}


LPWSTR GetGurrentUserRegPath(void)
{
    DWORD dwLastErr = ERROR_SUCCESS;
    LPWSTR szReturn = NULL;
    size_t stLen = 0;
    LPWSTR szSidText = GetCurrentUserSidAsWideChar();
    if (!szSidText)
    {
        dwLastErr = GetLastError();
        goto CLEANUP;
    }

    stLen = wcslen(szSidText)+2;

    szReturn = LocalAlloc(LPTR, sizeof(USER_REG_PATHW) + stLen*sizeof(WCHAR));
    if(!szReturn)
    {
        dwLastErr = GetLastError();
        goto CLEANUP;
    }

    memcpy(szReturn, USER_REG_PATHW, sizeof(USER_REG_PATHW));
    memcpy(&szReturn[dimof(USER_REG_PATHW)-1], szSidText, (stLen-1)*sizeof(WCHAR));
    szReturn[dimof(USER_REG_PATHW)+stLen-3]= L'\\';
    szReturn[dimof(USER_REG_PATHW)+stLen-2]= L'\0';



CLEANUP:

    if(szSidText)
        VERIFY(!LocalFree(szSidText));

    if(ERROR_SUCCESS==dwLastErr)
        return szReturn;

    SetLastError(dwLastErr);

    return NULL;
}


static LPWSTR GetClassesRootSubPath(LPCWSTR pszBaseKey)
{
    size_t stLen = wcslen(pszBaseKey)*sizeof(WCHAR);
    LPWSTR szReturn = LocalAlloc(LPTR, sizeof(SOFTWARE_CLASSES_START_KEYW) + stLen);
    if (szReturn)
    {
        memcpy(szReturn, SOFTWARE_CLASSES_START_KEYW, sizeof(SOFTWARE_CLASSES_START_KEYW));
        memcpy(&szReturn[dimof(SOFTWARE_CLASSES_START_KEYW)-1], pszBaseKey, stLen);
    }

    return szReturn;
}

