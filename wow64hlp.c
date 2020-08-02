/*
*
* $RCSfile: wow64hlp.c,v $
* $Source: /cvs/rgsymlnk/wow64hlp.c,v $
* $Author: cvs $
* $Revision: 1.1 $
* $Date: 2005/10/06 20:02:21 $
* $State: Exp $
* Copyright (c) Stefan Kuhr
*
*
*
* $Log: wow64hlp.c,v $
* Revision 1.1  2005/10/06 20:02:21  cvs
* no message
*
*/

#pragma warning (disable:4305)
#include <windows.h>
#pragma warning (default:4305)
#include "wow64hlp.h"

typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE hProcess,PBOOL Wow64Process);


BOOL IsRunningUnderWow64(void)
{
    BOOL bIsWow64 = FALSE;

#ifndef WIN64
    LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandleW(L"kernel32"),"IsWow64Process");

    if (NULL != fnIsWow64Process)
    {
        if (!fnIsWow64Process(GetCurrentProcess(),&bIsWow64))
            bIsWow64 = FALSE;
    }
#endif

    return bIsWow64;
}




