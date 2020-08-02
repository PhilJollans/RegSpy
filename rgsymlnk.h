#ifndef REGSMLNK_H_
#define REGSMLNK_H_

/*
*
* $RCSfile: rgsymlnk.h,v $
* $Source: /cvs/rgsymlnk/rgsymlnk.h,v $
* $Author: cvs $
* $Revision: 1.6 $
* $Date: 2005/10/16 12:14:54 $
* $State: Exp $
* Copyright (c) Stefan Kuhr
*
*
*
* $Log: rgsymlnk.h,v $
* Revision 1.6  2005/10/16 12:14:54  cvs
* Added SetSymLink flags
*
* Revision 1.5  2005/10/07 16:58:37  cvs
* Added dwFlags to functions, made a couple functions easier, added VERIFY, removed _alloca
*
* Revision 1.4  2005/10/06 20:02:01  cvs
* Adapted to new signature of CreateSymLinkKey
*
* Revision 1.3  2005/10/05 18:15:45  cvs
* Changed signature of CreateSymLink to use only one string instead of two, made ANSI functions mere stubs to the UNICODE functions
*
* Revision 1.2  2005/10/04 16:14:50  cvs
* Added added standard header, corrected include guards not to start with the reserved double underscores
* 
*/


#ifdef __cplusplus
extern "C" {
#endif

/// Flags for CreateSymLinkKey:
#define CSL_VOLATILE_LINK       0x01
#define CSL_WOW64_64KEY         0x02

/// Flags for SetSymLink:
#define SSL_IGNORE_WOW6432NODE_HANDLING 0x01

LONG CreateSymLinkKeyW(HKEY, LPCWSTR, PHKEY, DWORD );
LONG CreateSymLinkKeyA(HKEY, LPCSTR, PHKEY, DWORD );
LONG SetSymLinkW(HKEY, HKEY, LPCWSTR, DWORD);
LONG SetSymLinkA(HKEY, HKEY, LPCSTR, DWORD);
LONG OpenSymLinkW(HKEY, LPCWSTR, PHKEY, DWORD);
LONG OpenSymLinkA(HKEY, LPCSTR, PHKEY, DWORD);
LONG DeleteSymLinkW(HKEY, LPCWSTR, DWORD);
LONG DeleteSymLinkA(HKEY, LPCSTR, DWORD);

#ifdef __cplusplus
};
#endif

#ifdef UNICODE
#define CreateSymLinkKey CreateSymLinkKeyW
#define SetSymLink       SetSymLinkW
#define OpenSymLink      OpenSymLinkW
#define DeleteSymLink    DeleteSymLinkW
#else
#define CreateSymLinkKey CreateSymLinkKeyA
#define SetSymLink       SetSymLinkA
#define OpenSymLink      OpenSymLinkA
#define DeleteSymLink    DeleteSymLinkA
#endif

#endif /// REGSMLNK_H_
