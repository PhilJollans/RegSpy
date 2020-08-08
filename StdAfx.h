// stdafx.h : include file for standard system include files,
//  or project specific include files that are used frequently, but
//      are changed infrequently
//
#pragma once

#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers
#define _WIN32_WINNT _WIN32_WINNT_WINXP

#pragma comment(lib, "advapi32")
// This is for GetFileTitle, gan we get rid of that function?
#pragma comment(lib, "Comdlg32")
#include <windows.h>
#include <stdio.h>
#include "CStdString.h"

