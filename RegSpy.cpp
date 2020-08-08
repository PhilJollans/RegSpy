// RegSpy.cpp : Defines the entry point for the console application.
//

// Modified to output what would have happened to the registry
// to stdout by Justin Buist (jbuist@justinbuist.org) around early October 2003.
// Some of the code used to recurse through the registry trees was stolen from the 'regxml'
// project I found on http://www.thecodeproject.com.  Namely, the 'ConvertToString' function.
// Because I used this function the project is now dependant on MFC.  If somebody wants to
// remove all references to CString be my guest.


// /// DO NOT LINK WITH THE /GZ Option
#include "stdafx.h"
#include <windows.h>
#include <shlwapi.h>
#include <commdlg.h>
#include <iostream>
#include <string>
#include "rgsymlnk.h"

using namespace std;

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

typedef HINSTANCE (WINAPI *ProcLoadLibrary)(const char*);
typedef FARPROC (WINAPI *ProcGetProcAddress)(HMODULE, LPCSTR);
typedef HRESULT (STDAPICALLTYPE *ProcDllReg)() ;
typedef DWORD  (STDAPICALLTYPE *ProcWaitForS)(HANDLE, DWORD);
typedef long (STDAPICALLTYPE *RegOver) (HKEY, HKEY);
typedef long (STDAPICALLTYPE *RegCreate) (HKEY, LPCTSTR, DWORD, LPTSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
typedef DWORD (WINAPI* ProcResume)(HANDLE);


const string substituteKey ( "Software\\Substitute\\Registry\\" ) ;
string keycr ;
string keylm ;

// JJB:  Sloppy global counter.
int g_currLevel = 0;

char shortname [MAX_PATH] = {0};
string comname ;
string exeparm ;

typedef struct parmstag
{
  char               kcr [MAX_PATH];
  char               klm [MAX_PATH];
  ProcLoadLibrary	 fnload;
  ProcGetProcAddress fnGetProc;
  ProcResume         fnResume;
  ProcWaitForS       fnWaitFor;
  char               advdll [MAX_PATH];
  char               regover [MAX_PATH];
  char               regcreate [MAX_PATH];
  HANDLE             hProcThread;
} myparms;

myparms parms;

#pragma check_stack (off)

string ConvertToString ( DWORD dwType, LPTSTR szRawBuffer, DWORD nLen )
{
	// JJB:  Yep, I stole this from 'regxml'.  The author's copyright seems to
	// allow me to do anything but print out his documentation and make a paper
	// airplane out of it so this should be allowed.

	// Phil: I have replaced (MFC) CString with CStdString, whichis now on GitHub
	// https://github.com/lunakid/CStdString
	//
	// C++20 is introducing a method std::format()
	// https://en.cppreference.com/w/cpp/utility/format/format
	// which may be a better alternative, but it is not yet supported by Microsoft C++.

    CStdString s ;

	// conversion from number to string
	if ( (dwType>=REG_BINARY && dwType<=REG_DWORD_BIG_ENDIAN) ||
			dwType==11 ||
			dwType==REG_RESOURCE_LIST ||
			dwType==REG_RESOURCE_REQUIREMENTS_LIST)
	{
		switch (dwType)
		{
			case REG_BINARY :
			case REG_RESOURCE_LIST :
			case REG_RESOURCE_REQUIREMENTS_LIST :
			{
				CStdString sByte;
				for (int i=0; i<(long)nLen; i++)
				{
					byte c = szRawBuffer[i];
					sByte.Format(_T("%02x"), c);
					if (!s.IsEmpty()) s += _T(" ");
					s += sByte;
				}
			}
			break;
			case REG_DWORD : // == REG_DWORD_LITTLE_ENDIAN
			{
				byte a = szRawBuffer[3];
				byte b = szRawBuffer[2];
				byte c = szRawBuffer[1];
				byte d = szRawBuffer[0];
				s.Format(_T("0x%02x%02x%02x%02x"), a, b, c, d);
				DWORD n = (a<<24) | (b<<16) | (c<<8) | d;
				CStdString sDword;
				sDword.Format(_T(" (%d)"), n);
				s += sDword;
			}
			break;
			case REG_DWORD_BIG_ENDIAN :
			{
				byte a = szRawBuffer[0];
				byte b = szRawBuffer[1];
				byte c = szRawBuffer[2];
				byte d = szRawBuffer[3];
				s.Format(_T("0x%02x%02x%02x%02x"), a, b, c, d);
				DWORD n = (a<<24) | (b<<16) | (c<<8) | d;
				CStdString sDword;
				sDword.Format(_T(" (%d)"), n);
				s += sDword;
			}
			break;
			case 11 : // QWORD, QWORD_LITTLE_ENDIAN (64-bit integer)
			{
				byte a = szRawBuffer[7];
				byte b = szRawBuffer[6];
				byte c = szRawBuffer[5];
				byte d = szRawBuffer[4];
				byte e = szRawBuffer[3];
				byte f = szRawBuffer[2];
				byte g = szRawBuffer[1];
				byte h = szRawBuffer[0];
				s.Format(_T("0x%02x%02x%02x%02x%02x%02x%02x%02x"), a, b, c, d, e, f, g, h);
			}
			break;
		}
	}
	else
	{
		if (dwType==REG_LINK)
		{
			// convert the Unicode string to local charset string

			char *temps = new char[nLen+1];

			int nActualLength = ::WideCharToMultiByte(CP_ACP,
					0,
					(wchar_t *)szRawBuffer,
					-1,
					temps,
					nLen,
					NULL,
					NULL);

			temps[nActualLength]= _T('\0'); // EOL

			s = temps;

			delete [] temps;
		}
		else if (dwType==REG_MULTI_SZ)
		{
			// a MULTI_SZ value is a set of strings separated by a 0 char, and
			// finishes with a double 0

			for (int i=0; i<long(nLen-2); i++) // nLen-1 instead of nLen, because we don't care the second 0 of the double 0
			{
				if (szRawBuffer[i]==0)
					s += _T("\r\n");
				else
					s += szRawBuffer[i];
			}

		}
		else
		{
			s = szRawBuffer;
		}


	}

	// Since CStdString is based on std::base_string we can return it directly
	return (s);
}


static DWORD WINAPI ThreadProc (PVOID parm)
{
	HKEY hklm = 0;
	HKEY hkcr = 0;
	DWORD dwr=0;

	myparms* pp = (myparms*)parm;
	// load advapi32.dll
	HMODULE hadv = pp->fnload (pp->advdll);
	ProcGetProcAddress GetProc = (ProcGetProcAddress)(pp->fnGetProc);
	RegOver RegOverride = (RegOver)GetProc(hadv,pp->regover) ;
	RegCreate RegCreateK = (RegCreate)GetProc(hadv, pp->regcreate ) ;
	// Create our substitute keys
	long lc = RegCreateK (HKEY_CURRENT_USER, pp->kcr, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hkcr, &dwr);
	lc = RegOverride (HKEY_CLASSES_ROOT, hkcr);
	lc = RegCreateK(HKEY_CURRENT_USER, pp->klm, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hklm, &dwr);
	lc = RegOverride(HKEY_LOCAL_MACHINE, hklm);
	// Let the server run and register
	pp->fnResume (pp->hProcThread);
	// Wait for the server to finish
	pp->fnWaitFor (pp->hProcThread, 60000);
	return 0;
}

// This function marks the memory address after ThreadFunc.

static void AfterThreadProc (void) { }
#pragma check_stack

void CreateAtlRegistrar ()
{
  // We're going to look for the ATL Registrar in case it's need for our server to register, and if it's there we'll
  // copy the key data to our subsitute HKCR key.
  HKEY hkatl;
  long lr = RegOpenKeyEx (HKEY_CLASSES_ROOT, "CLSID\\{44EC053A-400F-11D0-9DCD-00A0C90391D3}\\InprocServer32", 0, KEY_READ, &hkatl);
  if (ERROR_FILE_NOT_FOUND == lr) {
    MessageBox (NULL, "Unable to find ATL Registrar - Registration Might Fail", "Warning", MB_OK);
  }
  else
  {
	char locatl[MAX_PATH];

	// The HKCR substitute
	string clsid = keycr + "\\CLSID\\{44EC053A-400F-11D0-9DCD-00A0C90391D3}\\InprocServer32" ;

    // We'll assume in here that all the ATL.DLL registry entries are present
    DWORD dwsz = sizeof (locatl);
    DWORD dwt = REG_SZ;
    lr = RegQueryValueEx (hkatl, NULL, NULL, &dwt, (BYTE*)locatl, &dwsz);		// Path to Dll
    HKEY hkclsid;
    DWORD dwr;
    //Write Clsid to our substitute HKCR
    lr = RegCreateKeyEx (HKEY_CURRENT_USER, clsid.c_str(), 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hkclsid, &dwr);
    // Set the InprocServer32 key value
    lr = RegSetValueEx (hkclsid, NULL, 0, REG_EXPAND_SZ, (BYTE*)locatl, dwsz);
    //Get and set the ThreadingModel
    lr = RegQueryValueEx (hkatl, "ThreadingModel", NULL, &dwt, (BYTE*)locatl, &dwsz);
    lr = RegSetValueEx (hkclsid, "ThreadingModel", 0, REG_SZ, (BYTE*)locatl, dwsz);
    RegCloseKey (hkatl);
    RegCloseKey (hkclsid);
  }
}

void DeleteAtlRegistrar ()
{
	string delclsid = keycr + "\\CLSID\\{44EC053A-400F-11D0-9DCD-00A0C90391D3}" ;
	SHDeleteKey ( HKEY_CURRENT_USER, delclsid.c_str() ) ;
}

string WindowsErrorText ( DWORD dwError )
{
  LPTSTR  errorText = NULL;
  string  result ;

  FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL,
                dwError,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPTSTR)&errorText,
                0,
                NULL) ;   // arguments - see note

  if ( NULL != errorText )
  {
	result = errorText ;

    // release memory allocated by FormatMessage()
    LocalFree(errorText);
    errorText = NULL;
  }

  return result ;
}

void GetWindowsError()
{
  DWORD	  dwError = GetLastError() ;
  string  errorText = WindowsErrorText ( dwError ) ;
  printf ( "Windows Error\n%s\n", errorText.c_str() ) ;
}

int injectexe ( string parm )
{

	// Copy the keys to the structure that we'll send to our remote thread
	strcpy_s ( parms.kcr, _countof(parms.kcr), keycr.c_str() );
	strcpy_s ( parms.klm, _countof(parms.klm), keylm.c_str() );

	// GetProcAddress values for the functions that our remote thread will call.
	HMODULE hk      = LoadLibrary ("kernel32.dll");

	if ( hk == NULL )
	{
	  GetWindowsError() ;
	  return 1 ;
	}

	parms.fnload    = (ProcLoadLibrary)::GetProcAddress (hk, "LoadLibraryA");
	parms.fnGetProc = (ProcGetProcAddress)::GetProcAddress (hk, "GetProcAddress");
	parms.fnResume  = (ProcResume)::GetProcAddress(hk, "ResumeThread");
	parms.fnWaitFor = (ProcWaitForS)::GetProcAddress (hk, "WaitForSingleObject");
	strcpy_s (parms.advdll, _countof(parms.advdll), "advapi32.dll");

	// The Regxxx functions are in advapi32.dll which we'll load in our remote thread
	strcpy_s (parms.regcreate, _countof(parms.regcreate), "RegCreateKeyExA");
	strcpy_s (parms.regover, _countof(parms.regover), "RegOverridePredefKey");

	// Build a command line for the server & make sure we can find it and initialize for the remote thread
	char cmdline [MAX_PATH];

	strcpy_s ( cmdline, _countof(cmdline), comname.c_str() ) ;
	strcat_s ( cmdline, _countof(cmdline), " " ) ;
	strcat_s ( cmdline, _countof(cmdline), parm.c_str() ) ;

	// Some ATL servers are services so we may have put -service in the command line, however this will cause
	// a service to be created which RegOverridePredefKey will not circumvent.
	if (0)
	ThreadProc (&parms);	// Jump into it to see it run in our process - Debugging purposes only

	STARTUPINFO si;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi;

	void* pcode = 0;
	void* pdata = 0;
	// Cleanup code
	if (0)
	{
cleanup:
		if (pcode)
			VirtualFreeEx (pi.hProcess, pcode, 0, MEM_RELEASE);
		if (pdata)
			VirtualFreeEx (pi.hProcess, pdata, 0, MEM_RELEASE);
		TerminateProcess (pi.hProcess, 1);
		WaitForSingleObject (pi.hProcess, INFINITE);
		WaitForSingleObject (pi.hThread, INFINITE);
		return 1;
	}

	BOOL bc = CreateProcess (NULL, cmdline, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	if (!bc)
	{
		MessageBox (NULL, "Can't Create Process", cmdline, MB_OK);
		return 1;
	}

	HANDLE hProcThread=0;
	BOOL bdup = DuplicateHandle (GetCurrentProcess(), pi.hThread, pi.hProcess, &hProcThread, PROCESS_ALL_ACCESS, false, 0);
	if (!bdup)
	{
		MessageBox (NULL, "Can't Dup Handle", cmdline, MB_OK);
		goto cleanup;
		return 1;
	}
	parms.hProcThread = hProcThread;
	// This code does not clean up absoltely everything, relying instead on process termination to
	// clean up handles and memory
	int cbCodeSize = (BYTE*)AfterThreadProc - (BYTE*)ThreadProc;
	if ( cbCodeSize < 0 )
	{
	  // There is no guarantee that the linker will place the functions in the order that they are in the file.
	  // I have counter 275 bytes in the function ThreadProc. Let's hope that 1000 is enough.
	  cbCodeSize = 1000 ;
	}

	pcode = VirtualAllocEx (pi.hProcess, 0, cbCodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	// The process was created suspended and has done very little.
	// TerminateProcess is unfriendly but should be safe under these circumstances
	if (0==pcode)
	{
		GetWindowsError() ;
		MessageBox (NULL, "Allocate code memory in process", cmdline, MB_OK);
		goto cleanup;
	}
	pdata = VirtualAllocEx (pi.hProcess, 0, sizeof (parms), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (0==pdata)
	{
		GetWindowsError() ;
		MessageBox (NULL, "Allocate data memory in process", cmdline, MB_OK);
		goto cleanup;
	}

	DWORD dwr;
	bc = WriteProcessMemory (pi.hProcess, pcode, (LPVOID)(DWORD) ThreadProc, cbCodeSize, &dwr);
	if (!bc)
	{
		MessageBox (NULL, "Can't Write code to Process Memory", cmdline, MB_OK);
		goto cleanup;
	}

	bc = WriteProcessMemory (pi.hProcess, pdata, &parms, sizeof (parms), &dwr);
	if (!bc)
	{
		MessageBox (NULL, "Can't Write data to Process Memory", cmdline, MB_OK);
		goto cleanup;
	}

	HKEY  hklm      = 0;
	HKEY  hkcr      = 0;
	HKEY  hklm_sw   = 0;
	HKEY  hklm_link = 0;
	long  lc;

	// It is easier if we create the temporary keys here, even if we have to call
	// RegOverridePredefKey in the context of the other process.
	// They would get created in CreateAtlRegistrar() anyway.
	lc = RegCreateKeyEx (HKEY_CURRENT_USER, keycr.c_str(), 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hkcr, &dwr);
	lc = RegCreateKeyEx (HKEY_CURRENT_USER, keylm.c_str(), 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hklm, &dwr);

	// Create a symbolic link from <keylm>\Software\Classes to <keycr>
	string keylm_software_classes = keylm + "\\Software\\Classes";
	lc = RegCreateKeyEx(hklm, "Software", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hklm_sw, &dwr);
	lc = DeleteSymLink (HKEY_CURRENT_USER, keylm_software_classes.c_str(), 0L);
	lc = CreateSymLinkKey (HKEY_CURRENT_USER, keylm_software_classes.c_str(), &hklm_link, 0);
	lc = SetSymLink (hklm_link, HKEY_CURRENT_USER, keycr.c_str(), 0);

	// At this point in time we're ready to set up the substitute registry entries
	CreateAtlRegistrar();

	// Let the remote thread go
	// JJB:  This throws a dialog box with a "File Not Found" error it in that I can't trace down.
	// Many thanks to somebody who can fix this or explain it to me.
	HANDLE ht = CreateRemoteThread (pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pcode, pdata, 0, NULL);
	if ( ht == NULL )
	{
	  GetWindowsError() ;
	}

	long gle = GetLastError();
	dwr = WaitForSingleObject (pi.hThread, INFINITE);
	CloseHandle (pi.hThread);
	CloseHandle (pi.hProcess);

	if ( ht != NULL )
	{
	  WaitForSingleObject (ht, 10000);
	  CloseHandle (ht);
	}

	// Delete the symbolic link and the Software key
	lc = DeleteSymLink (HKEY_CURRENT_USER, keylm_software_classes.c_str(), 0L);
	lc = RegDeleteKey (hklm, "Software");

	// Delete the ATL Registrar key we put in the substitute
	DeleteAtlRegistrar();

	return 1;
}

int DoDll()
{
	// We're going to look for the ATL Registrar in case it's need for our server to register, and if it's there we'll
	// copy the key data to our subsitute HKCR key.
	CreateAtlRegistrar();

	HMODULE hMod = ::LoadLibrary ( comname.c_str() );
	if (NULL==hMod){
		MessageBox (NULL, "Can't Find", comname.c_str(), MB_OK);
		return 1;
	}

	HKEY  hklm      = 0;
	HKEY  hkcr      = 0;
	HKEY  hklm_sw   = 0;
	HKEY  hklm_link = 0;
	DWORD dwr       = 0;
	long  lc;

	// Find DllregisterServer, prepare to call it
	ProcDllReg DLLRegisterServer = (ProcDllReg)::GetProcAddress(hMod,"DllRegisterServer" ) ;
	if (DLLRegisterServer != NULL)
    {
		lc = RegCreateKeyEx (HKEY_CURRENT_USER, keycr.c_str(), 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hkcr, &dwr);
		lc = RegOverridePredefKey (HKEY_CLASSES_ROOT, hkcr);

		lc = RegCreateKeyEx (HKEY_CURRENT_USER, keylm.c_str(), 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hklm, &dwr);
		lc = RegOverridePredefKey (HKEY_LOCAL_MACHINE, hklm);

		// Create a symbolic link from <keylm>\Software\Classes to <keycr>
		string keylm_software_classes = keylm + "\\Software\\Classes";
		lc = RegCreateKeyEx( hklm, "Software", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hklm_sw, &dwr ) ;
		lc = DeleteSymLink (HKEY_CURRENT_USER, keylm_software_classes.c_str(), 0L ) ;
		lc = CreateSymLinkKey ( HKEY_CURRENT_USER, keylm_software_classes.c_str(), &hklm_link, 0 ) ;
		lc = SetSymLink ( hklm_link, HKEY_CURRENT_USER, keycr.c_str(), 0 ) ;

		HRESULT hr = CoInitialize (NULL);	// Someone has to call this
		ProcDllReg DLLRegisterServer =
		  (ProcDllReg)::GetProcAddress(hMod,"DllRegisterServer" ) ;
		HRESULT regResult = DLLRegisterServer() ;

		if (FAILED(regResult))
		{
			string regErrorText = WindowsErrorText(regResult) ;

			printf ( "DllRegisterServer failed with HRESULT 0x%08X, %s", regResult, regErrorText.c_str() ) ;

			CStdString	buf ;
			buf.Format ( "DllRegisterServer failed with HRESULT 0x%08X, %s", regResult, regErrorText.c_str() ) ;
			MessageBox ( NULL, buf.c_str(), comname.c_str(), MB_OK ) ;
		}

		// Delete the symbolic link and the Software key
		lc = DeleteSymLink ( HKEY_CURRENT_USER, keylm_software_classes.c_str(), 0L);
		lc = RegDeleteKey ( hklm, "Software" ) ;

		RegOverridePredefKey (HKEY_CLASSES_ROOT, NULL);
		RegOverridePredefKey (HKEY_LOCAL_MACHINE, NULL);
		RegCloseKey (hkcr);
		RegCloseKey (hklm);
	}
	else {
		MessageBox (NULL, "DllRegisterServer Not Exported", comname.c_str(), MB_OK);
	}
	// Delete the ATL Registrar key we put in the substitute
	DeleteAtlRegistrar();

	::FreeLibrary (hMod);
	return 1;
}


void ExportKey (HKEY hKey, string chrPrefix, string chrOrigKey, FILE* pFile)
{
  // JJB:  I also stole the bulk of this from the 'regxml' project.

  CHAR     achKey[MAX_KEY_LENGTH];    // buffer for subkey name
  DWORD    cbName;                    // size of name string
  CHAR     achClass[MAX_PATH] = "";   // buffer for class name
  DWORD    cchClassName = MAX_PATH;   // size of class string
  DWORD    cSubKeys = 0;              // number of subkeys
  DWORD    cbMaxSubKey;               // longest subkey size
  DWORD    cchMaxClass;               // longest class string
  DWORD    cValues;					  // number of values for key
  DWORD    cchMaxValue;				  // longest value name
  DWORD    cbMaxValueData;			  // longest value data
  DWORD    cbSecurityDescriptor;	  // size of security descriptor
  FILETIME ftLastWriteTime;			  // last write time

  DWORD	   i ;
  DWORD	   retCode ;

  // Get the class name and the value count.
  retCode = RegQueryInfoKey ( hKey,                    // key handle
							  achClass,                // buffer for class name
							  &cchClassName,           // size of class string
							  NULL,                    // reserved
							  &cSubKeys,               // number of subkeys
							  &cbMaxSubKey,            // longest subkey size
							  &cchMaxClass,            // longest class string
							  &cValues,                // number of values for this key
							  &cchMaxValue,            // longest value name
							  &cbMaxValueData,         // longest value data
							  &cbSecurityDescriptor,   // security descriptor
							  &ftLastWriteTime ) ;     // last write time

  // JJB:  Here's that sloppy global variable again.
  // I decided that we didn't need to put [HKEY_LOCAL_MACHINE] and
  // [HKEY_CLASSES_ROOT] into the export file because they're most definately
  // already in your registry.
  // I decided this because it freaking blows up on import if you redefine
  // [HKEY_CLASSES_ROOT] so there wasn't much decision in my "choice".
  if (g_currLevel != 0)
    fprintf (pFile, "[%s]\n", chrPrefix.c_str());

  // Enumerate the key values.
  if (cValues)
  {
	CHAR* achValue = new CHAR[MAX_VALUE_NAME];
	DWORD cchValue = MAX_VALUE_NAME;

	for (i = 0, retCode = ERROR_SUCCESS; i < cValues; i++)
    {
      cchValue    = MAX_VALUE_NAME;
      achValue[0] = '\0';

      BYTE* achValueData = new BYTE[cbMaxValueData + 1];
      DWORD dwType;
      DWORD cchValueData = cbMaxValueData + 1;

      retCode = RegEnumValue ( hKey,
							   i,
							   achValue,
							   &cchValue,
							   NULL,
							   &dwType,
							   (LPBYTE)achValueData,
							   &cchValueData ) ;

      if (retCode == ERROR_SUCCESS)
      {
        string strData = ConvertToString ( dwType, (LPTSTR)achValueData, cchValueData ) ;

        // JJB:  In the registry output format you don't put quotes around an @ which stands
        // for "default value"... but you do for the other properties.  Odd.
		if ( strlen(achValue) == 0 )
		{
		  fprintf (pFile, "@=\"%s\"\n", strData.c_str());
		}
		else
		{
		  fprintf (pFile, "\"%s\"=\"%s\"\n", achValue, strData.c_str());
		}
      }
      else
      {
        // JJB:  Proper error handling is for people without debuggers.
        printf("We had an error. Ooops.\n");
      }
    }

	// Free the achValue buffer, which is now allocated dynamically.
	delete[] achValue ;
  }

  if (g_currLevel != 0)
    fprintf (pFile, "\n");
  g_currLevel++;

  // JJB:  Now that we're listed the key, and all values under that
  // key it's time to start enumerating the children keys.

  // Enumerate the subkeys, until RegEnumKeyEx fails.
  if (cSubKeys)
  {
    for (i = 0; i < cSubKeys; i++)
    {
      cbName = MAX_KEY_LENGTH;
      retCode = RegEnumKeyEx(hKey, i,
        achKey,
        &cbName,
        NULL,
        NULL,
        NULL,
        &ftLastWriteTime);

      if (retCode == ERROR_SUCCESS)
      {
        // JJB:  No, I don't know why I kept on using char arrays when
        // writing this.
        CStdString  chrNewPrefix;
        string		chrChild = chrOrigKey + "\\" + achKey ;

        long lc;
        HKEY hkChild;
        DWORD dwr = 0;

        chrNewPrefix.Format ("%s\\%s", chrPrefix.c_str(), achKey);
        lc = RegCreateKeyEx (HKEY_CURRENT_USER, chrChild.c_str(), 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hkChild, &dwr);
        ExportKey (hkChild, chrNewPrefix, chrChild, pFile);
      }
    }
  }


}

int main(int argc, char* argv[])
{
	long lc;
	int retval = 0;
	HKEY hklm = 0;
	HKEY hkcr = 0;
	DWORD dwr=0;

	if ( argc <= 1 )
	{
		printf ( "Usage:\n") ;
		printf ( "Regspy <COM Component> [<exe-parameter>]\n" ) ;
		printf ( "  <exe-parameter> is passed as a command line parameter if <COM component> is an .exe files.\n" ) ;
		printf ( "  The default value is -regserver\n" ) ;
		printf ( "  It is not used for DLL/OCX components.\n" ) ;
		return 1;
	}

	// Get path, file name
	comname = argv[1] ;
	if ( argc > 2 )
		exeparm = argv[2] ;
	else
		exeparm = "-regserver" ;

	// Generate an output filename, simply by adding .reg to the original name.
	// For exampls scrrun.dll would become scrrun.dll.reg
	string strRegName = comname + ".reg" ;

	// MSVC generates a warning for fopen which in my humble opinion is nonsense.
#pragma warning( push )
#pragma warning( disable : 4996)

	// Open the output file
	FILE* pFile = fopen ( strRegName.c_str(), "w+" ) ;

#pragma warning( pop )

	if ( pFile == NULL )
	{
	  printf ( "Failed to open output file %s\n", strRegName.c_str() ) ;
	  return 1 ;
	}

	short stuff = GetFileTitle ( comname.c_str(), shortname, MAX_PATH ) ;

	// Build our substitute registry keys
	keycr = substituteKey + shortname + "\\HKCR" ;
	keylm = substituteKey + shortname + "\\HKLM" ;

	// Delete them if they exist - start with a clean slate
	SHDeleteKey (HKEY_CURRENT_USER, keycr.c_str());
	SHDeleteKey (HKEY_CURRENT_USER, keylm.c_str());

	if ( comname.find ( ".exe" ) != string::npos )
      retval = injectexe ( exeparm ) ;
    else
      retval = DoDll();

	// JJB:  I tried to make this look as much like a registry export as I could.
	fprintf ( pFile, "Windows Registry Editor Version 5.00\n\n" ) ;

	lc = RegCreateKeyEx (HKEY_CURRENT_USER, keylm.c_str(), 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hklm, &dwr);

	// JJB: Look inside the ExportKey() function for why I reset this.
	g_currLevel = 0;
	// JJB: Recursively spit out the vaules under what 'hklm' points to and force the output to
	// pretend that the values are under 'HKEY_LOCAL_MACHINE'.
	// the 3rd paramter is the textual value of what hklm points to.  I'm lazy... and this was the
	// easy way.
	ExportKey ( hklm, "HKEY_LOCAL_MACHINE", keylm, pFile );

	lc = RegCreateKeyEx (HKEY_CURRENT_USER, keycr.c_str(), 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hkcr, &dwr);

	g_currLevel = 0;
	ExportKey ( hkcr, "HKEY_CLASSES_ROOT", keycr, pFile ) ;

	// Close the file
	fclose ( pFile ) ;
	pFile = NULL ;

	printf ( "Reg file created: %s\n", strRegName.c_str()) ;

	return retval;
}