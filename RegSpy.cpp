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

using namespace std;

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

typedef HINSTANCE (WINAPI *ProcLoadLibrary)(char*); 
typedef FARPROC (WINAPI *ProcGetProcAddress)(HMODULE, LPCSTR);
typedef HRESULT (STDAPICALLTYPE *ProcDllReg)() ; 
typedef DWORD  (STDAPICALLTYPE *ProcWaitForS)(HANDLE, DWORD);
typedef long (STDAPICALLTYPE *RegOver) (HKEY, HKEY);
typedef long (STDAPICALLTYPE *RegCreate) (HKEY, LPCTSTR, DWORD, LPTSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
typedef DWORD (WINAPI* ProcResume)(HANDLE); 


char keycr [MAX_PATH] = {"Software\\Substitute\\Registry\\"};
char keylm [MAX_PATH] = {"Software\\Substitute\\Registry\\"};

// JJB:  Sloppy global counter.
int g_currLevel = 0;

char shortname [MAX_PATH] = {0};
char comname [MAX_PATH] = {0};
char exeparm [MAX_PATH] = {0};

typedef struct parmstag {
	char kcr [MAX_PATH];
	char klm [MAX_PATH];
	ProcLoadLibrary	fnload;
	ProcGetProcAddress fnGetProc;
	ProcResume fnResume;
	ProcWaitForS fnWaitFor;
	char advdll [MAX_PATH];
	char regover [MAX_PATH];
	char regcreate [MAX_PATH];
	HANDLE hProcThread;

} myparms;

myparms parms;

#pragma check_stack (off) 

string ConvertToString(DWORD dwType, LPTSTR szRawBuffer, DWORD nLen)
{
	// JJB:  Yep, I stole this from 'regxml'.  The author's copyright seems to
	// allow me to do anything but print out his documentation and make a paper
	// airplane out of it so this should be allowed.

	CString s; // <-- JJB:  Sorry.

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
				CString sByte;
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
				CString sDword;
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
				CString sDword;
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

	// JJB:  I have a "thing" for std::base_string... it's my string of choice.
	std::string strRet((LPCTSTR)s);
	return (strRet);
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
	if (ERROR_FILE_NOT_FOUND==lr){
		MessageBox (NULL, "Unable to find ATL Registrar - Registration Might Fail", "Warning", MB_OK);
	}
	else
	{
		char clsid [MAX_PATH];
		char locatl [MAX_PATH];
		strcpy (clsid, keycr);	// The HKCR substitute
		strcat (clsid, "\\CLSID\\{44EC053A-400F-11D0-9DCD-00A0C90391D3}\\InprocServer32");		
		// We'll assume in here that all the ATL.DLL registry entries are present
		DWORD dwsz = sizeof (locatl);
		DWORD dwt = REG_SZ;
		lr = RegQueryValueEx (hkatl, NULL, NULL, &dwt, (BYTE*)locatl, &dwsz);		// Path to Dll
		HKEY hkclsid;
		DWORD dwr;
		//Write Clsid to our substitute HKCR 
		lr = RegCreateKeyEx (HKEY_CURRENT_USER, clsid, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hkclsid, &dwr);
		// Set the InprocServer32 key value
		lr = RegSetValueEx (hkclsid, NULL, 0, REG_SZ, (BYTE*)locatl, dwsz);
		//Get and set the ThreadingModel 
		lr = RegQueryValueEx (hkatl, "ThreadingModel", NULL, &dwt, (BYTE*)locatl, &dwsz);
		lr = RegSetValueEx (hkclsid, "ThreadingModel", 0, REG_SZ, (BYTE*)locatl, dwsz);
		RegCloseKey (hkatl);
		RegCloseKey (hkclsid);
	}
}

void DeleteAtlRegistrar ()
{
	char delclsid [MAX_PATH];
	strcpy (delclsid, keycr);
	strcat (delclsid, "\\CLSID\\{44EC053A-400F-11D0-9DCD-00A0C90391D3}");
	SHDeleteKey (HKEY_CURRENT_USER, delclsid);
}

int injectexe(char* parm)
{
	
	// Copy the keys to the structure that we'll send to our remote thread
	strcpy (parms.kcr, keycr);
	strcpy (parms.klm, keylm);

	// GetProcAddress values for the functions that our remote thread will call. 
	HMODULE hk = LoadLibrary ("kernel32.dll");
	parms.fnload = (ProcLoadLibrary)::GetProcAddress (hk, "LoadLibraryA"); 
	parms.fnGetProc = (ProcGetProcAddress)::GetProcAddress (hk, "GetProcAddress");
	parms.fnResume = (ProcResume)::GetProcAddress(hk, "ResumeThread"); 
	parms.fnWaitFor = (ProcWaitForS)::GetProcAddress (hk, "WaitForSingleObject"); 
	strcpy (parms.advdll, "advapi32.dll");

	// The Regxxx functions are in advapi32.dll which we'll load in our remote thread
	strcpy (parms.regcreate, "RegCreateKeyExA");
	strcpy (parms.regover, "RegOverridePredefKey");

	// Build a command line for the server & make sure we can find it and initialize for the remote thread
	char cmdline [MAX_PATH];
	strcpy (cmdline, comname); 

	strcat (cmdline, " ");
	strcat (cmdline, parm);
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
	const int cbCodeSize = (BYTE*)AfterThreadProc - (BYTE*)ThreadProc; 

	pcode = VirtualAllocEx (pi.hProcess, 0, cbCodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE); 
	// The process was created suspended and has done very little.
	// TerminateProcess is unfriendly but should be safe under these circumstances
	if (0==pcode)
	{
		MessageBox (NULL, "Allocate code memory in process", cmdline, MB_OK);
		goto cleanup;
	}
	pdata = VirtualAllocEx (pi.hProcess, 0, sizeof (parms), MEM_COMMIT, PAGE_EXECUTE_READWRITE); 
	if (0==pdata)
	{
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

	// At this point in time we're ready to set up the substitute registry entries 
	
	CreateAtlRegistrar();

	// Let the remote thread go 
	// JJB:  This throws a dialog box with a "File Not Found" error it in that I can't trace down.
	// Many thanks to somebody who can fix this or explain it to me.
	HANDLE ht = CreateRemoteThread (pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pcode, pdata, 0, NULL);
	long gle = GetLastError();
	dwr = WaitForSingleObject (pi.hThread, INFINITE);
	CloseHandle (pi.hThread);
	CloseHandle (pi.hProcess);
	WaitForSingleObject (ht, 10000);
	CloseHandle (ht);
	// Delete the ATL Registrar key we put in the substitute 
	DeleteAtlRegistrar();
	return 1;

}

int DoDll()
{
	// We're going to look for the ATL Registrar in case it's need for our server to register, and if it's there we'll
	// copy the key data to our subsitute HKCR key. 
	CreateAtlRegistrar();

	HMODULE hMod = ::LoadLibrary (comname);
	if (NULL==hMod){
		MessageBox (NULL, "Can't Find", comname, MB_OK);		
		return 1;
	}
	HKEY hklm = 0;
	HKEY hkcr = 0;
	DWORD dwr=0;
	// Find DllregisterServer, prepare to call it 
	ProcDllReg DLLRegisterServer = (ProcDllReg)::GetProcAddress(hMod,"DllRegisterServer" ) ;
	if (DLLRegisterServer != NULL)
    {
		long lc = RegCreateKeyEx (HKEY_CURRENT_USER, keycr, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hkcr, &dwr);
		lc = RegOverridePredefKey (HKEY_CLASSES_ROOT, hkcr);

		lc = RegCreateKeyEx (HKEY_CURRENT_USER, keylm, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hklm, &dwr);
		lc = RegOverridePredefKey (HKEY_LOCAL_MACHINE, hklm);
		CoInitialize (NULL);	// Someone has to call this
		ProcDllReg DLLRegisterServer =
		  (ProcDllReg)::GetProcAddress(hMod,"DllRegisterServer" ) ;
		HRESULT regResult = DLLRegisterServer() ;
		RegOverridePredefKey (HKEY_CLASSES_ROOT, NULL);
		RegOverridePredefKey (HKEY_LOCAL_MACHINE, NULL);
		RegCloseKey (hkcr);
		RegCloseKey (hklm);
	}
	else {
		MessageBox (NULL, "DllRegisterServer Not Exported", comname, MB_OK);
	}
	// Delete the ATL Registrar key we put in the substitute 
	DeleteAtlRegistrar();

	::FreeLibrary (hMod);
	return 1;
}


void ExportKey(HKEY hKey, char chrPrefix[MAX_PATH], char chrOrigKey[MAX_PATH]) 
{ 
	// JJB:  I also stole the bulk of this from the 'regxml' project.
	
	CHAR     achKey[MAX_KEY_LENGTH];   // buffer for subkey name
    DWORD    cbName;                   // size of name string 
    CHAR     achClass[MAX_PATH] = "";  // buffer for class name 
    DWORD    cchClassName = MAX_PATH;  // size of class string 
    DWORD    cSubKeys=0;               // number of subkeys 
    DWORD    cbMaxSubKey;              // longest subkey size 
    DWORD    cchMaxClass;              // longest class string 
    DWORD    cValues;              // number of values for key 
    DWORD    cchMaxValue;          // longest value name 
    DWORD    cbMaxValueData;       // longest value data 
    DWORD    cbSecurityDescriptor; // size of security descriptor 
    FILETIME ftLastWriteTime;      // last write time 
 
    DWORD i, retCode; 
 
    CHAR  achValue[MAX_VALUE_NAME]; 
    DWORD cchValue = MAX_VALUE_NAME; 
 

	// Get the class name and the value count. 
    retCode = RegQueryInfoKey(
        hKey,                    // key handle 
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
        &ftLastWriteTime);       // last write time  

	// JJB:  Here's that sloppy global variable again.
	// I decided that we didn't need to put [HKEY_LOCAL_MACHINE] and
	// [HKEY_CLASSES_ROOT] into the export file because they're most definately
	// already in your registry.
	// I decided this because it freaking blows up on import if you redefine
	// [HKEY_CLASSES_ROOT] so there wasn't much decision in my "choice".
	if (g_currLevel != 0)
		printf("[%s]\n", chrPrefix);

    // Enumerate the key values. 
    if (cValues) 
    {
        for (i=0, retCode=ERROR_SUCCESS; i<cValues; i++) 
        { 
			cchValue = MAX_VALUE_NAME;
            achValue[0] = '\0'; 
		    BYTE  *achValueData = new BYTE[cbMaxValueData + 1];
			DWORD dwType;
			DWORD cchValueData = cbMaxValueData + 1;

			retCode = RegEnumValue(hKey, i, 
                achValue, 
                &cchValue, 
                NULL, 
                &dwType,
                (LPBYTE) achValueData,
                &cchValueData);
 
            if (retCode == ERROR_SUCCESS) 
            {
				if (strlen(achValue) == 0)
					strcpy(achValue, "@");

				string strData = ConvertToString(dwType, (LPTSTR) achValueData, cchValueData);
				// JJB:  In the registry output format you don't put quotes around an @ which stands
				// for "default value"... but you do for the other properties.  Odd.
				if (strcmp(achValue, "@") == 0) 
					printf("%s=\"%s\"\n", achValue,  strData.c_str());
				else
					printf("\"%s\"=\"%s\"\n", achValue, strData.c_str());
			}
			else
			{
				// JJB:  Proper error handling is for people without debuggers.
				printf("We had an error. Ooops.\n");
			}
        }
    }

	if (g_currLevel != 0)
		printf("\n");
	g_currLevel++;

	// JJB:  Now that we're listed the key, and all values under that
	// key it's time to start enumerating the children keys.

	// Enumerate the subkeys, until RegEnumKeyEx fails.
    if (cSubKeys)
    {
        for (i=0; i<cSubKeys; i++) 
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
				char chrNewPrefix[MAX_PATH];
				char chrChild[MAX_PATH];
				strcpy(chrChild, chrOrigKey);
				strcat(chrChild, "\\");
				strcat(chrChild, achKey);

				long lc;
				HKEY hkChild;
				DWORD dwr = 0;

				sprintf(chrNewPrefix, "%s\\%s", chrPrefix, achKey);
				lc = RegCreateKeyEx (HKEY_CURRENT_USER, chrChild, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hkChild, &dwr);
				ExportKey(hkChild, chrNewPrefix, chrChild);
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

	if (argc <=1){
		MessageBox (NULL, "No File Specified in Command Line", "Error", MB_OK);
		return 1;
	}
	// Get path, file name
	strcpy (comname, argv[1]);
	if (argc > 2) 
		strcpy (exeparm, argv[2]);	
	else 
		strcpy (exeparm, "-regserver");

	short stuff = GetFileTitle (comname, shortname, MAX_PATH);
	// Build our substitute registry keys 
	strcat (keycr, shortname);
	strcat (keycr, "\\HKCR");
	strcat (keylm, shortname);
	strcat (keylm, "\\HKLM");

	// Delete them if they exist - start with a clean slate 
	SHDeleteKey (HKEY_CURRENT_USER, keycr);
	SHDeleteKey (HKEY_CURRENT_USER, keylm);

	char *pdest;
	pdest = strstr (comname, ".exe");
	if (pdest!=NULL)
	{
		retval = injectexe(exeparm);
	}
	else
		retval = DoDll();

	char chrRootKey[MAX_PATH];

	// JJB:  I tried to make this look as much like a registry export as I could.
	printf("Windows Registry Editor Version 5.00\n\n");

	strcpy(chrRootKey, "");
	strcat(chrRootKey, keylm);
	lc = RegCreateKeyEx (HKEY_CURRENT_USER, keylm, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hklm, &dwr);

	// JJB: Look inside the ExportKey() function for why I reset this.  
	g_currLevel = 0;
	// JJB: Recursively spit out the vaules under what 'hklm' points to and force the output to
	// pretend that the values are under 'HKEY_LOCAL_MACHINE'.
	// the 3rd paramter is the textual value of what hklm points to.  I'm lazy... and this was the
	// easy way.
	ExportKey(hklm, "HKEY_LOCAL_MACHINE", chrRootKey);

	strcpy(chrRootKey, "");
	strcat(chrRootKey, keycr);
	lc = RegCreateKeyEx (HKEY_CURRENT_USER, keycr, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hkcr, &dwr);

	g_currLevel = 0;
	ExportKey(hkcr, "HKEY_CLASSES_ROOT", chrRootKey);

	return retval;
}