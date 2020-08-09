# RegSpy

RegSpy is a tool to extract the COM (or ActiveX) registration information from:
* COM DLLs (.dll, .ocx)
* COM Exe-Servers (.exe)
* COM Type Libraries

This is the information entered into the registry when the component 
is registered using RegSvr32 (for DLLs) or by specifying the -regserver
command line parameter (for EXE files).

## Usage
The basic usage is
```
RegSpy <COM component>
```
where `<COM component>` is the path to the DLL, EXE or TLB file.

RegSpy generates a .Reg File in the format used by the Windows 
Registry Editor, RegEdit. The output file is generated in the same 
directory as the input file, with the additional extension .reg.

For example, if the input file is
```
c:\MyProject\MyComponent.dll
```
then the output file will be
```
c:\MyProject\MyComponent.dll.reg
```
### Admin rights

RegSpy requires admin rights to execute.

My experience is that not all of the registration information is 
generated if RegSpy is exeduted without admin rights. In particular,
the class registration (under HKEY_CLASSES_ROOT\CLSID) is generated, 
but the type library registration (under HKEY_CLASSES_ROOT\TypeLib)
is not generated. At least this seems to be true for ATL/C++ components.

## Acknowledgments

The original version of RegSpy was written by **Phil Wilson**.  
It was extended to output the .reg format (to stdout) by **Justin Buist**.

Justin Buist acknowledges that he used the function ConvertToString 
from a project he refers to as 'regxml', which I believe is the project
[Import/Export registry sections as XML](https://www.codeproject.com/Articles/3105/Import-Export-registry-sections-as-XML)
by **Stephane Rodriguez**.

This is the version which I downloaded from in
[the file RegSpy2.zip](http://www.installsite.org/files/iswi/RegSpy2.zip)
from 
[Install Site](http://www.installsite.org/pages/en/tt_analyze.htm).

In addition, I have used code from the project
[Registry Symbolic Links](https://www.codeproject.com/Articles/11973/Registry-Symbolic-Links)
by **Stefan Kuhr** and the 
[CStdString class](https://github.com/lunakid/CStdString)
originally by **Joe O'Leary**, helped by many people listed in the file.