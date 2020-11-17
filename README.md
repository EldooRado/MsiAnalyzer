# MsiAnalyzer
Project to analyze a msi files without msi.dll

The purpose of the project is allow to extraction of information about actions in msi file, withou use msi.dll. It allows use it on different platforms, not only on windows.
 
### How to build:
 WINDOWS: open MsiAnalyzer.sln and build.
 LINUX: invoke "make" command in directory with "Makefile"
 
 IMPORTANT: cpp17 standard is used (std::filesystem)
 
### How to use:
 
 1) input:
 MsiAnalyzer.exe <inpu_msi_file> or
 MsiAnalyzer.exe <msi_file> <output_dir>

2) output:
 <output_dir> with:
  - "tables" dir
  - "analyzeReport.txt" file, which contains summary of analyze
  - "script" dir (if any script is present)
  - "files" dir (if any embedded file is present)
  - "actions.txt" (if any customAction is present)

### Msi samples:
https://drive.google.com/drive/folders/1B--x_qQctYGTiS4wX0X0kJFCF62LvIWs?usp=sharing

### To do:
1. Max size of msi to anazlyze is MAX_DWORD_VALUE, because I used DWORD's to store file offsets. It can be good idea to change it to QWORD's
2. Add releases tab in github
3. There is possibility to overrite files. If someone add "ScriptPreamble.ps1" script to msi, then there is possiblity that overwriting.
4. Anlyze more tools to msi producing.
5. Add cmake
