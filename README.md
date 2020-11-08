# MsiAnalyzer
Project to analyze a msi files without msi.dll

The purpose of the project is allow to extraction of information about actions in msi file, withou use msi.dll. It allows use it on different platforms, not only on windows. MsiAnlyzer :
 -report file "msiAnalysisReport.txt" (if "CustomAction" table is present)
 -create "scripts" folder with extracted scripts (if it contains any)
 
### How to build:
 //todo
 
### How to use:
 
 -input:
 MsiAnalyzer.exe <inpu_msi_file>

-output:
 "msiAnalysisReport.txt" and "scripts" folder
