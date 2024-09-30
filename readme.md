# Project Summary

### Summary

**English:**

### Project Description: kill wdf.cpp

**Objective:**
The project aims to disable Windows Defender (WDF) by leveraging the TrustedInstaller service, which requires elevated privileges to manipulate. The code provided is a C++ program designed to run with System-level permissions, impersonate the TrustedInstaller service, and then execute commands to disable Windows Defender.

**Key Features:**

1. **Privilege Elevation:**
   - The program first ensures it is running with System privileges.
   - It then elevates its privileges to become the TrustedInstaller, which is necessary to modify Windows Defender settings.

2. **Impersonation:**
   - The program impersonates the TrustedInstaller service by duplicating its token and using it to create a new process.
   - This allows the program to execute commands with the elevated privileges of the TrustedInstaller.

3. **Service Manipulation:**
   - The program interacts with the Windows Service Control Manager (SCM) to query and manage the TrustedInstaller service.
   - It checks the status of the TrustedInstaller service and starts it if necessary.

4. **Process Creation:**
   - The program creates a new process with the TrustedInstaller's privileges, enabling it to execute commands that modify Windows Defender settings.
   - This is done using the `CreateProcessWithTokenW` function, which allows the creation of a new process with the security context of a specified token.

5. **Error Handling:**
   - The program includes detailed error handling using the `GetLastErrorAsString` function, which provides detailed error messages for debugging purposes.

**Usage:**
- The program can be run with or without command-line arguments.
- If no arguments are provided, it defaults to launching a PowerShell command.
- If arguments are provided, they are passed directly to the new process created with TrustedInstaller privileges.

**Dependencies:**
- The program relies on several Windows API functions and libraries, including `Userenv.lib`, `Shlwapi.lib`, `Advapi32.lib`, and `Shell32.lib`.

**Security Considerations:**
- The program requires administrative privileges to run and is designed to operate at the System level, making it potentially dangerous if misused.
- It is intended for educational or diagnostic purposes and should be handled with care to avoid unintended system modifications.

**GitHub References:**
- The project references several GitHub repositories that provide additional methods and scripts for disabling Windows Defender, including:
  - [AveYo/LeanAndMean](https://github.com/AveYo/LeanAndMean/blob/main/ToggleDefender.ps1)
  - [awuctl/tirun](https://github.com/awuctl/tirun)
  - [NYAN-x-CAT/disable_windowsdefend](https://github.com/NYAN-x-CAT/disable_windowsdefend)
  - [xbebhxx3/x3-DefenderRemove](https://github.com/xbebhxx3/x3-DefenderRemove)

**Conclusion:**
The `kill wdf.cpp` project is a sophisticated tool for disabling Windows Defender by leveraging the TrustedInstaller service. It requires careful handling due to its high-privilege operations and is intended for advanced users or developers working on system-level modifications.

**Chinese:**

### 项目描述：kill wdf.cpp

**目标：**
该项目旨在通过利用TrustedInstaller服务来禁用Windows Defender（WDF），这需要提升的权限才能进行操作。提供的代码是一个C++程序，设计为以系统级权限运行，模拟TrustedInstaller服务，然后执行命令以禁用Windows Defender。

**主要功能：**

1. **权限提升：**
   - 程序首先确保其以系统权限运行。
   - 然后将其权限提升为TrustedInstaller，这是修改Windows Defender设置所必需的。

2. **模拟：**
   - 程序通过复制TrustedInstaller服务的令牌并使用它来创建新进程，从而模拟TrustedInstaller服务。
   - 这使得程序能够以TrustedInstaller的提升权限执行命令。

3. **服务操作：**
   - 程序与Windows服务控制管理器（SCM）交互，以查询和管理TrustedInstaller服务。
   - 它会检查TrustedInstaller服务的状态，并在必要时启动它。

4. **进程创建：**
   - 程序使用TrustedInstaller的权限创建新进程，使其能够执行修改Windows Defender设置的命令。
   - 这是通过`CreateProcessWithTokenW`函数完成的，该函数允许使用指定令牌的安全上下文创建新进程。

5. **错误处理：**
   - 程序包含详细的错误处理，使用`GetLastErrorAsString`函数提供详细的错误消息，以便调试。

**使用方法：**
- 程序可以在有或没有命令行参数的情况下运行。
- 如果没有提供参数，它默认启动一个PowerShell命令。
- 如果提供了参数，它们将直接传递给使用TrustedInstaller权限创建的新进程。

**依赖项：**
- 程序依赖于多个Windows API函数和库，包括`Userenv.lib`、`Shlwapi.lib`、`Advapi32.lib`和`Shell32.lib`。

**安全考虑：**
- 程序需要管理员权限才能运行，并且设计为在系统级别操作，如果被滥用，可能会带来潜在危险。
- 它旨在用于教育或诊断目的，应谨慎处理以避免意外的系统修改。

**GitHub参考：**
- 该项目参考了多个GitHub仓库，提供了额外的禁用Windows Defender的方法和脚本，包括：
  - [AveYo/LeanAndMean](https://github.com/AveYo/LeanAndMean/blob/main/ToggleDefender.ps1)
  - [awuctl/tirun](https://github.com/awuctl/tirun)
  - [NYAN-x-CAT/disable_windowsdefend](https://github.com/NYAN-x-CAT/disable_windowsdefend)
  - [xbebhxx3/x3-DefenderRemove](https://github.com/xbebhxx3/x3-DefenderRemove)

**结论：**
`kill wdf.cpp`项目是一个通过利用TrustedInstaller服务来禁用Windows Defender的复杂工具。由于其高权限操作，需要谨慎处理，适用于进行系统级修改的高级用户或开发者。

### Content

## File: kill wdf.cpp

```
﻿// trustedInstaller 挂掉wdf  二进制文件
/*
1.得先是system权限 只有system权限才能提升成为trustedInstaller权限
2.变成turstedinstaller有很多方法 但是不是所有的都可以用 根据最有用的那个来写吧
3.利用trustedinstaller来停止defender

 https://github.com/AveYo/LeanAndMean/blob/main/ToggleDefender.ps1
 https://github.com/awuctl/tirun
 https://github.com/NYAN-x-CAT/disable_windowsdefend
 https://github.com/xbebhxx3/x3-DefenderRemove

 */

#include <iostream>
#include <string>
#include <system_error>
#include <codecvt>
#include <Windows.h>
#include <userenv.h>
#include <Shlobj.h>
#include <shlwapi.h>
#include <TlHelp32.h>

#pragma comment(lib,"Userenv.lib")
#pragma comment(lib,"Shlwapi.lib")
#pragma comment(lib,"Advapi32.lib")
#pragma comment(lib,"Shell32.lib")

using namespace std;

#define FNERROR(prefix) GetLastErrorAsString(__FUNCTION__, prefix)
static void GetLastErrorAsString(const string fnk, const wstring prefix)
{
	DWORD errorMessageID = GetLastError();

	wcout << wstring(fnk.begin(), fnk.end()) << L"()->" << prefix << L" failed (" + to_wstring(errorMessageID) + L") ";

	LPWSTR messageBuffer = nullptr;
	if (FormatMessageW(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr,
		errorMessageID,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		reinterpret_cast<PWSTR>(&messageBuffer),
		0,
		nullptr)) {
		wcout << messageBuffer;
		LocalFree(messageBuffer);
	}

	wcout << endl;
}

static bool EnablePrivilege(const wstring privilegeName)
{
	HANDLE hToken = nullptr;
	BOOL res = FALSE;

	do {
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
			FNERROR(L"OpenProcessToken(GetCurrentProcess())");
			break;
		}

		LUID luid;
		if (!LookupPrivilegeValueW(nullptr, privilegeName.c_str(), &luid)) {
			FNERROR(L"LookupPrivilegeValueW('" + privilegeName + L"')");
			break;
		}

		TOKEN_PRIVILEGES tp = { 0 };
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (!(res = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))) {
			FNERROR(L"AdjustTokenPrivileges('" + privilegeName + L"')");
			break;
		}

	} while (false);

	if (hToken == nullptr)
		CloseHandle(hToken);

	return res;
}

static bool ImpersonateToProcess(const wstring processName)
{
	HANDLE hSnapshot = nullptr;
	HANDLE hSystemProcess = nullptr, hSystemToken = nullptr, hDupToken = nullptr;
	BOOL res = FALSE;

	do {

		if ((hSnapshot = CreateToolhelp32Snapshot(
			TH32CS_SNAPPROCESS,
			0)) == INVALID_HANDLE_VALUE) {
			FNERROR(L"CreateToolhelp32Snapshot()");
			break;
		}

		PROCESSENTRY32W pe = { 0 };
		pe.dwSize = sizeof(PROCESSENTRY32W);
		if (Process32FirstW(hSnapshot, &pe))
			while (Process32NextW(hSnapshot, &pe) && _wcsicmp(pe.szExeFile, processName.c_str()));
		else {
			FNERROR(L"Process32FirstW('" + processName + L"')");
			break;
		}

		if (_wcsicmp(pe.szExeFile, processName.c_str())) {
			FNERROR(L"Cant`t found process: " + processName);
			break;
		}

		if ((hSystemProcess = OpenProcess(
			PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
			FALSE,
			pe.th32ProcessID)) == nullptr) {
			FNERROR(L"OpenProcess('" + processName + L"')");
			break;
		}

		if (!OpenProcessToken(
			hSystemProcess,
			MAXIMUM_ALLOWED,
			&hSystemToken)) {
			FNERROR(L"OpenProcessToken('" + processName + L"')");
			break;
		}

		SECURITY_ATTRIBUTES tokenAttributes;
		tokenAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
		tokenAttributes.lpSecurityDescriptor = nullptr;
		tokenAttributes.bInheritHandle = FALSE;
		if (!DuplicateTokenEx(
			hSystemToken,
			MAXIMUM_ALLOWED,
			&tokenAttributes,
			SecurityImpersonation,
			TokenImpersonation,
			&hDupToken)) {
			FNERROR(L"DuplicateTokenEx('" + processName + L"')");
			break;
		}

		if (!(res = ImpersonateLoggedOnUser(hDupToken))) {
			FNERROR(L"ImpersonateLoggedOnUser('" + processName + L"')");
			break;
		}

	} while (false);

	if (hSystemProcess != nullptr)
		CloseHandle(hSystemProcess);

	if (hDupToken != nullptr)
		CloseHandle(hDupToken);

	if (hSnapshot != nullptr)
		CloseHandle(hSnapshot);

	return (bool)res;
}

static DWORD GetPidTrustedInstallerService()
{
	SC_HANDLE hSCManager = nullptr;
	SC_HANDLE hService = nullptr;
	DWORD dwProcessId = 0;
	BOOL res = TRUE, started = TRUE;

	do {

		if ((hSCManager = OpenSCManagerW(
			nullptr,
			SERVICES_ACTIVE_DATABASE,
			GENERIC_EXECUTE)) == nullptr) {
			FNERROR(L"OpenSCManagerW()");
			break;
		}

		if ((hService = OpenServiceW(
			hSCManager,
			L"TrustedInstaller",
			GENERIC_READ | GENERIC_EXECUTE)) == nullptr) {
			FNERROR(L"OpenServiceW('TrustedInstaller')");
			break;
		}

		SERVICE_STATUS_PROCESS statusBuffer = { 0 };
		DWORD bytesNeeded;
		while (dwProcessId == 0 &&
			started &&
			(res = QueryServiceStatusEx(
				hService,
				SC_STATUS_PROCESS_INFO,
				reinterpret_cast<LPBYTE>(&statusBuffer),
				sizeof(SERVICE_STATUS_PROCESS),
				&bytesNeeded))) {

			switch (statusBuffer.dwCurrentState) {
			case SERVICE_STOPPED:
				started = StartServiceW(hService, 0, nullptr);
				if (!started) {
					FNERROR(L"StartServiceW('TrustedInstaller'");
				}
				break;
			case SERVICE_START_PENDING:
			case SERVICE_STOP_PENDING:
				Sleep(statusBuffer.dwWaitHint);
				break;
			case SERVICE_RUNNING:
				dwProcessId = statusBuffer.dwProcessId;
				break;
			}
		}

		if (!res) {
			FNERROR(L"QueryServiceStatusEx('TrustedInstaller')");
		}

	} while (false);

	if (hService != nullptr)
		CloseServiceHandle(hService);

	if (hSCManager != nullptr)
		CloseServiceHandle(hSCManager);

	return dwProcessId;
}

static bool CreateProcessAsTrustedInstaller(LPWSTR cmd)
{
	if (!EnablePrivilege(SE_DEBUG_NAME) ||
		!EnablePrivilege(SE_IMPERSONATE_NAME) ||
		!ImpersonateToProcess(L"winlogon.exe"))
		return false;

	HANDLE hTIProcess = nullptr, hTIToken = nullptr, hDupToken = nullptr;
	HANDLE hToken = nullptr;
	LPVOID lpEnvironment = nullptr;
	LPWSTR lpBuffer = nullptr;
	BOOL res = FALSE;

	do {

		DWORD pid = GetPidTrustedInstallerService();
		if (!pid)
			break;

		if ((hTIProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, pid)) == nullptr) {
			FNERROR(L"OpenProcess('TrustedInstaller')");
			break;
		}

		if (!OpenProcessToken(hTIProcess, MAXIMUM_ALLOWED, &hTIToken)) {
			FNERROR(L"OpenProcessToken('TrustedInstaller')");
			break;
		}

		SECURITY_ATTRIBUTES tokenAttributes;
		tokenAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
		tokenAttributes.lpSecurityDescriptor = nullptr;
		tokenAttributes.bInheritHandle = FALSE;
		if (!DuplicateTokenEx(
			hTIToken,
			MAXIMUM_ALLOWED,
			&tokenAttributes,
			SecurityImpersonation,
			TokenImpersonation,
			&hDupToken)) {
			FNERROR(L"DuplicateTokenEx()");
			break;
		}

		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &hToken)) {
			FNERROR(L"OpenProcessToken(GetCurrentProcess())");
			break;
		}

		if (!CreateEnvironmentBlock(
			&lpEnvironment,
			hToken,
			TRUE)) {
			FNERROR(L"CreateEnvironmentBlock()");
			break;
		}

		DWORD nBufferLength = GetCurrentDirectoryW(0, nullptr);
		if (!nBufferLength)
			break;

		lpBuffer = (LPWSTR)(new wchar_t[nBufferLength] {0});
		if (!GetCurrentDirectoryW(nBufferLength, lpBuffer)) {
			FNERROR(L"GetCurrentDirectoryW()");
			break;
		}

		STARTUPINFOW startupInfo;
		ZeroMemory(&startupInfo, sizeof(STARTUPINFOW));
		startupInfo.lpDesktop = (LPWSTR)L"Winsta0\\Default";
		PROCESS_INFORMATION processInfo;
		ZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));
		res = CreateProcessWithTokenW(
			hDupToken,
			LOGON_WITH_PROFILE,
			nullptr,
			cmd,
			CREATE_UNICODE_ENVIRONMENT,
			lpEnvironment,
			lpBuffer,
			&startupInfo,
			&processInfo);
		if (!res) {
			FNERROR(wstring(L"CreateProcessWithTokenW('") + cmd + L"')");
		}

	} while (false);

	if (lpBuffer == nullptr)
		delete lpBuffer;

	if (lpEnvironment == nullptr)
		DestroyEnvironmentBlock(lpEnvironment);

	if (hToken == nullptr)
		CloseHandle(hToken);

	if (hDupToken == nullptr)
		CloseHandle(hDupToken);

	if (hTIToken == nullptr)
		CloseHandle(hTIToken);

	if (hTIProcess == nullptr)
		CloseHandle(hTIProcess);

	return (bool)res;
}

int wmain(int argc, wchar_t* argv[])
{
	setlocale(LC_CTYPE, "");

	if (!IsUserAnAdmin()) {

		wcout << L"Error: User is not admin." << endl;

		// wait in console for gui mode
		DWORD processList = 0;
		if (GetConsoleProcessList(&processList, 1) == 1)
			Sleep(5000);

		return 0;
	}

	try {

		if (argc == 1)
			CreateProcessAsTrustedInstaller((LPWSTR)L"powershell.exe /c ");
		else
			CreateProcessAsTrustedInstaller((LPWSTR)PathGetArgsW(GetCommandLineW()));

	}
	catch (exception excpt) {
		wcout << excpt.what() << endl;
	}

	return 1;
}

```

----------------------------------------

