# Process Explorer vulnerable driver PPL Bypass
While it is well known that old versions (before 17.x) of SysInternals Process Explorer drivers (PSEXP152.sys) are vulnerable and can be abused to open full access process handles to PPL processes (IOCTL: 0x8335003c), newer versions (17.x upward) are still vulnerable and capable of doing the same with a different driver function (IOCTL: 0x83350014).
This IOCTL function duplicates arbitrary handles and also got a patch to filter the system process and any protected process (PP/PPL) in driver version 17.00. But there was a major oversight with this function, as it was still possible to duplicate any process and thread handle from your own non-PPL process. Just opening a PPL process with low permissions like PROCESS_QUERY_LIMITED_INFORMATION and then duplicating this handle from your own process via Process Explorer driver was enough to bypass the filter and receiving a full access handle to a PPL process.
I used this method years ago to bypass PPL process protection, but Microsoft patched this bypass with driver version 17.11 by checking now if the target handle is a PPL process or thread handle. Still, driver versions from 17.00 up to 17.09 (17.10 does not exist) are not included in Microsoft's vulnerable driver blocklist and I suspect some EDR vendors also don't flag these versions (for now).

This is just PoC implementation to kill PPL processes. The same powerful handle duplication IOCTL can also be used to duplicate other handle types like threads and to inject shellcode in other PPL processes.

    Usage:
	1. Download older SysInternals Process Explorer (17.00 to 17.10)
	2. Run procexp64.exe as administrator to load the vulnerable driver
	3. Look in Process Explorer for the PID of for example MsMpEng.exe (ex: 3660)
	4. Run ps_ppl_bypass.exe PID ("ps_ppl_bypass.exe 3660") as administrator to kill the target process

It is also still possible to get an old driver version from offical SysInternals website by extracting it from SysInternals Handles tool: https://learn.microsoft.com/en-us/sysinternals/downloads/handle
