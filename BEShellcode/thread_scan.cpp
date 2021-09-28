#include "thread_scan.h"

void thread_scan::scan_threads(){
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
	if (hSnap != INVALID_HANDLE_VALUE) {
		THREADENTRY32 lpe32;
		lpe32.dwSize = sizeof(THREADENTRY32);
		if (Thread32First(hSnap, &lpe32)) {
			do {
				if (lpe32.th32OwnerProcessID == GetCurrentProcessId()) {
					HANDLE thread_handle = OpenThread(0xA, 0, lpe32.th32ThreadID);
					if (thread_handle != INVALID_HANDLE_VALUE) {
						DWORD result = ResumeThread(thread_handle);
						if (result && result != -1) {
							SuspendThread(thread_handle);
							beshellcode::report(beshellcode::report_ids::SuspendedThread);
						}
						CONTEXT thread_context;
						thread_context.ContextFlags = CONTEXT_ALL;
						if (GetThreadContext(thread_handle, &thread_context)) {
							MEMORY_BASIC_INFORMATION mbi{ 0 };
							size_t return_length{ 0 };
							if (
								(NtQueryVirtualMemory((HANDLE)-1, (PVOID)thread_context.Rip, MemoryBasicInformation, &mbi, sizeof(mbi), &return_length) < 0) ||
								mbi.State != MEM_COMMIT ||
								mbi.Type != MEM_IMAGE && mbi.RegionSize > 0x2000) {
								beshellcode::report(beshellcode::report_ids::IllegalRip);
							}					
						}
						CloseHandle(thread_handle);

					}
				}
			} while (Thread32Next(hSnap, &lpe32));
		}
		CloseHandle(hSnap);
	}
}
