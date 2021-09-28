#include "systhreadfinder.h"

bool systhreadfinder::found_sys_thread(int depth) {
	int iteration;
	uintptr_t idletime1, kerneltime1, usertime1;
	uintptr_t idletime2, kerneltime2, usertime2;
	uintptr_t deltatime1, deltatime2, deltatime3;

	SYSTEM_PROCESS_INFORMATION* proc1;
	SYSTEM_PROCESS_INFORMATION* proc2;
	for (iteration = 0; iteration < depth; iteration++) {
		int* proc_list_start = nt::get_proc_list();
		GetSystemTimes((PFILETIME)&idletime1, (PFILETIME)&kerneltime1, (PFILETIME)&usertime1);
		Sleep(1000);
		int* proc_list_end = nt::get_proc_list();
		GetSystemTimes((PFILETIME)&idletime2, (PFILETIME)&kerneltime2, (PFILETIME)&usertime2);

		deltatime1 = 0;
		for (proc2 = (SYSTEM_PROCESS_INFORMATION*)proc_list_end;; proc2 = (SYSTEM_PROCESS_INFORMATION*)((char*)proc2 + proc2->NextOffset)) {
			for (proc1 = (SYSTEM_PROCESS_INFORMATION*)proc_list_start; proc2->ProcessId != proc1->ProcessId; proc1 = (SYSTEM_PROCESS_INFORMATION*)((char*)proc1 + proc1->NextOffset)) {
				if (!proc1->NextOffset) {
					deltatime1 += *(uintptr_t*)&proc2->KernelTime + *(uintptr_t*)&proc2->UserTime;
					goto END;
				}
			}
			deltatime2 = *(uintptr_t*)&proc2->KernelTime - *(uintptr_t*)&proc1->KernelTime + *(uintptr_t*)&proc2->UserTime - *(uintptr_t*)&proc1->UserTime;
			deltatime1 += deltatime2;
		END:
			if (!proc2->NextOffset)
				break;
		}
		deltatime3 = usertime2 - usertime1 + kerneltime2 - kerneltime1 - deltatime1;
		if (deltatime3 < 0x7270E0)
			break;
		free(proc_list_start);
		free(proc_list_end);
	}

	return iteration == depth;
}