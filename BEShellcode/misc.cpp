#include "misc.h"

void misc::check_KiUserExceptionDispatcher_hook() {
    DWORD* KiUserExceptionDispatcher = (DWORD*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "KiUserExceptionDispatcher");
    if (*KiUserExceptionDispatcher == 0x58B48FC)// Make sure its not patched
    {
        uintptr_t PointedTo = *(uintptr_t*)((char*)KiUserExceptionDispatcher + KiUserExceptionDispatcher[1] + 8);
        if (PointedTo)
        {
            MEMORY_BASIC_INFORMATION mbi{ 0 };
            size_t returnsize;
            if ((NtQueryVirtualMemory(
                (HANDLE)-1i64,
                (PVOID)(PointedTo & 0xFFFFFFFFFFFFF000ui64),
                MemoryBasicInformation,
                &mbi,
                sizeof(mbi),
                &returnsize
            ) < 0) || mbi.State == MEM_COMMIT && (mbi.Protect & 4) != 0) {
                beshellcode::report(beshellcode::report_ids::KiUserExceptionDispatcherHook);
            }

        }
    }
    else
        beshellcode::report(beshellcode::report_ids::KiUserExceptionDispatcherHook);
}

void misc::check_integrity() {
    WORD* mem_cpy = (WORD*)GetProcAddress(GetModuleHandleA("vcruntime140.dll"), "memcpy");
    WORD* mem_cmp = (WORD*)GetProcAddress(GetModuleHandleA("vcruntime140.dll"), "memcmp");
    if ((mem_cpy && *mem_cpy == 0x25FF) || (mem_cmp && *mem_cmp == 0x25FF)) {
        beshellcode::report(beshellcode::report_ids::PatchedFunction);
    }
    WORD* curr_thread_id = (WORD*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetCurrentThreadId");
    if (curr_thread_id && *curr_thread_id == 0x25FF) {
        beshellcode::report(beshellcode::report_ids::PatchedFunction);
    }
}
