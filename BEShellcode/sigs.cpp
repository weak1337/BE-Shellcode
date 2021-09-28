#include "sigs.h"

std::vector<std::string>string_signatures{
	"ojects\\PUBGChinese",
	"BattleGroundsPrivate_CheatESP",
	"Neck",
	"Chest",
	"Mouse 1",
	"PlayerESPColor",
	"HackMachine",
	"VisualHacks.net",
	".rdata$zzzdbg",
	"D3D11Present initialised",
	"[ %.0fM ]",
	"[hp:%d]%dm",
	"d$8",
	"POSITION",
	"%s",
	"%d",
	"POSITION",
	"COLOR",
	"\n<assembly xmlns='urn:schemas-mi"
};

bool hit_sig(uintptr_t base, DWORD size) {
	for (auto curr_sig : string_signatures) {
		if (nt::scanpattern<uintptr_t>((BYTE*)base, size, (char*)curr_sig.c_str(), 0)) {
			printf("HIT SIG: %s\n", curr_sig.c_str());
			return true;
		}
	}
	return false;
}

void signatures::scan_sigs() {
	uintptr_t limit = (uintptr_t)GetModuleHandleA(0);
	uintptr_t curr_page_addy = 0x0;
	do {
		MEMORY_BASIC_INFORMATION mbi{ 0 };
		size_t return_length{ 0 };
		if (NtQueryVirtualMemory((HANDLE)-1, (PVOID)curr_page_addy, MemoryBasicInformation, &mbi, sizeof(mbi), &return_length) == 0) {
			if (
				mbi.State == MEM_COMMIT &&
				((mbi.Protect == PAGE_EXECUTE) || (mbi.Protect == PAGE_EXECUTE_READ) || (mbi.Protect == PAGE_EXECUTE_READWRITE))
				// && membase < beshellcode || membase > beshellcode
				)
			{
				if (mbi.Type == MEM_MAPPED || mbi.Type == MEM_PRIVATE) {
					if (hit_sig(curr_page_addy, mbi.RegionSize)) {
						beshellcode::report(beshellcode::report_ids::HitSignature);
					}
				}

			}
		}
		curr_page_addy = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
	} while (curr_page_addy < 0x7FFFFFFF0000);
	
}