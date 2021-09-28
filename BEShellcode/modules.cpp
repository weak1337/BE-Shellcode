#include "modules.h"
std::vector<std::string>black_list_dlls{
	"..\\..\\Plugins\\ZipUtility\\ThirdParty\\7zpp\\dll\\Win64\\7z.dll",
	"hal.dll",
	"nvToolsExt64_1.dll",
	"ws2detour_x96.dll",
	"networkdllx64.dll",
	"nxdetours_64.dll",
	"nvcompiler.dll",
	"wmp.dll",
	"Project1.dll",
	"RompseAssPussy.dll", //wtf
	"DxtoryMM_x64.dll",
	"mslib.dll",
	"C:\\Windows\\mscorlib.ni.dll",
	"frAQBc8W.dll",
	//some checks on OwClientdll
	"shimloader64.dll",
	"BE_DLL.dll"
};
std::vector<std::string>black_list_driver{
	"\\\\.\\Beep",
	"\\\\.\\Null"
};
void module_check::check_modules() {
	for(auto current_module: black_list_dlls){
		if (GetModuleHandleA(current_module.c_str())) {
			beshellcode::report(beshellcode::report_ids::BlacklistedDll);
		}
	}
	for (auto current_driver : black_list_driver) {
		if (CreateFileA(current_driver.c_str(), 0x80000000, 3, 0, 3, 0, 0) != INVALID_HANDLE_VALUE) {
			beshellcode::report(beshellcode::report_ids::BlacklistedDriver);
		}
	}
	uintptr_t gameoverlaybase = (uintptr_t)GetModuleHandleA("gameoverlayrenderer64.dll");
	if (gameoverlaybase) {
		PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(gameoverlaybase + ((PIMAGE_DOS_HEADER)gameoverlaybase)->e_lfanew);
		if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0x2000) {
			beshellcode::report(beshellcode::report_ids::BlacklistedDll);
		}
	}

}