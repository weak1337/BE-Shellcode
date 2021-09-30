#include "nt.h"
int* nt::get_proc_list() {
	int* proc_list = NULL;
	ULONG proc_list_size = 0;
	NtQuerySystemInformation(SystemProcessInformation, proc_list, proc_list_size, &proc_list_size);
	int* buf = (int*)realloc(proc_list, proc_list_size);
	if (buf == NULL)
		return NULL;
	else
		proc_list = buf;
	NtQuerySystemInformation(SystemProcessInformation, proc_list, proc_list_size, &proc_list_size);
	return proc_list;
}
int* nt::get_driver_list() {
	int* driver_list = NULL;
	ULONG driver_list_size = 0;
	NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0xB, 0, driver_list_size, &driver_list_size);
	int* buf = (int*)realloc(driver_list, driver_list_size);
	if (buf == NULL)
		return NULL;
	else
		driver_list = buf;
	NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0xB, driver_list, driver_list_size, &driver_list_size);
	return driver_list;
}
std::vector<nt_modules>nt::get_module_list() {
	std::vector<nt_modules> modules_to_return;

	PPEB peb = (PPEB)__readgsqword(0x60);
	PPEB_LDR_DATA ldr = peb->Ldr;
	PLDR_DATA_TABLE_ENTRY current_module = NULL;
	PLIST_ENTRY list = ldr->InLoadOrderModuleList.Flink;
	while (list != NULL && list != &ldr->InLoadOrderModuleList) {
		current_module = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		nt_modules new_nt_module;
		new_nt_module.base = (uintptr_t)current_module->DllBase;
		new_nt_module.size = current_module->SizeOfImage;
		modules_to_return.push_back(new_nt_module);
		list = list->Flink;
	}
	return modules_to_return;
}