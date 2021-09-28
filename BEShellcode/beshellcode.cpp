#include "beshellcode.h"
void beshellcode::report(report_ids report_id) {
	printf("Triggered report id: %x\n", report_id);
}

HANDLE beshellcode::add_exception_handler() {
	PVOID handler = AddVectoredExceptionHandler(1, veh::be_handler);
	if (handler != INVALID_HANDLE_VALUE) {
		HMODULE user32 = LoadLibraryA("USER32.dll");
		HMODULE kernel32 = LoadLibraryA("KERNEL32.dll");
		HMODULE win32u = LoadLibraryA("win32u.dll");
		HMODULE ntdll = LoadLibraryA("ntdll.dll");
		HMODULE ucrtbase = LoadLibraryA("ucrtbase.dll");
		
		veh::add_func((uintptr_t)GetProcAddress(user32, "GetAsyncKeyState"));	
		veh::add_func((uintptr_t)GetProcAddress(user32, "GetCursorPos"));
		veh::add_func((uintptr_t)GetProcAddress(kernel32, "IsBadReadPtr"));
		veh::add_func((uintptr_t)GetProcAddress(win32u, "NtUserGetAsyncKeyState"));
		veh::add_func((uintptr_t)GetProcAddress(user32, "GetForegroundWindow"));
		veh::add_func((uintptr_t)GetProcAddress(user32, "CallWindowProcW"));
		veh::add_func((uintptr_t)GetProcAddress(win32u, "NtUserPeekMessage"));
		veh::add_func((uintptr_t)GetProcAddress(ntdll, "NtSetEvent"));
		veh::add_func((uintptr_t)GetProcAddress(ucrtbase, "__stdio_common_vsprintf_s"));
		veh::add_func((uintptr_t)GetProcAddress(ucrtbase, "sqrtf"));
		
	
	}
	

	/*
	Some additional d3d11 + dxgi + game specific stuff
	*/
	return (HANDLE)handler;
}
void beshellcode::remove_exception_handler(HANDLE handle) {
	if(handle != INVALID_HANDLE_VALUE)
		RemoveVectoredExceptionHandler(handle);
}

void beshellcode::find_system_threads()
{
	if (systhreadfinder::found_sys_thread(10)) {
		report(report_ids::HiddenSystemThread);
	}
}

void beshellcode::check_KiUserExceptionDispatcher_hook() {
	misc::check_KiUserExceptionDispatcher_hook();
}
void beshellcode::check_modules() {
	module_check::check_modules();
}
void beshellcode::function_integrity() {
	misc::check_integrity();
}
void beshellcode::scan_sigs() {
	signatures::scan_sigs();
}
void beshellcode::scan_threads() {
	thread_scan::scan_threads();
}