#pragma once
#include <Windows.h>
#include <iostream>
#include <tuple>
#include <vector>
#include "veh.h"
#include "systhreadfinder.h"
#include "misc.h"
#include "modules.h"
#include "sigs.h"
#include "thread_scan.h"
namespace beshellcode {
	enum class report_ids : uint8_t {
		IllegaleCaller, //BE -> 0x43
		HiddenSystemThread,
		KiUserExceptionDispatcherHook,
		BlacklistedDll,
		BlacklistedDriver,
		PatchedFunction,
		HitSignature,
		SuspendedThread,
		IllegalRip

	};
	void report(report_ids report_id);
	HANDLE add_exception_handler();
	void remove_exception_handler(HANDLE handle);
	void find_system_threads();
	void check_KiUserExceptionDispatcher_hook();
	void check_modules();
	void function_integrity();
	void scan_sigs();
	void scan_threads();
}