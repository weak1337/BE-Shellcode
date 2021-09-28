#pragma once
#include <Windows.h>
#include "nt.h"
#include "beshellcode.h"
namespace misc {
	void check_KiUserExceptionDispatcher_hook();
	void check_integrity();
}