#pragma once
#include <Windows.h>
#include "nt.h"

namespace systhreadfinder {
	bool found_sys_thread(int depth);
}