#include "beshellcode.h"

int thread_main(HMODULE dll) {
    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);
    printf("Detections:\n");
    beshellcode::find_system_threads();
    beshellcode::check_KiUserExceptionDispatcher_hook();
    beshellcode::check_modules();
    beshellcode::function_integrity();
    beshellcode::scan_threads();
    HANDLE handler = beshellcode::add_exception_handler(); //Shellcode is called multiple times. Hook will be restored after first call
    beshellcode::scan_sigs();
    system("pause");
    beshellcode::remove_exception_handler(handler);
    fclose(f);
    FreeConsole();
    FreeLibraryAndExitThread(dll, 0);
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  
    DWORD fdwReason,     
    LPVOID lpReserved) 
{

    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(0, 0, (LPTHREAD_START_ROUTINE)thread_main, hinstDLL, 0, 0);
        break;
    }
    return TRUE;

}
