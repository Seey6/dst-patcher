#define _IMAGEHLP_SOURCE_

#include <windows.h>

#define MiniDumpWriteDump DstMemPatchSystemMiniDumpWriteDump
#include <dbghelp.h>
#undef MiniDumpWriteDump

#include <string.h>

#include "dst_mem_patch.h"

typedef BOOL (WINAPI *MiniDumpWriteDumpProc)(
    HANDLE hProcess,
    DWORD process_id,
    HANDLE hFile,
    MINIDUMP_TYPE dump_type,
    PMINIDUMP_EXCEPTION_INFORMATION exception_param,
    PMINIDUMP_USER_STREAM_INFORMATION user_stream_param,
    PMINIDUMP_CALLBACK_INFORMATION callback_param);

static INIT_ONCE g_dbghelp_once = INIT_ONCE_STATIC_INIT;
static HMODULE g_system_dbghelp = NULL;
static MiniDumpWriteDumpProc g_real_MiniDumpWriteDump = NULL;
static DWORD g_dbghelp_error = ERROR_SUCCESS;

static HMODULE LoadSystemDbghelp(void) {
    WCHAR path[MAX_PATH];
    const WCHAR suffix[] = L"\\dbghelp.dll";
    const UINT path_capacity = (UINT)(sizeof(path) / sizeof(path[0]));
    const size_t suffix_chars = sizeof(suffix) / sizeof(suffix[0]);
    UINT len = GetSystemDirectoryW(path, path_capacity);

    if (len == 0) {
        g_dbghelp_error = GetLastError();
        return NULL;
    }

    if ((size_t)len + suffix_chars > path_capacity) {
        g_dbghelp_error = ERROR_INSUFFICIENT_BUFFER;
        return NULL;
    }

    memcpy(path + len, suffix, sizeof(suffix));

    HMODULE module = LoadLibraryW(path);
    if (!module) {
        g_dbghelp_error = GetLastError();
    }

    return module;
}

static BOOL CALLBACK ResolveDbghelpOnce(PINIT_ONCE once,
                                        PVOID param,
                                        PVOID* context) {
    (void)once;
    (void)param;
    (void)context;

    g_system_dbghelp = LoadSystemDbghelp();
    if (!g_system_dbghelp) {
        return TRUE;
    }

    g_real_MiniDumpWriteDump =
        (MiniDumpWriteDumpProc)GetProcAddress(g_system_dbghelp,
                                              "MiniDumpWriteDump");
    if (!g_real_MiniDumpWriteDump) {
        g_dbghelp_error = GetLastError();
        FreeLibrary(g_system_dbghelp);
        g_system_dbghelp = NULL;
    }

    return TRUE;
}

static BOOL EnsureRealMiniDumpWriteDump(void) {
    if (!InitOnceExecuteOnce(&g_dbghelp_once, ResolveDbghelpOnce, NULL, NULL)) {
        g_dbghelp_error = GetLastError();
        return FALSE;
    }

    if (!g_real_MiniDumpWriteDump) {
        SetLastError(g_dbghelp_error ? g_dbghelp_error : ERROR_PROC_NOT_FOUND);
        return FALSE;
    }

    return TRUE;
}

__declspec(dllexport) BOOL WINAPI MiniDumpWriteDump(
    HANDLE hProcess,
    DWORD process_id,
    HANDLE hFile,
    MINIDUMP_TYPE dump_type,
    PMINIDUMP_EXCEPTION_INFORMATION exception_param,
    PMINIDUMP_USER_STREAM_INFORMATION user_stream_param,
    PMINIDUMP_CALLBACK_INFORMATION callback_param) {
    if (!EnsureRealMiniDumpWriteDump()) {
        return FALSE;
    }

    return g_real_MiniDumpWriteDump(hProcess,
                                   process_id,
                                   hFile,
                                   dump_type,
                                   exception_param,
                                   user_stream_param,
                                   callback_param);
}

BOOL WINAPI DllMain(HMODULE module, DWORD reason, LPVOID reserved) {
    (void)reserved;

    if (reason == DLL_PROCESS_ATTACH) {
        DstMemPatchOnProcessAttach(module);
    }

    return TRUE;
}
