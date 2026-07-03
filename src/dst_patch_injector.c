#include <windows.h>
#include <tlhelp32.h>
#include <conio.h>
#include <stdio.h>
#include <wchar.h>

static const WCHAR* const kTargetProcessNames[] = {
    L"dontstarve_dedicated_server_nullrenderer_x64.exe",
    L"dontstarve_steam_x64.exe"
};
static const WCHAR kDllFileName[] = L"dst_mem_patch.dll";

static const WCHAR* BaseNameOfPath(const WCHAR* path) {
    const WCHAR* cursor = path;
    const WCHAR* base = path;

    while (*cursor) {
        if (*cursor == L'\\' || *cursor == L'/') {
            base = cursor + 1;
        }
        ++cursor;
    }

    return base;
}

static int BuildDllPath(WCHAR* out_path, DWORD out_count) {
    DWORD len = GetModuleFileNameW(NULL, out_path, out_count);
    WCHAR* last_slash = NULL;
    WCHAR* cursor = out_path;

    if (len == 0 || len >= out_count) {
        return 0;
    }

    while (*cursor) {
        if (*cursor == L'\\' || *cursor == L'/') {
            last_slash = cursor;
        }
        ++cursor;
    }

    if (!last_slash) {
        return wcscpy_s(out_path, out_count, kDllFileName) == 0;
    }

    *(last_slash + 1) = L'\0';
    return wcscat_s(out_path, out_count, kDllFileName) == 0;
}

static int IsExactTargetProcessName(const WCHAR* process_name) {
    const WCHAR* base_name;
    SIZE_T i;

    if (!process_name) {
        return 0;
    }

    base_name = BaseNameOfPath(process_name);
    for (i = 0; i < sizeof(kTargetProcessNames) / sizeof(kTargetProcessNames[0]); ++i) {
        if (_wcsicmp(base_name, kTargetProcessNames[i]) == 0) {
            return 1;
        }
    }

    return 0;
}

static void PrintAllowedTargets(void) {
    SIZE_T i;

    wprintf(L"[INFO] allowed targets:\n");
    for (i = 0; i < sizeof(kTargetProcessNames) / sizeof(kTargetProcessNames[0]); ++i) {
        wprintf(L"       - %ls\n", kTargetProcessNames[i]);
    }
}

static void TryEnableDebugPrivilege(void) {
    HANDLE token = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &token)) {
        return;
    }

    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(token);
        return;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(token);
}

static int IsDllAlreadyLoaded(DWORD pid) {
    HANDLE snapshot;
    MODULEENTRY32W module;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    module.dwSize = sizeof(module);
    if (!Module32FirstW(snapshot, &module)) {
        CloseHandle(snapshot);
        return 0;
    }

    do {
        if (_wcsicmp(BaseNameOfPath(module.szModule), kDllFileName) == 0 ||
            _wcsicmp(BaseNameOfPath(module.szExePath), kDllFileName) == 0) {
            CloseHandle(snapshot);
            return 1;
        }
    } while (Module32NextW(snapshot, &module));

    CloseHandle(snapshot);
    return 0;
}

static int InjectDllIntoProcess(DWORD pid, const WCHAR* dll_path) {
    HANDLE process = NULL;
    HANDLE thread = NULL;
    LPVOID remote_path = NULL;
    SIZE_T path_bytes = (wcslen(dll_path) + 1) * sizeof(WCHAR);
    SIZE_T written = 0;
    LPTHREAD_START_ROUTINE load_library_w;
    DWORD wait_result;
    DWORD exit_code = 0;
    int ok = 0;

    if (IsDllAlreadyLoaded(pid)) {
        wprintf(L"[SKIP] pid=%lu already has %ls loaded\n", pid, kDllFileName);
        return 1;
    }

    process = OpenProcess(PROCESS_CREATE_THREAD |
                              PROCESS_QUERY_INFORMATION |
                              PROCESS_VM_OPERATION |
                              PROCESS_VM_WRITE,
                          FALSE,
                          pid);
    if (!process) {
        wprintf(L"[FAIL] pid=%lu OpenProcess error=%lu\n", pid, GetLastError());
        return 0;
    }

    remote_path = VirtualAllocEx(process, NULL, path_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_path) {
        wprintf(L"[FAIL] pid=%lu VirtualAllocEx error=%lu\n", pid, GetLastError());
        CloseHandle(process);
        return 0;
    }

    if (!WriteProcessMemory(process, remote_path, dll_path, path_bytes, &written) ||
        written != path_bytes) {
        wprintf(L"[FAIL] pid=%lu WriteProcessMemory error=%lu\n", pid, GetLastError());
        VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
        CloseHandle(process);
        return 0;
    }

    load_library_w = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),
                                                            "LoadLibraryW");
    if (!load_library_w) {
        wprintf(L"[FAIL] pid=%lu cannot resolve LoadLibraryW error=%lu\n", pid, GetLastError());
        VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
        CloseHandle(process);
        return 0;
    }

    thread = CreateRemoteThread(process, NULL, 0, load_library_w, remote_path, 0, NULL);
    if (!thread) {
        wprintf(L"[FAIL] pid=%lu CreateRemoteThread error=%lu\n", pid, GetLastError());
        VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
        CloseHandle(process);
        return 0;
    }

    wait_result = WaitForSingleObject(thread, 15000);
    if (wait_result != WAIT_OBJECT_0) {
        wprintf(L"[FAIL] pid=%lu LoadLibraryW wait result=%lu error=%lu\n",
                pid,
                wait_result,
                GetLastError());
    } else if (!GetExitCodeThread(thread, &exit_code) || exit_code == 0) {
        wprintf(L"[FAIL] pid=%lu LoadLibraryW returned 0 error=%lu\n", pid, GetLastError());
    } else {
        wprintf(L"[ OK ] pid=%lu injected %ls\n", pid, kDllFileName);
        ok = 1;
    }

    CloseHandle(thread);
    VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
    CloseHandle(process);
    return ok;
}

static int InjectAllTargets(const WCHAR* dll_path) {
    HANDLE snapshot;
    PROCESSENTRY32W process;
    int found = 0;
    int success = 0;
    int failed = 0;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        wprintf(L"[FAIL] CreateToolhelp32Snapshot error=%lu\n", GetLastError());
        return 1;
    }

    process.dwSize = sizeof(process);
    if (!Process32FirstW(snapshot, &process)) {
        wprintf(L"[FAIL] Process32FirstW error=%lu\n", GetLastError());
        CloseHandle(snapshot);
        return 1;
    }

    do {
        if (!IsExactTargetProcessName(process.szExeFile)) {
            continue;
        }

        ++found;
        wprintf(L"[INFO] target pid=%lu name=%ls\n", process.th32ProcessID, process.szExeFile);
        if (InjectDllIntoProcess(process.th32ProcessID, dll_path)) {
            ++success;
        } else {
            ++failed;
        }
    } while (Process32NextW(snapshot, &process));

    CloseHandle(snapshot);

    if (found == 0) {
        wprintf(L"[INFO] no allowed target process found\n");
    }

    wprintf(L"[DONE] found=%d success_or_skipped=%d failed=%d\n", found, success, failed);
    return failed == 0 ? 0 : 1;
}

static int ExitWithPause(int exit_code) {
    wprintf(L"[INFO] press any key to exit...\n");
    fflush(stdout);
    _getwch();
    return exit_code;
}

int main(int argc, char** argv) {
    WCHAR dll_path[MAX_PATH];
    DWORD attributes;

    (void)argv;

    if (argc != 1) {
        wprintf(L"[FAIL] this tool accepts no arguments\n");
        PrintAllowedTargets();
        return ExitWithPause(2);
    }

    if (!BuildDllPath(dll_path, MAX_PATH)) {
        wprintf(L"[FAIL] cannot build %ls path\n", kDllFileName);
        return ExitWithPause(1);
    }

    attributes = GetFileAttributesW(dll_path);
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        wprintf(L"[FAIL] missing DLL next to injector: %ls\n", dll_path);
        return ExitWithPause(1);
    }

    TryEnableDebugPrivilege();
    wprintf(L"[INFO] DLL: %ls\n", dll_path);
    PrintAllowedTargets();
    return ExitWithPause(InjectAllTargets(dll_path));
}
