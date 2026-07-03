#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

static INIT_ONCE g_patch_once = INIT_ONCE_STATIC_INIT;
static int g_patch_target = 0;

enum {
    PATCH_TARGET_NONE = 0,
    PATCH_TARGET_SERVER,
    PATCH_TARGET_CLIENT
};

static const WCHAR kServerProcessName[] =
    L"dontstarve_dedicated_server_nullrenderer_x64.exe";
static const WCHAR kClientProcessName[] = L"dontstarve_steam_x64.exe";

static const uint8_t SIG_OWNERSHIP[] = {
    0x0F, 0xB6, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00,
    0x0F, 0x45, 0x00,
    0x8A, 0x00
};

static const uint8_t MSK_OWNERSHIP[] = {
    0xFF, 0xFF, 0x00,
    0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0x00,
    0xFF, 0x00
};

static const uint8_t SIG_EXISTS[] = {
    0xB0, 0x01,
    0x48, 0x83, 0xC4, 0x00,
    0x00, 0x00, 0x00,
    0xC3
};

static const uint8_t MSK_EXISTS[] = {
    0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0x00,
    0x00, 0x00, 0x00,
    0xFF
};

static const uint8_t SIG_EXISTS_B[] = {
    0xB0, 0x01,
    0x48, 0x8B, 0x00, 0x24, 0x00,
    0x48, 0x83, 0xC4, 0x00,
    0x00, 0x00, 0x00,
    0xC3
};

static const uint8_t MSK_EXISTS_B[] = {
    0xFF, 0xFF,
    0xFF, 0xFF, 0x00, 0xFF, 0x00,
    0xFF, 0xFF, 0xFF, 0x00,
    0x00, 0x00, 0x00,
    0xFF
};

static const uint8_t SIG_EXISTS_R12[] = {
    0xB0, 0x01,
    0x48, 0x83, 0xC4, 0x00,
    0x41, 0x5C, 0x5E, 0x5D,
    0xC3
};

static const uint8_t MSK_EXISTS_R12[] = {
    0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF
};

typedef struct Signature {
    const uint8_t* bytes;
    const uint8_t* mask;
    SIZE_T len;
} Signature;

typedef int (*PrologueCheck)(const uint8_t* p);

static const Signature kExistsSignatures[] = {
    { SIG_EXISTS_R12, MSK_EXISTS_R12, sizeof(SIG_EXISTS_R12) },
    { SIG_EXISTS, MSK_EXISTS, sizeof(SIG_EXISTS) },
    { SIG_EXISTS_B, MSK_EXISTS_B, sizeof(SIG_EXISTS_B) }
};

static const uint8_t SIG_CLIENT_C1_ENTRY[] = {
    0x40, 0x53,
    0x48, 0x83, 0xEC, 0x30,
    0x48, 0x8B, 0xDA,
    0x45, 0x33, 0xC0,
    0x41, 0x8D, 0x50, 0x01,
    0x48, 0x8B, 0xCB
};

static const uint8_t MSK_CLIENT_C1_ENTRY[] = {
    0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF
};

static const uint8_t SIG_CLIENT_C2_ENTRY[] = {
    0x40, 0x53,
    0x48, 0x83, 0xEC, 0x30,
    0x0F, 0x57, 0xC0,
    0x48, 0x8B, 0xDA,
    0x45, 0x33, 0xC0,
    0x41, 0x8D, 0x50, 0x01,
    0x48, 0x8B, 0xCB,
    0xF3, 0x0F, 0x11, 0x44, 0x24, 0x50
};

static const uint8_t MSK_CLIENT_C2_ENTRY[] = {
    0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static const uint8_t CLIENT_BOOL_BAND[] = {
    0x33, 0xD2,
    0x48, 0x8B, 0xCB,
    0x84, 0xC0,
    0x0F, 0x95, 0xC2
};

static const uint8_t CLIENT_OWNERSHIP_ENTRY[] = {
    0x40, 0x53,
    0x48, 0x83, 0xEC, 0x40
};

static const uint8_t CLIENT_RETURN_TRUE_ENTRY[] = {
    0xB0, 0x01, 0xC3,
    0x90, 0x90, 0x90
};

static const uint8_t CLIENT_SETNZ_DL[] = {
    0x0F, 0x95, 0xC2
};

static const uint8_t CLIENT_MOV_DL_TRUE[] = {
    0xB2, 0x01, 0x90
};

static const uint8_t CLIENT_C1_RETURN_ONE[] = {
    0xB8, 0x01, 0x00, 0x00, 0x00,
    0x48, 0x83, 0xC4, 0x30,
    0x5B,
    0xC3
};

static const uint8_t CLIENT_C2_VERSION_PUSH[] = {
    0x48, 0x8B, 0xCB,
    0x66, 0x0F, 0x6E, 0x4C, 0x24, 0x50,
    0x0F, 0x5A, 0xC9
};

static const uint8_t CLIENT_C2_RETURN_TWO[] = {
    0xB8, 0x02, 0x00, 0x00, 0x00,
    0x48, 0x83, 0xC4, 0x30,
    0x5B,
    0xC3
};

#define CLIENT_C1_PATCH_OFFSET 0x36
#define CLIENT_C2_PATCH_OFFSET 0x44
#define CLIENT_C1_OWNERSHIP_CALL_OFFSET 0x31
#define CLIENT_C2_SETNZ_OFFSET 0x4B

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

static int GetPatchTargetForCurrentProcess(void) {
    const WCHAR* base_name;
    WCHAR path[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, path, MAX_PATH);

    if (len == 0 || len >= MAX_PATH) {
        return PATCH_TARGET_NONE;
    }

    base_name = BaseNameOfPath(path);
    if (_wcsicmp(base_name, kServerProcessName) == 0) {
        return PATCH_TARGET_SERVER;
    }
    if (_wcsicmp(base_name, kClientProcessName) == 0) {
        return PATCH_TARGET_CLIENT;
    }

    return PATCH_TARGET_NONE;
}

static SIZE_T GetImageSize(HMODULE module) {
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)module;
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    const IMAGE_NT_HEADERS64* nt =
        (const IMAGE_NT_HEADERS64*)((const uint8_t*)module + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    return nt->OptionalHeader.SizeOfImage;
}

static int IsOwnershipPrologue(const uint8_t* p) {
    if (p[0] != 0x48 || p[1] != 0x89) {
        return 0;
    }
    if (p[3] != 0x24 || p[4] != 0x08) {
        return 0;
    }
    if (p[5] != 0x48 || p[6] != 0x89) {
        return 0;
    }
    if (p[8] != 0x24 || p[9] != 0x10) {
        return 0;
    }
    if (p[10] == 0x48 && p[11] == 0x89 && p[13] == 0x24 && p[14] == 0x18) {
        return 1;
    }
    return p[10] >= 0x50 && p[10] <= 0x5F;
}

static int IsExistsPrologue(const uint8_t* p) {
    int off = 0;
    if (p[0] == 0x40) {
        off++;
    }
    if (p[off] != 0x55) {
        return 0;
    }
    if (p[off + 1] != 0x56) {
        return 0;
    }
    if (p[off + 2] != 0x41 || p[off + 3] != 0x54) {
        return 0;
    }
    return p[off + 4] == 0x48 && p[off + 5] == 0x83 && p[off + 6] == 0xEC;
}

static const uint8_t* FuzzyFind(const uint8_t* base, SIZE_T size,
                                const uint8_t* pat, const uint8_t* mask,
                                SIZE_T len) {
    SIZE_T i;
    SIZE_T j;

    if (size < len) {
        return NULL;
    }

    for (i = 0; i <= size - len; ++i) {
        int match = 1;
        for (j = 0; j < len; ++j) {
            if (mask[j] && base[i + j] != pat[j]) {
                match = 0;
                break;
            }
        }
        if (match) {
            return base + i;
        }
    }
    return NULL;
}

static const uint8_t* BackToPrologue(const uint8_t* match,
                                     const uint8_t* lower_bound,
                                     PrologueCheck is_prologue) {
    SIZE_T max_back = (SIZE_T)(match - lower_bound);
    SIZE_T limit = max_back < 1024 ? max_back : 1024;
    SIZE_T i;

    for (i = 0; i <= limit; ++i) {
        const uint8_t* p = match - i;
        if (p > lower_bound && p[-1] == 0xCC && is_prologue(p)) {
            return p;
        }
        if (is_prologue(p)) {
            if (p > lower_bound && p[-1] == 0x40 && is_prologue(p - 1)) {
                return p - 1;
            }
            return p;
        }
    }
    return NULL;
}

static const uint8_t* FindFunctionEntryBySignature(HMODULE module,
                                                   const Signature* sig,
                                                   PrologueCheck is_prologue) {
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)module;
    const IMAGE_NT_HEADERS64* nt =
        (const IMAGE_NT_HEADERS64*)((const uint8_t*)module + dos->e_lfanew);
    const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
    WORD i;

    for (i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        const uint8_t* begin;
        const uint8_t* cursor;
        SIZE_T section_size;

        if (!(section->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            !(section->Characteristics & IMAGE_SCN_CNT_CODE)) {
            continue;
        }

        section_size = section->Misc.VirtualSize;
        if (section_size == 0) {
            section_size = section->SizeOfRawData;
        }
        if (section_size < sig->len) {
            continue;
        }

        begin = (const uint8_t*)module + section->VirtualAddress;
        cursor = begin;

        while (cursor <= begin + section_size - sig->len) {
            const uint8_t* match = FuzzyFind(cursor,
                                             (SIZE_T)((begin + section_size) - cursor),
                                             sig->bytes,
                                             sig->mask,
                                             sig->len);
            const uint8_t* entry;

            if (!match) {
                break;
            }

            entry = BackToPrologue(match, begin, is_prologue);
            if (entry) {
                return entry;
            }

            cursor = match + 1;
        }
    }

    return NULL;
}

static const uint8_t* FindFunctionEntry(HMODULE module,
                                        const Signature* signatures,
                                        SIZE_T count,
                                        PrologueCheck is_prologue) {
    SIZE_T i;

    for (i = 0; i < count; ++i) {
        const uint8_t* entry =
            FindFunctionEntryBySignature(module, &signatures[i], is_prologue);
        if (entry) {
            return entry;
        }
    }

    return NULL;
}

static int BytesAt(const uint8_t* base,
                   const uint8_t* limit,
                   SIZE_T offset,
                   const uint8_t* expected,
                   SIZE_T len) {
    if (base + offset < base || base + offset + len < base + offset) {
        return 0;
    }
    if (base + offset + len > limit) {
        return 0;
    }
    return memcmp(base + offset, expected, len) == 0;
}

static int IsRelCallAt(const uint8_t* base, const uint8_t* limit, SIZE_T offset) {
    if (base + offset < base || base + offset + 5 < base + offset) {
        return 0;
    }
    return base + offset + 5 <= limit && base[offset] == 0xE8;
}

static const uint8_t* RelCallTargetAt(const uint8_t* base, SIZE_T offset) {
    int32_t rel;
    uintptr_t next;

    if (base[offset] != 0xE8) {
        return NULL;
    }

    memcpy(&rel, base + offset + 1, sizeof(rel));
    next = (uintptr_t)(base + offset + 5);
    return (const uint8_t*)(next + (intptr_t)rel);
}

static int RangeInsideImage(const uint8_t* ptr,
                            SIZE_T len,
                            const uint8_t* image_begin,
                            const uint8_t* image_end) {
    uintptr_t p = (uintptr_t)ptr;
    uintptr_t begin = (uintptr_t)image_begin;
    uintptr_t end = (uintptr_t)image_end;

    if (!ptr || !image_begin || !image_end || begin > end) {
        return 0;
    }
    if (p < begin || p > end) {
        return 0;
    }
    return len <= (SIZE_T)(end - p);
}

typedef int (*CandidateCheck)(const uint8_t* entry, const uint8_t* section_end);

static int IsClientC1Candidate(const uint8_t* entry, const uint8_t* section_end) {
    return IsRelCallAt(entry, section_end, 0x13) &&
           IsRelCallAt(entry, section_end, 0x20) &&
           IsRelCallAt(entry, section_end, 0x31) &&
           BytesAt(entry, section_end, CLIENT_C1_PATCH_OFFSET,
                   CLIENT_BOOL_BAND, sizeof(CLIENT_BOOL_BAND)) &&
           IsRelCallAt(entry, section_end, 0x40) &&
           BytesAt(entry, section_end, 0x45,
                   CLIENT_C1_RETURN_ONE, sizeof(CLIENT_C1_RETURN_ONE));
}

static int IsClientC2Candidate(const uint8_t* entry, const uint8_t* section_end) {
    return IsRelCallAt(entry, section_end, 0x1C) &&
           IsRelCallAt(entry, section_end, 0x29) &&
           IsRelCallAt(entry, section_end, 0x3F) &&
           BytesAt(entry, section_end, CLIENT_C2_PATCH_OFFSET,
                   CLIENT_BOOL_BAND, sizeof(CLIENT_BOOL_BAND)) &&
           IsRelCallAt(entry, section_end, 0x4E) &&
           BytesAt(entry, section_end, 0x53,
                   CLIENT_C2_VERSION_PUSH, sizeof(CLIENT_C2_VERSION_PUSH)) &&
           IsRelCallAt(entry, section_end, 0x5F) &&
           BytesAt(entry, section_end, 0x64,
                   CLIENT_C2_RETURN_TWO, sizeof(CLIENT_C2_RETURN_TWO));
}

static const uint8_t* FindUniqueCandidate(HMODULE module,
                                          const Signature* sig,
                                          CandidateCheck check,
                                          int* count_out) {
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)module;
    const IMAGE_NT_HEADERS64* nt =
        (const IMAGE_NT_HEADERS64*)((const uint8_t*)module + dos->e_lfanew);
    const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
    const uint8_t* found = NULL;
    int count = 0;
    WORD i;

    for (i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        const uint8_t* begin;
        const uint8_t* end;
        const uint8_t* cursor;
        SIZE_T section_size;

        if (!(section->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            !(section->Characteristics & IMAGE_SCN_CNT_CODE)) {
            continue;
        }

        section_size = section->Misc.VirtualSize;
        if (section_size == 0) {
            section_size = section->SizeOfRawData;
        }
        if (section_size < sig->len) {
            continue;
        }

        begin = (const uint8_t*)module + section->VirtualAddress;
        end = begin + section_size;
        cursor = begin;

        while (cursor <= end - sig->len) {
            const uint8_t* match = FuzzyFind(cursor,
                                             (SIZE_T)(end - cursor),
                                             sig->bytes,
                                             sig->mask,
                                             sig->len);
            if (!match) {
                break;
            }

            if (check(match, end)) {
                found = match;
                ++count;
            }

            cursor = match + 1;
        }
    }

    if (count_out) {
        *count_out = count;
    }
    return count == 1 ? found : NULL;
}

static void ApplyBytes(void* addr, const uint8_t* patch, SIZE_T len) {
    DWORD old_protect = 0;

    if (!VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &old_protect)) {
        return;
    }

    memcpy(addr, patch, len);
    FlushInstructionCache(GetCurrentProcess(), addr, len);
    VirtualProtect(addr, len, old_protect, &old_protect);
}

static void ApplyReturnTruePatch(void* addr) {
    static const uint8_t patch[] = { 0xB0, 0x01, 0xC3 };
    ApplyBytes(addr, patch, sizeof(patch));
}

static const char* UniqueStatus(const uint8_t* ptr, int count) {
    if (ptr) {
        return "PATCHED";
    }
    if (count > 1) {
        return "AMBIG";
    }
    return "MISS";
}

static void PatchServerTargets(HMODULE main_module) {
    const uint8_t* ownership_entry;
    const uint8_t* exists_entry;
    char msg[256];

    static const Signature kOwnershipSignatures[] = {
        { SIG_OWNERSHIP, MSK_OWNERSHIP, sizeof(SIG_OWNERSHIP) }
    };

    ownership_entry = FindFunctionEntry(main_module,
                                        kOwnershipSignatures,
                                        sizeof(kOwnershipSignatures) / sizeof(kOwnershipSignatures[0]),
                                        IsOwnershipPrologue);
    exists_entry = FindFunctionEntry(main_module,
                                     kExistsSignatures,
                                     sizeof(kExistsSignatures) / sizeof(kExistsSignatures[0]),
                                     IsExistsPrologue);

    if (ownership_entry) {
        ApplyReturnTruePatch((void*)ownership_entry);
    }
    if (exists_entry) {
        ApplyReturnTruePatch((void*)exists_entry);
    }

    snprintf(msg,
             sizeof(msg),
             "[DST Mem Patch] server sub_140201900: %s (%p) | sub_140201C20: %s (%p)\n",
             ownership_entry ? "PATCHED" : "MISS",
             ownership_entry,
             exists_entry ? "PATCHED" : "MISS",
             exists_entry);
    OutputDebugStringA(msg);
}

static void PatchClientTargets(HMODULE main_module) {
    const Signature c1_sig = {
        SIG_CLIENT_C1_ENTRY,
        MSK_CLIENT_C1_ENTRY,
        sizeof(SIG_CLIENT_C1_ENTRY)
    };
    const Signature c2_sig = {
        SIG_CLIENT_C2_ENTRY,
        MSK_CLIENT_C2_ENTRY,
        sizeof(SIG_CLIENT_C2_ENTRY)
    };
    const uint8_t* c1_entry;
    const uint8_t* c2_entry;
    const uint8_t* c1_ownership_entry = NULL;
    const uint8_t* c2_setnz = NULL;
    const uint8_t* image_begin = (const uint8_t*)main_module;
    const uint8_t* image_end = image_begin + GetImageSize(main_module);
    int c1_count = 0;
    int c2_count = 0;
    char msg[320];

    c1_entry = FindUniqueCandidate(main_module, &c1_sig, IsClientC1Candidate, &c1_count);
    c2_entry = FindUniqueCandidate(main_module, &c2_sig, IsClientC2Candidate, &c2_count);

    if (c1_entry) {
        c1_ownership_entry = RelCallTargetAt(c1_entry, CLIENT_C1_OWNERSHIP_CALL_OFFSET);
        if (!RangeInsideImage(c1_ownership_entry,
                              sizeof(CLIENT_OWNERSHIP_ENTRY),
                              image_begin,
                              image_end) ||
            memcmp(c1_ownership_entry,
                   CLIENT_OWNERSHIP_ENTRY,
                   sizeof(CLIENT_OWNERSHIP_ENTRY)) != 0) {
            c1_ownership_entry = NULL;
        }
    }

    if (c1_ownership_entry) {
        ApplyBytes((void*)c1_ownership_entry,
                   CLIENT_RETURN_TRUE_ENTRY,
                   sizeof(CLIENT_RETURN_TRUE_ENTRY));
    }

    if (c2_entry) {
        c2_setnz = c2_entry + CLIENT_C2_SETNZ_OFFSET;
        if (!RangeInsideImage(c2_setnz,
                              sizeof(CLIENT_SETNZ_DL),
                              image_begin,
                              image_end) ||
            memcmp(c2_setnz, CLIENT_SETNZ_DL, sizeof(CLIENT_SETNZ_DL)) != 0) {
            c2_setnz = NULL;
        }
    }

    if (c2_setnz) {
        ApplyBytes((void*)c2_setnz,
                   CLIENT_MOV_DL_TRUE,
                   sizeof(CLIENT_MOV_DL_TRUE));
    }

    snprintf(msg,
             sizeof(msg),
             "[DST Mem Patch] client C1 helper: %s count=%d wrapper=%p target=%p | C2 setnz: %s count=%d wrapper=%p patch=%p\n",
             UniqueStatus(c1_ownership_entry, c1_count),
             c1_count,
             c1_entry,
             c1_ownership_entry,
             UniqueStatus(c2_setnz, c2_count),
             c2_count,
             c2_entry,
             c2_setnz);
    OutputDebugStringA(msg);
}

static BOOL CALLBACK PatchTargetsOnce(PINIT_ONCE once, PVOID param, PVOID* context) {
    (void)once;
    (void)param;
    (void)context;

    HMODULE main_module = GetModuleHandleW(NULL);

    if (g_patch_target == PATCH_TARGET_NONE) {
        OutputDebugStringA("[DST Mem Patch] patch skipped for non-target process\n");
        return TRUE;
    }

    if (!main_module || GetImageSize(main_module) == 0) {
        OutputDebugStringA("[DST Mem Patch] invalid main module image\n");
        return TRUE;
    }

    if (g_patch_target == PATCH_TARGET_SERVER) {
        PatchServerTargets(main_module);
    } else if (g_patch_target == PATCH_TARGET_CLIENT) {
        PatchClientTargets(main_module);
    }

    return TRUE;
}

static void EnsurePatchApplied(void) {
    InitOnceExecuteOnce(&g_patch_once, PatchTargetsOnce, NULL, NULL);
}

__declspec(dllexport) void ApplyDstMemPatch(void) {
    EnsurePatchApplied();
}

BOOL WINAPI DllMain(HMODULE module, DWORD reason, LPVOID reserved) {
    (void)module;
    (void)reserved;

    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        g_patch_target = GetPatchTargetForCurrentProcess();
        EnsurePatchApplied();
    }

    return TRUE;
}
