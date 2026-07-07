#ifndef DST_MEM_PATCH_H
#define DST_MEM_PATCH_H

#include <windows.h>

void DstMemPatchApply(void);
void DstMemPatchOnProcessAttach(HMODULE module);

#endif
