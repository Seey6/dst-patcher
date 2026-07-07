cmake_minimum_required(VERSION 3.20)

project(dst_mem_patch C)

set(DST_MEM_PATCH_WIN32_DEFINITIONS
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

add_library(dst_mem_patch SHARED
    src/dst_mem_patch.c
)

add_library(dbghelp_proxy SHARED
    src/dbghelp_proxy.c
    src/dst_mem_patch.c
)

add_executable(dst_patch_injector
    src/dst_patch_injector.c
)

target_compile_definitions(dst_mem_patch PRIVATE
    ${DST_MEM_PATCH_WIN32_DEFINITIONS}
)

target_compile_definitions(dbghelp_proxy PRIVATE
    ${DST_MEM_PATCH_WIN32_DEFINITIONS}
    DST_MEM_PATCH_NO_DLL_ENTRY
)

target_compile_definitions(dst_patch_injector PRIVATE
    ${DST_MEM_PATCH_WIN32_DEFINITIONS}
)

target_link_libraries(dst_mem_patch PRIVATE
    kernel32
)

target_link_libraries(dbghelp_proxy PRIVATE
    kernel32
)

target_link_libraries(dst_patch_injector PRIVATE
    kernel32
    advapi32
)

set_target_properties(dst_mem_patch PROPERTIES
    PREFIX ""
    OUTPUT_NAME "dst_mem_patch"
)

set_target_properties(dbghelp_proxy PROPERTIES
    PREFIX ""
    OUTPUT_NAME "dbghelp"
)

set_target_properties(dst_patch_injector PROPERTIES
    OUTPUT_NAME "dst_patch_injector"
)
