cmake_minimum_required(VERSION 3.20)

project(dst_mem_patch C)

add_library(dst_mem_patch SHARED
    src/dst_mem_patch.c
)

add_executable(dst_patch_injector
    src/dst_patch_injector.c
)

target_compile_definitions(dst_mem_patch PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

target_compile_definitions(dst_patch_injector PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

target_link_libraries(dst_mem_patch PRIVATE
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

set_target_properties(dst_patch_injector PROPERTIES
    OUTPUT_NAME "dst_patch_injector"
)
