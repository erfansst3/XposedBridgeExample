cmake_minimum_required(VERSION 3.22.1)
project("xposed_native_diag")

add_library(xposed_native_diag SHARED
    native_diag.cpp
    sandhook_deep_inspector.cpp
)

find_library(log-lib log)

target_link_libraries(xposed_native_diag
    ${log-lib}
    dl
)
