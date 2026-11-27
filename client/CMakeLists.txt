cmake_minimum_required(VERSION 3.15)
project(AtroxLauncher CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(AtroxLauncher WIN32 main.cpp LicenseGate.cpp)
target_compile_definitions(AtroxLauncher PRIVATE UNICODE _UNICODE)
target_link_libraries(AtroxLauncher PRIVATE winhttp bcrypt uxtheme advapi32 user32 gdi32)

if(MSVC)
    target_compile_options(AtroxLauncher PRIVATE /utf-8)
else()
    target_link_options(AtroxLauncher PRIVATE -municode -static)
endif()
