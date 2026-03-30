cmake_minimum_required(VERSION 3.18)

project(
    oxscanner
    VERSION 1.0.0
    DESCRIPTION "Oxbuild Compliance Agent — Phase 0 PII Scanner"
    LANGUAGES CXX
)

# ---------------------------------------------------------------------------
# C++ Standard
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD          17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)

# ---------------------------------------------------------------------------
# Build type defaults
# ---------------------------------------------------------------------------
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

message(STATUS "Build type : ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ standard : C++${CMAKE_CXX_STANDARD}")

# ---------------------------------------------------------------------------
# Compiler hardening flags
# ---------------------------------------------------------------------------
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
        -Wno-unused-parameter
        # Optimisation
        $<$<CONFIG:Release>:-O3>
        $<$<CONFIG:Release>:-march=native>
        $<$<CONFIG:Release>:-DNDEBUG>
        # Debug info
        $<$<CONFIG:Debug>:-g3>
        $<$<CONFIG:Debug>:-fsanitize=address,undefined>
    )
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_link_options(-fsanitize=address,undefined)
    endif()
elseif(MSVC)
    add_compile_options(
        /W4
        /WX
        $<$<CONFIG:Release>:/O2>
        $<$<CONFIG:Release>:/DNDEBUG>
    )
endif()

# ---------------------------------------------------------------------------
# Find Python interpreter + development headers (required by pybind11)
# ---------------------------------------------------------------------------
find_package(Python3 3.9 REQUIRED
    COMPONENTS Interpreter Development.Module
)
message(STATUS "Python : ${Python3_VERSION} @ ${Python3_EXECUTABLE}")

# ---------------------------------------------------------------------------
# pybind11
# Supports three acquisition strategies (tried in order):
#   1. System-installed pybind11 via find_package (preferred for CI)
#   2. pybind11 installed in the active Python env (pip install pybind11)
#   3. Vendored / git-submodule copy at vendor/pybind11
# ---------------------------------------------------------------------------

# Strategy 1 — system cmake package
find_package(pybind11 2.11 QUIET CONFIG)

if(NOT pybind11_FOUND)
    # Strategy 2 — Python-installed pybind11
    execute_process(
        COMMAND "${Python3_EXECUTABLE}" -c
                "import pybind11; print(pybind11.get_cmake_dir())"
        OUTPUT_VARIABLE PY_PYBIND11_DIR
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE PY_PYBIND11_RESULT
    )
    if(PY_PYBIND11_RESULT EQUAL 0)
        list(APPEND CMAKE_PREFIX_PATH "${PY_PYBIND11_DIR}")
        find_package(pybind11 2.11 REQUIRED CONFIG)
        message(STATUS "pybind11 : found via Python env at ${PY_PYBIND11_DIR}")
    else()
        # Strategy 3 — vendored submodule
        set(VENDOR_PYBIND "${CMAKE_CURRENT_SOURCE_DIR}/vendor/pybind11")
        if(EXISTS "${VENDOR_PYBIND}/CMakeLists.txt")
            add_subdirectory("${VENDOR_PYBIND}" pybind11)
            message(STATUS "pybind11 : using vendored copy at ${VENDOR_PYBIND}")
        else()
            message(FATAL_ERROR
                "pybind11 not found. Install it via:\n"
                "  pip install pybind11\n"
                "or add it as a git submodule:\n"
                "  git submodule add https://github.com/pybind/pybind11 vendor/pybind11"
            )
        endif()
    endif()
else()
    message(STATUS "pybind11 : found system package v${pybind11_VERSION}")
endif()

# ---------------------------------------------------------------------------
# The compiled extension module — name must match PYBIND11_MODULE(_oxscanner, …)
# ---------------------------------------------------------------------------
pybind11_add_module(_oxscanner MODULE
    scanner.cpp
)

# Public include directory (none required beyond pybind11's own headers)
target_include_directories(_oxscanner
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link against Python (handled automatically by pybind11_add_module,
# but explicit for MSVC visibility)
target_link_libraries(_oxscanner PRIVATE pybind11::module pybind11::lto)

# Enable inter-procedural optimisation in Release
set_target_properties(_oxscanner PROPERTIES
    INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE
)

# ---------------------------------------------------------------------------
# Install target — copies the .so / .pyd next to scanner_wrapper.py
# ---------------------------------------------------------------------------
install(
    TARGETS _oxscanner
    LIBRARY DESTINATION "${CMAKE_CURRENT_SOURCE_DIR}"
    RUNTIME DESTINATION "${CMAKE_CURRENT_SOURCE_DIR}"   # Windows .pyd
)

# ---------------------------------------------------------------------------
# Convenience build-and-install target
# ---------------------------------------------------------------------------
add_custom_target(install_module
    COMMAND "${CMAKE_COMMAND}" --install . --config $<CONFIG>
    DEPENDS _oxscanner
    COMMENT "Installing _oxscanner module to source tree…"
)

# ---------------------------------------------------------------------------
# Unit-test target (runs Python doctest on scanner_wrapper.py)
# ---------------------------------------------------------------------------
enable_testing()
add_test(
    NAME python_wrapper_smoke
    COMMAND "${Python3_EXECUTABLE}" -m pytest
            "${CMAKE_CURRENT_SOURCE_DIR}/scanner_wrapper.py"
            --doctest-modules -v
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)

# ---------------------------------------------------------------------------
# Print summary
# ---------------------------------------------------------------------------
message(STATUS "")
message(STATUS "┌─ Oxbuild C++ Scanner Build Summary ─────────────────────")
message(STATUS "│  Module      : _oxscanner")
message(STATUS "│  Output dir  : ${CMAKE_CURRENT_SOURCE_DIR}")
message(STATUS "│  C++ std     : C++${CMAKE_CXX_STANDARD}")
message(STATUS "│  Build type  : ${CMAKE_BUILD_TYPE}")
message(STATUS "│  pybind11    : ${pybind11_VERSION}")
message(STATUS "│  Python      : ${Python3_VERSION}")
message(STATUS "└──────────────────────────────────────────────────────────")