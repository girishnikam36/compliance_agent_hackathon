"""
setup.py — Oxbuild C++ Scanner | pip-based build (Windows-safe)
================================================================
Builds the _oxscanner pybind11 extension using Python's OWN build
machinery instead of CMake.

WHY THIS WORKS WHERE CMAKE FAILED:
  - Python's setuptools calls the SAME cl.exe that compiled Python itself.
  - That guarantees the architectures match (both x64 if Python is x64).
  - It reads the Python include/lib paths directly from sys — no guessing.
  - It works with any Visual Studio version Python was built against.

USAGE (run from local_bridge/core/):
  pip install pybind11 setuptools wheel
  pip install . --no-build-isolation

The compiled .pyd ends up in site-packages AND is copied next to this
file by the post-build step at the bottom.
"""

import os
import shutil
import sys
from pathlib import Path

from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext


# ─────────────────────────────────────────────────────────────────────────────
# Locate pybind11 include directory
# ─────────────────────────────────────────────────────────────────────────────

def get_pybind11_include() -> str:
    """Return the pybind11 include path from the current Python environment."""
    try:
        import pybind11
        return pybind11.get_include()
    except ImportError:
        print("ERROR: pybind11 not found. Run: pip install pybind11")
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Custom build command: copies .pyd next to scanner_wrapper.py after build
# ─────────────────────────────────────────────────────────────────────────────

class BuildExtAndCopy(build_ext):
    """Extends build_ext to copy the compiled module to the source directory."""

    def run(self):
        super().run()
        self._copy_to_source()

    def _copy_to_source(self):
        source_dir = Path(__file__).parent
        build_dir  = Path(self.build_lib)

        # Find the built .pyd / .so in the build directory
        pyd_files = list(build_dir.rglob("_oxscanner*.pyd")) + \
                    list(build_dir.rglob("_oxscanner*.so"))

        if not pyd_files:
            # Also check the temporary build directory
            temp_dir = Path(self.build_temp)
            pyd_files = list(temp_dir.rglob("_oxscanner*.pyd")) + \
                        list(temp_dir.rglob("_oxscanner*.so"))

        if pyd_files:
            dest = source_dir / pyd_files[0].name
            shutil.copy2(str(pyd_files[0]), str(dest))
            print(f"\n✅ Scanner module copied to:\n   {dest}\n")
        else:
            # Try inplace location
            inplace = list(source_dir.rglob("_oxscanner*.pyd")) + \
                      list(source_dir.rglob("_oxscanner*.so"))
            if inplace:
                print(f"\n✅ Scanner module already in place:\n   {inplace[0]}\n")
            else:
                print("\n⚠  Could not find compiled module to copy.")
                print("   Run: python setup.py build_ext --inplace\n")


# ─────────────────────────────────────────────────────────────────────────────
# Compiler flags
# ─────────────────────────────────────────────────────────────────────────────

def get_extra_compile_args() -> list[str]:
    if sys.platform == "win32":
        return [
            "/std:c++17",    # C++17
            "/O2",           # Optimise
            "/W3",           # Warnings level 3
            "/EHsc",         # Exception handling
            "/DNDEBUG",      # Disable debug asserts
        ]
    else:
        # macOS / Linux
        return [
            "-std=c++17",
            "-O3",
            "-Wall",
            "-DNDEBUG",
            "-fvisibility=hidden",   # Reduces symbol table size
        ]


def get_extra_link_args() -> list[str]:
    if sys.platform == "win32":
        return []
    elif sys.platform == "darwin":
        return ["-stdlib=libc++"]
    else:
        return []


# ─────────────────────────────────────────────────────────────────────────────
# Extension definition
# ─────────────────────────────────────────────────────────────────────────────

ext = Extension(
    name="_oxscanner",
    sources=["scanner.cpp"],
    include_dirs=[
        get_pybind11_include(),
    ],
    extra_compile_args=get_extra_compile_args(),
    extra_link_args=get_extra_link_args(),
    language="c++",
)


# ─────────────────────────────────────────────────────────────────────────────
# Setup call
# ─────────────────────────────────────────────────────────────────────────────

setup(
    name="_oxscanner",
    version="1.0.0",
    description="Oxbuild Compliance Agent — Phase 0 PII Scanner",
    author="Oxbuild Engineering",
    ext_modules=[ext],
    cmdclass={"build_ext": BuildExtAndCopy},
    python_requires=">=3.9",
    zip_safe=False,
)