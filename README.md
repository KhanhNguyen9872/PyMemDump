# PyInstaller Memory Dump Extractor

This toolchain allows for the reverse-engineering and extraction of PyInstaller compiled executables by analyzing their live process **Memory Dumps**. 

It is specifically designed to bypass packers, DRM solutions, and custom protectors (like FionaProtector) that deliberately overwrite, encrypt, or mutilate the PyInstaller `PYZ` metadata and Table of Contents (TOC) to prevent static extraction tools (like `pyinstxtractor`) from working. 

By dumping the application from RAM while it is executing, we allow the Python Interpreter to do the heavy lifting of decrypting the bytecode paths.

---

## Tool 1: Dumping Process Memory (`dump_process.py`)

To analyze the application, we first need a full snapshot of its memory space after it has been unpacked and loaded by the OS.

You have two methods to create a Memory Dump:

### Method 1: Using the provided `dump_process.py`
This script uses the native Windows `dbghelp.dll` API to perform a full process memory dump natively without third-party software.
Ensure the target executable is currently running, then execute the script as Administrator.

**Usage:**
```cmd
# You can target by Process Name
python dump_process.py target_app.exe

# Or by exact PID
python dump_process.py 1234
```
A `.dmp` file (e.g., `target_app.exe.dmp`) will be created in your current directory. It may be several hundred megabytes.

### Method 2: Using Process Hacker 2
If you prefer a GUI tool:
1. Open **Process Hacker 2** (Run as Administrator).
2. Locate the target running `.exe` in the processes list.
3. **Right-Click** the process -> **Create dump file...**
4. Save the `.dmp` file to your working directory.

---

## Tool 2: Carving the Python Bytecode (`pyinstaller_dump_extract.py`)

Once you have the `.dmp` file, execute `pyinstaller_dump_extract.py` against it.

Because PyInstaller protectors wipe the application TOC, this script does not rely on static offsets. Instead, it dynamically brute-force scans the entire memory space for:
- Valid Zlib-compressed streams yielding Python `CodeObjects`.
- Uncompressed raw `marshal` payloads (`\xe3\x00\x00\x00`).

The script automatically detects the running Python Version (3.10 - 3.14) from the memory structures and prepends the exact matching `.pyc` magic header, allowing standard debuggers to decompile the output seamlessly.

**Usage:**
```cmd
python pyinstaller_dump_extract.py target_app.exe.dmp
```

**Features:**
- Supports Python 3.10 through 3.14.
- Automatically wipes/recreates the output directory `target_app.exe.dmp_extracted`.
- Preserves the directory structures and module hierarchy embedded inside the memory `CodeObjects` (e.g., `pathlib\_local.pyc`).
- Deduplicates payload carving to provide you the cleanest application source possible.

---

## Frequently Asked Questions (FAQ)

**Q: Why does `pyinstxtractor.py` find 100+ files on disk, but this memory extractor only finds ~10 files? Am I missing code?**

**A:** No, you are not missing any application code! 
When PyInstaller creates an executable on disk, it bundles hundreds of standard Python libraries (`threading`, `socket`, `urllib`, etc.) into a giant `PYZ` archive "just in case" the app needs them.
However, Python is lazily loaded. In a **Memory Dump**, the only Code objects that actively persist and decompress into RAM are the modules that your executable *actually imported and utilized*. 
This script acts as the ultimate filter—it skips all the standard library bloat and extracts exactly what is dynamically loaded, including the core application logic (e.g., `main.pyc`).

**Q: How do I read the `.pyc` files?**

**A:** You will need a Python Bytecode Decompiler matching the extracted version (often visible in the terminal output, e.g., Python 3.13):
- Use `decompyle3` (For older versions <= 3.8)
- Use `pycdc` (C++ Decompiler, supports Python 3.9 -> 3.13)
- Use standard `dis.dis()` logic in Python to read the low-level interpreter ops.
