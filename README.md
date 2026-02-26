# PyMemDump

This toolchain allows for the reverse-engineering, analysis, and extraction of internal assets from **any compiled or packed Python executable** by analyzing their live process **Memory Dumps**.

While it effectively extracts PyInstaller applications, it is a **universal** Python memory extraction tool designed to recover `.pyc`, `.pyd`, `.dll`, and other loaded assets directly from RAM. This makes it highly effective against packers, DRM solutions, and custom protectors that deliberately overwrite or encrypt metadata on disk to prevent static extraction tools from working.

By dumping the application from RAM while it is executing, we let the Python interpreter handle the decryption, unpacking, and dynamic loading, allowing us to harvest the raw code objects and libraries.

---

## Tool 1: Dumping Process Memory (`dump_process.py`)

To analyze a Python application, we first need a full snapshot of its memory space after it has been unpacked and loaded by the OS.

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

## Tool 2: Carving Python Assets (`main.py`)

Once you have the `.dmp` file, execute the main extractor against it.

Rather than relying on static offsets or specific PyInstaller structures, this tool dynamically brute-force scans the entire memory space for:
- Valid Zlib-compressed streams yielding Python `CodeObjects`.
- Uncompressed raw `marshal` payloads (`\xe3\x00\x00\x00`).
- Dynamically loaded extensions (`.pyd`, `.dll`, `.so`).

The script automatically detects the running Python Version (3.9 - 3.15) from the memory structures and prepends the exact matching `.pyc` magic header, allowing standard debuggers to decompile the output seamlessly.

**Usage:**
```cmd
python main.py target_app.exe.dmp
```

**Features:**
- Universal memory extraction for Python versions **3.9 through 3.15**.
- Works out-of-the-box with **PyInstaller** and **PyArmor (v7 or below)**.
- Extracts compiled bytecode (`.pyc`), binary extensions (`.pyd`), and shared libraries (`.dll`).
- Automatically creates and organizes outputs within an extracted directory.
- Deduplicates payload carving to provide you the cleanest application source possible.
- Agnostic to the packaging tool: **any application or protector that dynamically loads a `.pyc` or Python code object into RAM can be dumped and extracted**.
- **Nuitka Support:** Can dump loaded resources and libraries from Nuitka-compiled executables (extracts `.pyc` of libraries as long as they were not explicitly compiled/translated into Cython/C extensions).

---

## Frequently Asked Questions (FAQ)

**Q: Why do static extraction tools (like pyinstxtractor) find 100+ files on disk, but this memory extractor only finds a fraction of them? Am I missing code?**

**A:** No, you are not missing any active application code! 
When tools like PyInstaller create an executable on disk, they bundle hundreds of standard libraries "just in case" the app needs them. However, Python dynamically loads only what it actually executes. In a **Memory Dump**, the only Code objects that actively decompress into RAM are the modules that your executable *actually imported and utilized at the exact moment the dump was taken*. 
This means the tool will **only extract `.pyc` / `<code object>` files that the program has actively loaded into memory**. This acts as the ultimate filter—extracting only the core application logic (e.g., `main.pyc`) and omitting standard library bloat. If a certain feature or module wasn't triggered before you dumped the process, its code might not be extracted.

**Q: How do I read the `.pyc` files?**

**A:** You will need a Python Bytecode Decompiler matching the extracted version (often visible in the terminal output, e.g., Python 3.13):
- Use **pylingual.io** (Web-based decompiler, highly recommended for modern Python).
- Use `pycdc` (C++ Decompiler, supports Python 3.9 -> 3.15).
- Output the low-level interpreter ops using standard `dis.dis()` in Python, and feed the disassembly to an AI like **Gemini, Claude, or ChatGPT** to help reconstruct the source code.
- Use `decompyle3` (For older versions <= 3.8).

**Q: Why can't I directly `import` the extracted `.pyd` or `.dll` files in a new Python script?**

**A:** Because these binaries were dumped directly from the process memory (heap/RAM) while they were already loaded and executing. As a result, they may lack their pristine original PE headers, correct section alignments on disk, and other essential characteristics of a fully-formed file. The Windows OS loader will likely refuse to load them normally. You should only use these memory-dumped `.pyd` and `.dll` files for static reverse-engineering and analysis inside tools like **IDA Pro**, **Ghidra**, or **Binary Ninja**.
