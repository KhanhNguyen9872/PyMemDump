import os
import sys
import zlib
import bz2
import lzma
import marshal
import shutil
import hashlib
import pefile
import re
import struct
import opcode

from minidump.minidumpfile import MinidumpFile

# Magic numbers for Python 3.9 - 3.15
# Format: bytes magic + \x0d\x0d\x0a
PYTHON_MAGICS = {
    '3.9': b'\x61\x0d\x0d\x0a',
    '3.10': b'\x6f\x0d\x0d\x0a',
    '3.11': b'\xa7\x0d\x0d\x0a',
    '3.12': b'\xcb\x0d\x0d\x0a',
    '3.13': b'\xf3\x0d\x0d\x0a',
    '3.14': b'\x2b\x0e\x0d\x0a',
    '3.15': b'\x4c\x0e\x0d\x0a'
}

def build_pyc_header(magic_bytes, py_ver):
    """
    Builds a dummy 16-byte pyc header for Python 3.7+
    Header: magic (4) + bitfield/padding (4) + timestamp (4) + file_size (4)
    """
    return magic_bytes + b'\x00' * 12

def extract_strings(data, out_path):
    """Extracts contiguous readable ASCII and Unicode strings from the binary blob."""
    print("[*] ----- Phase 4: Extracting String Artifacts -----")
    # ASCII strings of 6+ characters
    ascii_strings = re.findall(b'[\x20-\x7E]{6,}', data)
    # Basic UTF-16LE strings (every other byte is 0x00)
    utf16_strings = re.findall(b'(?:[\x20-\x7E]\x00){6,}', data)
    
    unique_strings = set()
    for s in ascii_strings:
        unique_strings.add(s.decode('ascii', 'ignore'))
        
    for s in utf16_strings:
        try:
            unique_strings.add(s.decode('utf-16le', 'ignore'))
        except:
            pass
            
    # Filter strings to ignore pure gibberish
    meaningful_strings = sorted(list(unique_strings))
    
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write("=== Extracted Strings (6+ chars) ===\n")
        f.write("Useful for finding URLs, IPs, API Keys, and plaintext Python Configs/Scripts.\n\n")
        f.write('\n'.join(meaningful_strings))
        
    print(f"  [+] Extracted {len(meaningful_strings)} unique readable strings to strings.txt")

def extract_zip_archives(data, out_dir):
    """Dynamically finds and extracts ZIP archives (which could be .zip, .jar, .docx, or wheel files)"""
    print("\n[*] ----- Phase 5: Extracting Specific File Types (ZIP, SQLite, etc.) -----")
    
    # 1. Carve ZIP Archives
    start = 0
    zip_count = 0
    zip_magic = b'PK\x03\x04'
    while True:
        idx = data.find(zip_magic, start)
        if idx == -1:
            break
            
        try:
            # A valid ZIP file EOCD record is marked by PK\x05\x06.
            # However, this sequence can randomly appear in compressed data.
            # We must search forward and validate that the EOCD cd_offset + cd_size == its own relative position
            eocd_idx = data.find(b'PK\x05\x06', idx)
            found_valid_zip = False
            
            while eocd_idx != -1 and (eocd_idx - idx) < 250 * 1024 * 1024: # max 250MB search
                # EOCD record is at least 22 bytes long
                if eocd_idx + 22 <= len(data):
                    cd_size = struct.unpack('<I', data[eocd_idx+12:eocd_idx+16])[0]
                    cd_offset = struct.unpack('<I', data[eocd_idx+16:eocd_idx+20])[0]
                    
                    # Check if the Central Directory ends exactly where this EOCD begins
                    if cd_offset + cd_size == (eocd_idx - idx):
                        comment_len = struct.unpack('<H', data[eocd_idx+20:eocd_idx+22])[0]
                        end_idx = eocd_idx + 22 + comment_len
                        
                        zip_data = data[idx:end_idx]
                        out_path = os.path.join(out_dir, f"embedded_archive_{idx:X}.zip")
                        with open(out_path, 'wb') as f:
                            f.write(zip_data)
                        
                        print(f"  [+] Extracted ZIP Archive: embedded_archive_{idx:X}.zip ({len(zip_data)/1024:.1f} KB)")
                        zip_count += 1
                        start = end_idx
                        found_valid_zip = True
                        break
                
                # Keep searching if this wasn't the true EOCD
                eocd_idx = data.find(b'PK\x05\x06', eocd_idx + 4)
                
            if found_valid_zip:
                continue
                
        except Exception:
            pass
            
        start = idx + 4

    # 2. Carve SQLite Databases
    start = 0
    sqlite_count = 0
    sqlite_magic = b'SQLite format 3\x00'
    while True:
        idx = data.find(sqlite_magic, start)
        if idx == -1:
            break
            
        try:
            # SQLite databases have page sizes defined in the header header[16:18]
            # Database size = page_size * page_count(header[28:32])
            header = data[idx:idx+100]
            if len(header) >= 32:
                page_size = struct.unpack('>H', header[16:18])[0]
                if page_size == 1:
                    page_size = 65536
                page_count = struct.unpack('>I', header[28:32])[0]
                
                db_size = page_size * page_count
                
                # Sanity check database size
                if 0 < db_size < 100 * 1024 * 1024:
                    db_data = data[idx:idx+db_size]
                    out_path = os.path.join(out_dir, f"embedded_database_{idx:X}.sqlite")
                    with open(out_path, 'wb') as f:
                        f.write(db_data)
                    print(f"  [+] Extracted SQLite Database: embedded_database_{idx:X}.sqlite ({db_size/1024:.1f} KB)")
                    sqlite_count += 1
                    start = idx + db_size
                    continue
        except Exception:
            pass
            
        start = idx + 16

    # 3. Carve PyInstaller PYZ archives
    start = 0
    pyz_count = 0
    pyz_magic = b'PYZ\x00'
    while True:
        idx = data.find(pyz_magic, start)
        if idx == -1:
            break
            
        try:
            # PYZ archives in memory dumps are tricky because they don't have a strict end marker
            # But they usually contain a TOC (Table of Contents) followed by zlib code objects.
            # A conservative 15MB dump from the PYZ signature is usually enough to capture the entire
            # bundled archive so external tools like `pyinstxtractor` can parse it.
            pyz_end = min(idx + 15 * 1024 * 1024, len(data))
            pyz_data = data[idx:pyz_end]
            
            # Write it out
            out_path = os.path.join(out_dir, f"embedded_archive_{idx:X}.pyz")
            with open(out_path, 'wb') as f:
                f.write(pyz_data)
                
            print(f"  [+] Extracted PYZ Archive: embedded_archive_{idx:X}.pyz (15.0 MB)")
            pyz_count += 1
            
            # Jump forward
            start = idx + 1024 * 1024
        except Exception:
            start = idx + 4

    print(f"  [*] Extracted {zip_count} ZIP archives, {sqlite_count} SQLite databases, and {pyz_count} PYZ archives.")



def extract_virtual_code_objects(dump_path, out_dir):
    print("\n[*] ----- Phase 6: Scanning for Live PyCodeObjects in Virtual Memory -----")
    try:
        mf = MinidumpFile.parse(dump_path)
        reader = mf.get_reader()
    except Exception as e:
        print(f"  [-] Failed to parse as Minidump: {e}")
        return

    # Find python DLL
    py_base = None
    py_size = None
    py_name = None
    for mod in mf.modules.modules:
        name = mod.name.lower()
        if 'python3' in name and name.endswith('.dll'):
            py_base = mod.baseaddress
            py_size = mod.size
            py_name = mod.name
            break

    if not py_base:
        print("  [-] Could not find python3X.dll in the minidump's loaded modules.")
        return

    print(f"  [+] Found {py_name} at base {hex(py_base)}")

    # Read DLL headers from local system to avoid minidump page boundary errors
    try:
        import sys, os
        dll_path = os.path.join(sys.base_exec_prefix, py_name)
        if not os.path.exists(dll_path):
            print(f"  [-] Could not find {py_name} locally at {dll_path} to resolve PyCode_Type.")
            return
            
        pe = pefile.PE(dll_path)
        pe.parse_data_directories([pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
        pycode_type_rva = None
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name == b'PyCode_Type':
                    pycode_type_rva = exp.address
                    break
        if not pycode_type_rva:
            print("  [-] Could not find PyCode_Type export in the Python DLL.")
            return
            
        pycode_type_ptr = py_base + pycode_type_rva
        print(f"  [+] PyCode_Type absolute pointer located at: {hex(pycode_type_ptr)}")
    except Exception as e:
        print(f"  [-] Error reading Python DLL locally: {e}")
        return

    # Scan virtual memory for this pointer
    target_bytes = struct.pack("<Q", pycode_type_ptr)
    
    def read_str(addr):
        if addr == 0: return ""
        try:
            head = reader.read(addr, 50)
            length = struct.unpack("<q", head[16:24])[0]
            if 0 < length < 1000:
                for offset in (40, 48):
                    try: return reader.read(addr + offset, length).decode('utf-8')
                    except: pass
            return ""
        except Exception: return ""

    def dump_tuple(addr):
        if addr == 0: return tuple()
        try:
            head = reader.read(addr, 24)
            size = struct.unpack("<q", head[16:24])[0]
            if size < 0 or size > 1000: return tuple()
            items = []
            for i in range(size):
                item_ptr = struct.unpack("<Q", reader.read(addr + 24 + i*8, 8))[0]
                s = read_str(item_ptr)
                if s:
                    items.append(s)
                else:
                    # Placeholder for non-string constants (e.g. ints, None, nested code objs)
                    # We inject a dummy integer so marshal doesn't fail
                    items.append(i)
            return tuple(items)
        except Exception:
            return tuple()

    def dump_nested_codeobj(obj_addr, depth=0, outf=None):
        prefix = "  " * depth
        try:
            struct_data = reader.read(obj_addr, 200)
            co_consts_ptr = struct.unpack("<Q", struct_data[24:32])[0]
            co_names_ptr = struct.unpack("<Q", struct_data[32:40])[0]
            co_filename = struct.unpack("<Q", struct_data[112:120])[0]
            co_name = struct.unpack("<Q", struct_data[120:128])[0]
            
            name_str = read_str(co_name)
            filename_str = read_str(co_filename)
            outf.write(f"{prefix}CodeObj @ {hex(obj_addr)}: name={name_str!r}, file={filename_str!r}\n")
            
            if co_names_ptr != 0:
                try:
                    head = reader.read(co_names_ptr, 24)
                    size = struct.unpack("<q", head[16:24])[0]
                    if 0 < size < 1000:
                        names = []
                        for i in range(size):
                            item_ptr = struct.unpack("<Q", reader.read(co_names_ptr + 24 + i*8, 8))[0]
                            names.append(read_str(item_ptr))
                        outf.write(f"{prefix}  Names: {names}\n")
                except: pass
                
            if co_consts_ptr != 0:
                try:
                    head = reader.read(co_consts_ptr, 24)
                    size = struct.unpack("<q", head[16:24])[0]
                    if 0 < size < 1000:
                        for i in range(size):
                            item_ptr = struct.unpack("<Q", reader.read(co_consts_ptr + 24 + i*8, 8))[0]
                            s = read_str(item_ptr)
                            if s:
                                outf.write(f"{prefix}  Const[{i}]: (str) {s!r}\n")
                            else:
                                try:
                                    item_type = struct.unpack("<Q", reader.read(item_ptr + 8, 8))[0]
                                    if item_type == pycode_type_ptr:
                                        outf.write(f"{prefix}  Const[{i}]: NESTED CODEOBJ\n")
                                        dump_nested_codeobj(item_ptr, depth+2, outf)
                                    else:
                                        outf.write(f"{prefix}  Const[{i}]: <ptr {hex(item_ptr)} type {hex(item_type)}>\n")
                                except: pass
                except: pass
        except Exception as e:
            outf.write(f"{prefix}Error: {e}\n")

    def disassemble_codeobj(obj_addr, outf=None):
        try:
            struct_data = reader.read(obj_addr, 200)
            co_consts_ptr = struct.unpack("<Q", struct_data[24:32])[0]
            co_names_ptr = struct.unpack("<Q", struct_data[32:40])[0]
            co_filename = struct.unpack("<Q", struct_data[112:120])[0]
            
            consts = dump_tuple(co_consts_ptr)
            names = tuple(str(x) for x in dump_tuple(co_names_ptr))
            
            outf.write(f"{'='*40}\nDisassembling CodeObj @ {hex(obj_addr)}\n{'='*40}\n")
            outf.write(f"File: {read_str(co_filename)}\n")
            outf.write(f"Names: {names}\n")
            outf.write(f"Consts: {consts}\n\n")
            
            bytecode = reader.read(obj_addr + 160, 500)
            
            i = 0
            while i < len(bytecode):
                op = bytecode[i]
                arg = bytecode[i+1]
                
                opname = opcode.opname[op]
                if not opname.startswith("<"):
                    argval = ""
                    if opname in opcode.hasconst and arg < len(consts): argval = f"({consts[arg]})"
                    elif opname in opcode.hasname and arg < len(names): argval = f"({names[arg]})"
                    elif opname in opcode.hasjrel: argval = f"(to {i + 2 + arg*2})"
                    elif opname in opcode.hasjabs: argval = f"(to {arg*2})"
                    
                    outf.write(f"{i:4} {opname:20} {arg} {argval}\n")
                    if opname == 'RETURN_VALUE':
                        break
                i += 2
        except Exception as e:
            outf.write(f"Error disassembling: {e}\n")

    def build_pyc_from_memory(obj_addr, name_str, out_path):
        try:
            struct_data = reader.read(obj_addr, 250)
            
            co_argcount = struct.unpack("<i", struct_data[0:4])[0]
            co_posonlyargcount = struct.unpack("<i", struct_data[56:60])[0]
            co_kwonlyargcount = struct.unpack("<i", struct_data[60:64])[0]
            co_nlocals = struct.unpack("<i", struct_data[16:20])[0]
            co_stacksize = struct.unpack("<i", struct_data[4:8])[0]
            co_flags = struct.unpack("<i", struct_data[8:12])[0]
            co_firstlineno = struct.unpack("<i", struct_data[40:44])[0]
            
            co_consts_ptr = struct.unpack("<Q", struct_data[24:32])[0]
            co_names_ptr = struct.unpack("<Q", struct_data[32:40])[0]
            co_varnames_ptr = struct.unpack("<Q", struct_data[48:56])[0]
            co_filename_ptr = struct.unpack("<Q", struct_data[112:120])[0]
            co_name_ptr = struct.unpack("<Q", struct_data[120:128])[0]
            
            consts = dump_tuple(co_consts_ptr)
            names = dump_tuple(co_names_ptr)
            varnames = dump_tuple(co_varnames_ptr)
            filename = read_str(co_filename_ptr) or "unknown"
            name = read_str(co_name_ptr) or "unknown"
            
            bytecode = reader.read(obj_addr + 160, 500) # heuristic read length
            # truncate payload slightly for safety
            
            try:
                # In Python 3.12, CodeType() constructor is extremely strict. 
                # Create a generic dummy function and use its code object properties.
                def dummy(): pass
                c_dummy = dummy.__code__
                
                # Create a new code object dynamically matching Python 3.12 structure
                # Because the raw memory could contain invalid jump targets, we construct
                # a minimal valid code object preserving just the user's data fields
                c = c_dummy.replace(
                    co_consts=consts,
                    co_names=names,
                    co_varnames=varnames,
                    co_filename=filename,
                    co_name=name,
                    co_qualname=name,
                )
                
                pyc_bytes = build_pyc_header(PYTHON_MAGICS['3.12'], '3.12') + marshal.dumps(c)
                
                # Append raw bytecode as a separate readable block or comment if possible
                with open(out_path, "wb") as f_out:
                    f_out.write(pyc_bytes)
                print(f"  [+] Reconstructed valid metadata PyCodeObject -> {out_path}")
                
                # Always dump hex to be safe because code instructions cannot be easily 
                # injected into a clean `types.CodeType` instance without failing opcode assertions
                with open(out_path + ".hex", "wb") as f_out:
                    f_out.write(bytecode)
                    
            except Exception as e:
                # Fallback if code.replace fails
                print(f"  [-] Recompilation failed for {name_str}: {e}. Saving raw hex trace instead.")
                with open(out_path + ".hex", "wb") as f_out:
                    f_out.write(bytecode)
                    
        except Exception as e:
            print(f"  [-] Error extracting PyCodeObject memory: {e}")

    out_file = os.path.join(out_dir, "all_objs.txt")
    print(f"  [*] Scanning all virtual segments... writing log to {out_file}")
    
    found = 0
    with open(out_file, "w", encoding="utf-8") as outf:
        outf.write(f"=== Live PyCodeObject Dump (Pointer: {hex(pycode_type_ptr)}) ===\n\n")
        outf.write(f"{'Memory Address':<20} | {'Object Name':<40} | {'Defined Filename'}\n")
        outf.write("-" * 100 + "\n")
        
        for segment in mf.memory_segments_64.memory_segments:
            size = segment.size
            addr = segment.start_virtual_address
            try:
                data = reader.read(addr, size)
            except:
                continue
                
            idx = 0
            while True:
                idx = data.find(target_bytes, idx)
                if idx == -1: break
                
                obj_addr = addr + idx - 8 # offset to start of generic object struct
                try:
                    struct_data = reader.read(obj_addr, 200)
                    
                    # Offsets in 64-bit Python (rough heuristics for >= 3.10)
                    co_filename = struct.unpack("<Q", struct_data[112:120])[0]
                    co_name = struct.unpack("<Q", struct_data[120:128])[0]
                    
                    name_str = read_str(co_name)
                    filename_str = read_str(co_filename)
                    if name_str or filename_str:
                        outf.write(f"{hex(obj_addr):<20} | {name_str:<40} | {filename_str}\n")
                        found += 1
                        
                        # Check interesting payload targets user requested
                        if '<_huynhngocuyen_system_runner' in filename_str or ('<module>' == name_str and '<string>' == filename_str):
                            safe_file = filename_str.replace('<', '').replace('>', 'obj')
                            
                            out_path = os.path.join(out_dir, f"reconstructed_{safe_file}_{hex(obj_addr)}.pyc")
                            build_pyc_from_memory(obj_addr, name_str, out_path)
                            
                            txt_path = os.path.join(out_dir, f"analytics_{safe_file}_{hex(obj_addr)}.txt")
                            with open(txt_path, "w", encoding="utf-8") as analytics_file:
                                analytics_file.write("--- NESTED CODEOBJ STRUCTURE ---\n")
                                dump_nested_codeobj(obj_addr, 0, analytics_file)
                                analytics_file.write("\n\n--- INLINE DISASSEMBLY (Python 3.12) ---\n")
                                disassemble_codeobj(obj_addr, analytics_file)
                            print(f"  [+] Saved deep analytics to -> {txt_path}")
                            
                except Exception:
                    pass
                    
                idx += 8

    print(f"  [+] Found {found} active PyCodeObjects in process heap.")


def extract_from_memory_dump(dump_path):

    if not os.path.exists(dump_path):
        print(f"Error: Could not find '{dump_path}'")
        sys.exit(1)

    # Creating output directory based on the dump name
    out_dir = dump_path + "_extracted"
    if os.path.exists(out_dir):
        print(f"[*] Removing existing directory: {out_dir}")
        shutil.rmtree(out_dir)
    os.makedirs(out_dir)

    print(f"[*] Reading {dump_path} into memory...")
    try:
        with open(dump_path, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f"[-] Error reading file: {e}")
        return

    # Priority 1: Try to detect via PythonXX.dll (Windows) or libpython3.X.so (Linux)
    match_dll = re.search(br'(?i)python3(\d+)\.dll', data)
    match_so = re.search(br'(?i)libpython3\.(\d+)\.so', data)
    
    detected_version = None
    if match_dll:
        minor = int(match_dll.group(1).decode('ascii'))
        detected_version = f"3.{minor}"
        print(f"[+] Detected Python Version: {detected_version} from python3{minor}.dll")
    elif match_so:
        minor = int(match_so.group(1).decode('ascii'))
        detected_version = f"3.{minor}"
        print(f"[+] Detected Python Version: {detected_version} from libpython3.{minor}.so")

    if detected_version and detected_version in PYTHON_MAGICS:
        py_ver = detected_version
        magic_bytes = PYTHON_MAGICS[py_ver]
    else:
        # Priority 2: Search for known magic headers in the dump
        # We prioritize the running version of Python to avoid false positives with older versions
        current_ver = f"{sys.version_info.major}.{sys.version_info.minor}"
        found_versions = []
        for version, magic in PYTHON_MAGICS.items():
            if data.find(magic) != -1:
                found_versions.append(version)
        
        if found_versions:
            if current_ver in found_versions:
                py_ver = current_ver
            else:
                # If current version is not found, take the highest found version (likely the target)
                py_ver = sorted(found_versions, key=lambda v: [int(x) for x in v.split('.')])[-1]
            
            magic_bytes = PYTHON_MAGICS[py_ver]
            print(f"[+] Detected Python Version: {py_ver} from magic byte signature (candidates: {', '.join(found_versions)})")
        else:
            print("[!] Could not detect Python version automatically. Falling back to 3.12")
            py_ver = '3.12'
            magic_bytes = PYTHON_MAGICS[py_ver]

    print(f"[*] Using Pyc Header for Python {py_ver}")
    pyc_header = build_pyc_header(magic_bytes, py_ver)

    # marshal is strictly minor-version dependent
    current_ver = f"{sys.version_info.major}.{sys.version_info.minor}"
    if current_ver != py_ver:
        print(f"[-] VERSION MISMATCH: Dump contains Python {py_ver} but script is running with Python {current_ver}!")
        print(f"[*] Please run the extraction script with Python {py_ver} to match the target.")
        sys.exit(1)

    extracted_files = 0
    extracted_names = set()
    
    # Store hashes and code object signatures to deduplicate identical modules
    extracted_hashes = set()
    extracted_code_signatures = {} # outname -> signature hash

    def get_code_signature(obj):
        """Creates a deterministic hash of the critical parts of a python code object"""
        hasher = hashlib.md5()
        for attr in ['co_argcount', 'co_posonlyargcount', 'co_kwonlyargcount', 
                     'co_nlocals', 'co_stacksize', 'co_flags', 'co_code', 
                     'co_consts', 'co_names', 'co_varnames', 'co_freevars', 'co_cellvars']:
            val = getattr(obj, attr, None)
            if val is not None:
                if attr == 'co_consts':
                    # co_consts can contain nested code objects, which evaluate to <code object at 0x...> string
                    # This memory address changes per load! We must hash nested code objects recursively.
                    consts_repr = []
                    for c in val:
                        if type(c).__name__ == 'code':
                            consts_repr.append(get_code_signature(c).hex())
                        else:
                            consts_repr.append(repr(c))
                    hasher.update(str(consts_repr).encode('utf-8', 'ignore'))
                else:
                    hasher.update(str(val).encode('utf-8', 'ignore'))
        return hasher.digest()

    def process_code_object(obj, raw_bytes, idx, is_zlib=False, comp_name="Zlib"):
        nonlocal extracted_files, extracted_names, extracted_hashes, extracted_code_signatures
        try:
            raw_filename = str(obj.co_filename)
        except AttributeError:
            # Not a code object or malformed
            return

        # Deduplicate identical bytecode payloads
        payload_hash = hashlib.sha512(raw_bytes).hexdigest()
        if payload_hash in extracted_hashes:
            return  # Skip identical duplicates
        
        extracted_hashes.add(payload_hash)

        clean_filename = raw_filename.replace('\\', '/')
        if clean_filename.startswith('<frozen ') and clean_filename.endswith('>'):
            # e.g '<frozen importlib._bootstrap>' -> 'importlib._bootstrap' -> 'importlib/_bootstrap.py'
            module_name = clean_filename[8:-1]
            rel_path = module_name.replace('.', '/') + '.py'
        elif '_MEI' in clean_filename:
            parts = clean_filename.split('/')
            try:
                mei_idx = next(i for i, part in enumerate(parts) if part.startswith('_MEI'))
                rel_path = '/'.join(parts[mei_idx+1:])
            except StopIteration:
                rel_path = clean_filename.split('/')[-1]
        else:
            if ':' in clean_filename:
                clean_filename = clean_filename.split(':')[-1]
            rel_path = clean_filename.lstrip('/')
            
        if not rel_path.endswith('.py'):
            rel_path = f"unknown_module_{idx:X}.py"

        rel_path_c = rel_path + "c"
        outname = rel_path_c
        
        # Calculate a signature for this specific code object
        sig = get_code_signature(obj)
        
        # If a file with this name already exists, check if it's the exact same code
        if outname in extracted_names:
            if extracted_code_signatures.get(outname) == sig:
                # Code is identical (probably just 0-pad/metadata differences), skip extracting duplicate
                return
            else:
                # Code is different but same name (e.g two different scripts with same name), write with hex suffix
                base, ext = os.path.splitext(rel_path)
                outname = f"{base}_{idx:X}.pyc"
                
        extracted_names.add(outname)
        extracted_code_signatures[outname] = sig

        outpath = os.path.join(out_dir, outname)
        os.makedirs(os.path.dirname(outpath), exist_ok=True)
        
        with open(outpath, 'wb') as f:
            f.write(pyc_header)
            f.write(raw_bytes)
            
        prefix = f"{comp_name} Pyc" if is_zlib else "Raw Pyc"
        print(f"  [+] Extracted {prefix}: {raw_filename} -> {outname}")
        extracted_files += 1

    print("\n[*] ----- Phase 1: Scanning for Compressed Pyc Streams (ZLIB, GZIP, BZ2, LZMA) -----")
    
    # We define headers and their corresponding decompressor factory functions
    compressors = [
        (b'\x78\x9c', 'Zlib', lambda: zlib.decompressobj()),
        (b'\x78\xda', 'Zlib', lambda: zlib.decompressobj()),
        (b'\x78\x01', 'Zlib', lambda: zlib.decompressobj()),
        (b'\x1f\x8b\x08', 'GZIP', lambda: zlib.decompressobj(wbits=31)),
        (b'BZh', 'BZ2', lambda: bz2.BZ2Decompressor()),
        (b'\xfd7zXZ\x00', 'LZMA', lambda: lzma.LZMADecompressor())
    ]
    
    for magic_hdr, comp_name, decompressor_factory in compressors:
        start = 0
        while True:
            idx = data.find(magic_hdr, start)
            if idx == -1:
                break
                
            try:
                # Create a fresh decompressor object
                d = decompressor_factory()
                
                # Decompress up to 16MB chunk
                decompressed = d.decompress(data[idx:idx+16*1024*1024])
                
                if decompressed:
                    # Check for Python < 3.12 marshal magic or Python >= 3.12 marshal magic
                    if decompressed.startswith(b'\xe3') or decompressed.startswith(b'c\x00\x00\x00'):
                        try:
                            obj = marshal.loads(decompressed)
                            if type(obj).__name__ == 'code':
                                process_code_object(obj, decompressed, idx, is_zlib=True, comp_name=comp_name)
                        except Exception:
                            pass
                    else:
                        # PyInstaller sometimes embeds whole .pyc files (with 16-byte headers)
                        if len(decompressed) > 16:
                            magic = decompressed[:4]
                            if magic in PYTHON_MAGICS.values():
                                try:
                                    obj = marshal.loads(decompressed[16:])
                                    if type(obj).__name__ == 'code':
                                        process_code_object(obj, decompressed[16:], idx, is_zlib=True, comp_name=comp_name)
                                except Exception:
                                    pass
                            
            except Exception: # Catch zlib, bz2, lzma, and marshal errors
                pass
            
            start = idx + 1

    print("\n[*] ----- Phase 2: Scanning for Uncompressed PyCode Objects -----")
    for search_pattern in [b'\xe3\x00\x00\x00\x00', b'c\x00\x00\x00\x00\x00\x00\x00\x00']:
        start = 0
        while True:
            idx = data.find(search_pattern, start)
            if idx == -1:
                break
            
            try:
                chunk = data[idx:idx+8*1024*1024]
                obj = marshal.loads(chunk)
                if type(obj).__name__ == 'code':
                    # For Python 3.12 marshal, we need to correctly reserialize it
                    process_code_object(obj, marshal.dumps(obj), idx, is_zlib=False)
            except Exception:
                pass
            
            start = idx + 1

    print("\n[*] ----- Phase 3: Extracting Embedded PE Binaries (DLL / PYD) -----")
    start = 0
    extracted_pe = 0
    while True:
        idx = data.find(b'MZ\x90\x00', start)
        if idx == -1:
            break
            
        try:
            slice_data = data[idx:idx+20*1024*1024]
            pe = pefile.PE(data=slice_data, fast_load=True)
            
            original_dll_name = f"embedded_{idx:X}.dll"
            is_pyd = False
            
            try:
                # We use fast_load for speed, so we must manually parse EXPORT and RESOURCE dirs
                pe.parse_data_directories(directories=[
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']
                ])
                if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                    name_ord = pe.DIRECTORY_ENTRY_EXPORT.struct.Name
                    name_bytes = pe.get_string_at_rva(name_ord)
                    if name_bytes:
                        original_dll_name = name_bytes.decode('utf-8', 'ignore')
                        if original_dll_name.endswith('.pyd'):
                            is_pyd = True
            except Exception:
                pass
                
            size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
            pe_data = slice_data[:size_of_image]
            
            # Heuristic detection for generic missing DLL names
            if original_dll_name.startswith("embedded_"):
                # 0. Try to extract name from StringFileInfo Version Info
                try:
                    for fileinfo in pe.FileInfo:
                        for d in fileinfo:
                            if d.name == 'StringFileInfo':
                                for st in d.StringTable:
                                    orig_name = st.entries.get(b'OriginalFilename', b'').decode('utf-8', 'ignore')
                                    internal_name = st.entries.get(b'InternalName', b'').decode('utf-8', 'ignore')
                                    
                                    name_cand = None
                                    if internal_name and '.dll' in internal_name.lower():
                                        name_cand = internal_name
                                    elif orig_name and '.dll' in orig_name.lower():
                                        name_cand = orig_name
                                        
                                    if name_cand:
                                        if name_cand.lower().endswith('.mui'):
                                            name_cand = name_cand[:-4]
                                        original_dll_name = name_cand
                                        break
                except Exception:
                    pass
                
            if original_dll_name.startswith("embedded_"):
                # 1. Try to find a PDB debug string path (e.g C:\\...\\vcruntime140.amd64.pdb)
                pdb_path = re.search(b'([a-zA-Z0-9_\\-\\.]+)\\.pdb', pe_data, re.IGNORECASE)
                if pdb_path:
                    guessed_name = pdb_path.group(1).decode('utf-8', 'ignore') + '.dll'
                    original_dll_name = guessed_name
                else:
                    # 2. Try to find the first string that looks like a .dll name
                    dll_name = re.search(b'([a-zA-Z0-9_\\-\\.]+)\\.dll', pe_data, re.IGNORECASE)
                    if dll_name:
                        original_dll_name = dll_name.group()[:64].decode('utf-8', 'ignore')
            
            # Heuristic detection for Python C-Extensions (Cython / PyInstaller modules)
            if original_dll_name.startswith("embedded_") or original_dll_name.endswith(".dll"):
                # Search the PE binary for strings ending in .pyx or .py
                matches = set(re.findall(b'([a-zA-Z_][a-zA-Z0-9_]*)\\.(?:pyx|py)', pe_data))
                if matches:
                    is_pyd = True
                    # Take the longest match or the first match as the module name
                    best_match = max(matches, key=len).decode('utf-8', 'ignore')
                    original_dll_name = f"{best_match}.pyd"
                elif b'PyInit_' in pe_data or b'cython' in pe_data.lower() or b'pybind11' in pe_data.lower():
                    is_pyd = True
                    original_dll_name = f"embedded_python_extension_{idx:X}.pyd"
            
            if is_pyd and original_dll_name.endswith('.dll'):
                original_dll_name = original_dll_name[:-4] + '.pyd'
            
            pe_outpath = os.path.join(out_dir, original_dll_name)
            
            if os.path.exists(pe_outpath):
                base, ext = os.path.splitext(original_dll_name)
                pe_outpath = os.path.join(out_dir, f"{base}_{idx:X}{ext}")
                
            type_str = "PYD Extension" if is_pyd else "PE Binary"
            print(f"  [+] Extracted {'PYD Extension' if is_pyd else 'PE Binary'}: {original_dll_name} (Size: {size_of_image / 1024:.1f} KB)")
            
            # Apply PE Header Unmapping before saving
            try:
                # The extracted bytes are in Memory Layout (Virtual Address)
                # We need to unmap them to Disk Layout (Raw Offset) so analysis tools can read them
                for section in pe.sections:
                    section.PointerToRawData = section.VirtualAddress
                    section.SizeOfRawData = max(section.Misc_VirtualSize, section.SizeOfRawData)
                # Ensure Windows loader/IDA knows the file alignment constraint
                pe.OPTIONAL_HEADER.FileAlignment = pe.OPTIONAL_HEADER.SectionAlignment
                pe_data = pe.write()
            except Exception as e:
                # If unmapping fails, fallback to raw memory dump write
                pass
                
            with open(pe_outpath, 'wb') as f:
                f.write(pe_data)
            
            extracted_pe += 1
            
            start = idx + size_of_image
        except pefile.PEFormatError:
            start = idx + 4
        except Exception:
            start = idx + 4

    extract_strings(data, os.path.join(out_dir, "strings.txt"))

    extract_zip_archives(data, out_dir)
    extract_virtual_code_objects(dump_path, out_dir)

    print(f"\n[*] Finished! Successfully extracted {extracted_files} .pyc files and {extracted_pe} PE binaries to {out_dir}/")
    print(f"[*] You can now use decompyle3 or pycdc to decompile the extracted pyc files.")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Extract PyInstaller assets from memory dumps")
    parser.add_argument("dump_file", help="Path to the memory dump (e.g. main.exe.dmp)")
    
    args = parser.parse_args()
        
    try:
        import pefile
        from minidump.minidumpfile import MinidumpFile
    except ImportError:
        print("[-] Missing required libraries. Please install them with 'pip install pefile minidump'")
        sys.exit(1)
        
    extract_from_memory_dump(args.dump_file)
