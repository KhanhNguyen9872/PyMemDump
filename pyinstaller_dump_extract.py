import os
import sys
import zlib
import marshal
import shutil
import hashlib
import pefile
import re
import struct

# Magic numbers for Python 3.9 - 3.15
# Format: bytes magic + \r\n
# padding/timestamp/size depends on Python version (usually 16 bytes total for Python 3.7+)
PYTHON_MAGICS = {
    '3.9': b'\x61\x0d\r\n',
    '3.10': b'\x6f\x0d\r\n',
    '3.11': b'\xa7\x0d\r\n',
    '3.12': b'\xcb\x0d\r\n',
    '3.13': b'\xf3\x0d\r\n',
    '3.14': b'\x2b\x0e\r\n',
    '3.15': b'\x4c\x0e\r\n'
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

    # Detect Python version by looking for the DLL string
    py_ver = '3.13' # Default fallback
    magic_bytes = PYTHON_MAGICS[py_ver]
    
    # Try to detect via PythonXX.dll
    match = re.search(br'(?i)python3(\d+)\.dll', data)
    if match:
        minor = int(match.group(1).decode('ascii'))
        detected_version = f"3.{minor}"
        if detected_version in PYTHON_MAGICS:
            py_ver = detected_version
            magic_bytes = PYTHON_MAGICS[py_ver]
            print(f"[+] Detected Python Version: {py_ver} from python3{minor}.dll")
    else:
        # Fallback to search for known magic headers in the dump
        for version, magic in PYTHON_MAGICS.items():
            if data.find(magic) != -1:
                py_ver = version
                magic_bytes = magic
                print(f"[+] Detected Python Version: {py_ver} from magic byte signature")
                break

    print(f"[*] Using Pyc Header for Python {py_ver}")
    pyc_header = build_pyc_header(magic_bytes, py_ver)

    # marshal is strictly minor-version dependent
    current_ver = f"3.{sys.version_info.minor}"
    if current_ver != py_ver:
        print(f"[-] VERSION MISMATCH: Dump contains Python {py_ver} but script is running with Python {current_ver}!")
        sys.exit(1)

    extracted_files = 0
    extracted_names = set()
    extracted_hashes = set() # Store hashes to deduplicate identical modules

    def process_code_object(obj, raw_bytes, idx, is_zlib=False):
        nonlocal extracted_files, extracted_names, extracted_hashes
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
        if '_MEI' in clean_filename:
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
        if outname in extracted_names:
            base, ext = os.path.splitext(rel_path)
            outname = f"{base}_{idx:X}.pyc"
        extracted_names.add(outname)

        outpath = os.path.join(out_dir, outname)
        os.makedirs(os.path.dirname(outpath), exist_ok=True)
        
        with open(outpath, 'wb') as f:
            f.write(pyc_header)
            f.write(raw_bytes)
            
        prefix = "Zlib Pyc" if is_zlib else "Raw Pyc"
        print(f"  [+] Extracted {prefix}: {raw_filename} -> {outname}")
        extracted_files += 1

    print("\n[*] ----- Phase 1: Scanning for Zlib compressed Pyc Streams -----")
    for zlib_hdr in [b'\x78\x9c', b'\x78\xda', b'\x78\x01']:
        start = 0
        while True:
            idx = data.find(zlib_hdr, start)
            if idx == -1:
                break
                
            try:
                decompressed = zlib.decompress(data[idx:idx+16*1024*1024])
                if decompressed.startswith(b'\xe3'):
                    try:
                        obj = marshal.loads(decompressed)
                        if type(obj).__name__ == 'code':
                            process_code_object(obj, decompressed, idx, is_zlib=True)
                    except Exception:
                        pass
            except zlib.error:
                pass
            
            start = idx + 1

    print("\n[*] ----- Phase 2: Scanning for Uncompressed PyCode Objects -----")
    start = 0
    search_pattern = b'\xe3\x00\x00\x00\x00'
    while True:
        idx = data.find(search_pattern, start)
        if idx == -1:
            break
        
        try:
            chunk = data[idx:idx+8*1024*1024]
            obj = marshal.loads(chunk)
            if type(obj).__name__ == 'code':
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
            try:
                pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
                if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                    name_ord = pe.DIRECTORY_ENTRY_EXPORT.struct.Name
                    name_bytes = pe.get_string_at_rva(name_ord)
                    if name_bytes:
                        original_dll_name = name_bytes.decode('utf-8', 'ignore')
            except Exception:
                pass
                
            size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
            pe_data = slice_data[:size_of_image]
            
            pe_outpath = os.path.join(out_dir, original_dll_name)
            
            if os.path.exists(pe_outpath):
                base, ext = os.path.splitext(original_dll_name)
                pe_outpath = os.path.join(out_dir, f"{base}_{idx:X}{ext}")
                
            with open(pe_outpath, 'wb') as f:
                f.write(pe_data)
                
            print(f"  [+] Extracted PE Binary: {original_dll_name} (Size: {size_of_image/1024:.1f} KB)")
            extracted_pe += 1
            
            start = idx + size_of_image
        except pefile.PEFormatError:
            start = idx + 4
        except Exception:
            start = idx + 4

    extract_strings(data, os.path.join(out_dir, "strings.txt"))
    extract_zip_archives(data, out_dir)

    print(f"\n[*] Finished! Successfully extracted {extracted_files} .pyc files and {extracted_pe} PE binaries to {out_dir}/")
    print(f"[*] You can now use decompyle3 or pycdc to decompile the extracted pyc files.")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Extract PyInstaller assets from memory dumps")
    parser.add_argument("dump_file", help="Path to the memory dump (e.g. main.exe.dmp)")
    
    args = parser.parse_args()
        
    try:
        import pefile
    except ImportError:
        print("[-] python-pefile is not installed. Please install it with 'pip install pefile'")
        sys.exit(1)
        
    extract_from_memory_dump(args.dump_file)
