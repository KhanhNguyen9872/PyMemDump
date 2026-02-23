import os
import sys
import zlib
import marshal
import shutil
import hashlib

# Magic numbers for Python 3.10 - 3.14
# Format: bytes magic + \r\n
# padding/timestamp/size depends on Python version (usually 16 bytes total for Python 3.7+)
PYTHON_MAGICS = {
    '3.10': b'\x6f\x0d\r\n',
    '3.11': b'\xa7\x0d\r\n',
    '3.12': b'\xcb\x0d\r\n',
    '3.13': b'\xf3\x0d\r\n',
    '3.14': b'\x05\x0e\r\n'  # Note: 3.14 may change as it's unreleased, using a placeholder/approx
}

def build_pyc_header(magic_bytes, py_ver):
    """
    Builds a dummy 16-byte pyc header for Python 3.7+
    Header: magic (4) + bitfield/padding (4) + timestamp (4) + file_size (4)
    """
    return magic_bytes + b'\x00' * 12

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
    import re
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
        # We hash the raw marshal bytes so if the exact same compiled script is loaded into 
        # multiple locations in memory, we only extract it once!
        payload_hash = hashlib.md5(raw_bytes).hexdigest()
        if payload_hash in extracted_hashes:
            return  # Skip identical duplicates
        
        extracted_hashes.add(payload_hash)

        # Replace backslashes with forward slashes for cross-platform processing
        clean_filename = raw_filename.replace('\\', '/')
        
        # If the path contains the pyinstaller temp directory temp_dir stuff, we just want the relative path inside it
        if '_MEI' in clean_filename:
            parts = clean_filename.split('/')
            try:
                mei_idx = next(i for i, part in enumerate(parts) if part.startswith('_MEI'))
                rel_path = '/'.join(parts[mei_idx+1:])
            except StopIteration:
                rel_path = clean_filename.split('/')[-1]
        else:
            # It might just be raw relative paths like zipfile/_path/glob.py
            # We strip off absolute root markers like C:/ or /usr/ if present
            if ':' in clean_filename:
                clean_filename = clean_filename.split(':')[-1]
            rel_path = clean_filename.lstrip('/')
            
        if not rel_path.endswith('.py'):
            rel_path = f"unknown_module_{idx:X}.py"

        # Change .py extension to .pyc
        rel_path_c = rel_path + "c"
        
        # In case different files identically named exist but have different hashes
        outname = rel_path_c
        if outname in extracted_names:
            base, ext = os.path.splitext(rel_path)
            outname = f"{base}_{idx:X}.pyc"
        extracted_names.add(outname)

        outpath = os.path.join(out_dir, outname)
        
        # Ensure the subdirectories exist
        os.makedirs(os.path.dirname(outpath), exist_ok=True)
        
        with open(outpath, 'wb') as f:
            f.write(pyc_header)
            f.write(raw_bytes)
            
        prefix = "Zlib Pyc" if is_zlib else "Raw Pyc"
        print(f"  [+] Extracted {prefix}: {raw_filename} -> {outname}")
        extracted_files += 1

    print("\n[*] ----- Phase 1: Scanning for Zlib compressed Pyc Streams -----")
    # Search for common Zlib headers
    for zlib_hdr in [b'\x78\x9c', b'\x78\xda', b'\x78\x01']:
        start = 0
        while True:
            idx = data.find(zlib_hdr, start)
            if idx == -1:
                break
                
            try:
                # Try decompressing 16MB slices
                decompressed = zlib.decompress(data[idx:idx+16*1024*1024])
                # Check if it's a marshal object (type code \xe3)
                if decompressed.startswith(b'\xe3'):
                    try:
                        # Validate the marshal object
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
    # PyCode objects in marshal start with \xe3 followed by 0 for argcounts in modules
    search_pattern = b'\xe3\x00\x00\x00\x00'
    while True:
        idx = data.find(search_pattern, start)
        if idx == -1:
            break
        
        try:
            # We slice a big chunk so marshal.loads has enough data to parse the whole object
            chunk = data[idx:idx+8*1024*1024]
            # Try loading the code object
            obj = marshal.loads(chunk)
            if type(obj).__name__ == 'code':
                process_code_object(obj, marshal.dumps(obj), idx, is_zlib=False)
        except Exception:
            pass
        
        start = idx + 1

    print(f"\n[*] Finished! Successfully extracted {extracted_files} unique .pyc files to {out_dir}/")
    print(f"[*] You can now use decompyle3 or pycdc to decompile the extracted pyc files.")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python pyinstaller_dump_extract.py <main.exe.dmp>")
        sys.exit(1)
        
    dump_file = sys.argv[1]
    extract_from_memory_dump(dump_file)
