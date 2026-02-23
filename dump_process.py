import os
import sys
import ctypes
import psutil

# Windows API Constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MINIDUMP_WITH_FULL_MEMORY = 0x00000002

# Load Windows DLLs
dbghelp = ctypes.windll.dbghelp
kernel32 = ctypes.windll.kernel32

def is_admin():
    """Returns True if the script is running with Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def run_as_admin():
    """Relaunches the current script with Administrator privileges using Windows UAC."""
    print("[*] Requesting Administrator privileges...")
    
    # sys.executable is the path to python.exe
    # sys.argv contains the script path and its arguments
    script = os.path.abspath(sys.argv[0])
    params = ' '.join([script] + sys.argv[1:])
    
    # 1 specifies SW_SHOWNORMAL
    res = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    
    if res <= 32:
        print("[-] Failed to elevate privileges or user cancelled the UAC prompt.")
        sys.exit(1)
    
    # If successful, this original unprivileged process can just exit, 
    # since the new elevated window is taking over.
    sys.exit(0)

def get_pid_by_name(process_name):
    """Finds a running process ID by its executable name."""
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] and proc.info['name'].lower() == process_name.lower():
                return proc.info['pid']
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return None

def create_memory_dump(pid, output_filename):
    """Creates a full memory dump of the target process using Windows dbghelp API."""
    # Open the process with required privileges
    process_handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    
    if not process_handle:
        print(f"[-] Failed to open process PID {pid}. Ensure the target process is running.")
        return False
        
    print(f"[*] Opened process {pid} successfully.")
    
    # Windows CreateFile Constants
    GENERIC_WRITE = 0x40000000
    CREATE_ALWAYS = 2
    FILE_ATTRIBUTE_NORMAL = 0x80
    
    # Open file handle for writing the dump
    file_handle = kernel32.CreateFileW(
        output_filename,
        GENERIC_WRITE,
        0,
        None,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        None
    )
    
    if file_handle == -1: # INVALID_HANDLE_VALUE
        print(f"[-] Failed to create output file: {output_filename}")
        kernel32.CloseHandle(process_handle)
        return False
        
    print(f"[*] Writing full memory dump to {output_filename}...")
    print(f"[*] Please wait, this may take a moment and produce a large file...")
    
    # Invoke MiniDumpWriteDump from dbghelp.dll
    success = dbghelp.MiniDumpWriteDump(
        process_handle,
        pid,
        file_handle,
        MINIDUMP_WITH_FULL_MEMORY,
        None,
        None,
        None
    )
    
    # Clean up handles
    kernel32.CloseHandle(file_handle)
    kernel32.CloseHandle(process_handle)
    
    if success:
        dump_size = os.path.getsize(output_filename) / (1024 * 1024)
        print(f"[+] Success! Dump created: {output_filename} ({dump_size:.2f} MB)")
        input("Press Enter to exit...")  # Keeps the new admin window open so the user can read the result
        return True
    else:
        print(f"[-] Memory dump failed. Error Code: {kernel32.GetLastError()}")
        input("Press Enter to exit...")
        return False

def main():
    if len(sys.argv) < 2:
        print("Usage: python dump_process.py <ProcessName.exe | PID>")
        input("Press Enter to exit...")
        sys.exit(1)
        
    if not is_admin():
        run_as_admin()
        return

    target = sys.argv[1]
    
    # Check if target is a PID or a process name
    if target.isdigit():
        pid = int(target)
        output_filename = f"process_{pid}.dmp"
    else:
        pid = get_pid_by_name(target)
        if pid is None:
            print(f"[-] Could not find any running process named '{target}'.")
            input("Press Enter to exit...")
            sys.exit(1)
        output_filename = f"{target}.dmp"
        
    print(f"[*] Target Process: {target} (PID: {pid})")
    create_memory_dump(pid, output_filename)

if __name__ == '__main__':
    main()
