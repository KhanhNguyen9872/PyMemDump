# -*- coding: utf-8 -*-
import os
import sys
import subprocess
import platform

# Ensure psutil is installed
def install_psutil():
    print("[*] psutil is not installed. Attempting to install...")
    os_name = platform.system()
    
    def try_pip():
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil", "--break-system-packages"])
            return True
        except Exception:
            return False

    if try_pip(): return True

    # If pip fails and we are on Linux/Termux, try to install pip or system package
    if os_name == "Linux":
        is_termux = "TERMUX_VERSION" in os.environ or os.path.exists("/data/data/com.termux")
        
        if is_termux:
            print("[*] Termux detected. Ensuring pip and build tools...")
            try:
                # In Termux, pip is usually in the 'python' package
                subprocess.check_call(["pkg", "install", "python", "-y"])
                if try_pip(): return True
                
                # If pip install still fails, psutil might need compilation
                print("[*] psutil might need compilation. Installing build tools...")
                subprocess.check_call(["pkg", "install", "python3-pip", "python3-dev", "clang", "make", "binutils", "-y"])
                if try_pip(): return True
                
                # Last resort: try pkg package if it works now
                subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil"])
                return True
            except Exception:
                pass
        else:
            # General Linux
            print("[*] Linux detected. Attempting to install pip/psutil via apt...")
            try:
                subprocess.check_call(["sudo", "apt", "update", "-y"])
                # Try to install pip first
                subprocess.check_call(["sudo", "apt", "install", "python3-pip", "-y"])
                if try_pip(): return True
                
                # Try system package as fallback
                subprocess.check_call(["sudo", "apt", "install", "python3-psutil", "-y"])
                return True
            except Exception:
                pass

    return False

try:
    import psutil
except ImportError:
    if install_psutil():
        try:
            import psutil
            print("[+] psutil installed successfully.")
        except ImportError:
            print("[-] psutil installed but still cannot be imported.")
            sys.exit(1)
    else:
        print("[-] Failed to install psutil automatically.")
        print("[!] Please install psutil manually: \n    - Windows: pip install psutil\n    - Linux: sudo apt install python3-psutil\n    - Termux: pkg install python-psutil")
        sys.exit(1)

class ProcessDumper:
    def __init__(self, target):
        self.target = target
        self.pid = self._resolve_pid(target)
        self.process_name = self._get_process_name()
        self.output_filename = f"{self.process_name or 'process'}_{self.pid}.dmp"

    def _resolve_pid(self, target):
        if target.isdigit():
            return int(target)
        
        matches = []
        current_pid = os.getpid()
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['pid'] == current_pid:
                    continue
                if proc.info['name'] and proc.info['name'].lower() == target.lower():
                    matches.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        if not matches:
            print(f"[-] Could not find any running process named '{target}'.")
            sys.exit(1)
        
        if len(matches) == 1:
            return matches[0]['pid']
        
        print(f"[*] Found {len(matches)} processes matching '{target}':")
        for i, proc in enumerate(matches):
            try:
                # Try to get more info if possible
                p = psutil.Process(proc['pid'])
                create_time = p.create_time()
                import datetime
                time_str = datetime.datetime.fromtimestamp(create_time).strftime("%Y-%m-%d %H:%M:%S")
                print(f"  {i+1}. PID: {proc['pid']} (Started: {time_str})")
            except:
                print(f"  {i+1}. PID: {proc['pid']}")
        
        while True:
            choice = input(f"[?] Select PID to dump (or enter PID directly): ").strip()
            if choice.isdigit():
                choice_int = int(choice)
                # Check if it was an index
                if 1 <= choice_int <= len(matches):
                    return matches[choice_int - 1]['pid']
                # Or if it's one of the PIDs shown
                if any(m['pid'] == choice_int for m in matches):
                    return choice_int
                # Or maybe it's a PID not in matches but user knows what they are doing? 
                # Better to just allow any valid numeric input if they insist, 
                # but let's stick to the list or direct PID for now.
                print(f"[*] Proceeding with PID {choice_int}...")
                return choice_int
            print("[-] Invalid input. Please enter a number from the list or a PID.")

    def _get_process_name(self):
        try:
            return psutil.Process(self.pid).name()
        except:
            return None

    def is_privileged(self):
        raise NotImplementedError

    def elevate_privileges(self):
        raise NotImplementedError

    def dump(self):
        raise NotImplementedError

class WindowsDumper(ProcessDumper):
    def __init__(self, target):
        import ctypes
        self.ctypes = ctypes
        self.kernel32 = ctypes.windll.kernel32
        self.dbghelp = ctypes.windll.dbghelp
        super().__init__(target)

    def is_privileged(self):
        try:
            return self.ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    def elevate_privileges(self):
        print("[*] Requesting Administrator privileges...")
        script = os.path.abspath(sys.argv[0])
        params = ' '.join([f'"{script}"'] + sys.argv[1:])
        res = self.ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        if res <= 32:
            print("[-] Failed to elevate privileges.")
            sys.exit(1)
        sys.exit(0)

    def dump(self):
        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010
        MINIDUMP_WITH_FULL_MEMORY = 0x00000002
        GENERIC_WRITE = 0x40000000
        CREATE_ALWAYS = 2
        FILE_ATTRIBUTE_NORMAL = 0x80

        p_obj = psutil.Process(self.pid)
        try:
            p_obj.suspend()
            h_proc = self.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, self.pid)
            if not h_proc:
                print(f"[-] Failed to open process PID {self.pid}.")
                return False

            h_file = self.kernel32.CreateFileW(self.output_filename, GENERIC_WRITE, 0, None, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, None)
            if h_file == -1:
                print(f"[-] Failed to create output file: {self.output_filename}")
                self.kernel32.CloseHandle(h_proc)
                return False

            print(f"[*] Dumping memory to {self.output_filename}...")
            success = self.dbghelp.MiniDumpWriteDump(h_proc, self.pid, h_file, MINIDUMP_WITH_FULL_MEMORY, None, None, None)
            
            self.kernel32.CloseHandle(h_file)
            self.kernel32.CloseHandle(h_proc)

            if success:
                print(f"[+] Success! Dump created: {self.output_filename} ({os.path.getsize(self.output_filename)/(1024*1024):.2f} MB)")
                return True
        finally:
            p_obj.resume()
        return False

class LinuxDumper(ProcessDumper):
    def is_privileged(self):
        return os.getuid() == 0

    def elevate_privileges(self):
        print("[*] Requesting root privileges via sudo...")
        args = ['sudo', sys.executable] + sys.argv
        os.execvp('sudo', args)

    def dump(self):
        try:
            print(f"[*] Dumping memory for PID {self.pid} via procfs...")
            with open(f"/proc/{self.pid}/maps", "r") as maps_file:
                with open(f"/proc/{self.pid}/mem", "rb", 0) as mem_file:
                    with open(self.output_filename, "wb") as dump_file:
                        for line in maps_file:
                            parts = line.split()
                            if not parts: continue
                            addr_range = parts[0]
                            start, end = [int(x, 16) for x in addr_range.split("-")]
                            
                            # Skip special regions if needed, but for full dump we try all
                            try:
                                mem_file.seek(start)
                                chunk = mem_file.read(end - start)
                                dump_file.write(chunk)
                            except Exception:
                                # Some regions might not be readable even as root (e.g. vsyscall)
                                # We pad with zeros to keep the dump alignment if we want a "raw" dump
                                # but usually we just skip or use a structured format like ELF core.
                                # For simplicity, we just skip unreadable chunks here.
                                dump_file.write(b'\x00' * (end - start))
            
            print(f"[+] Success! Dump created: {self.output_filename} ({os.path.getsize(self.output_filename)/(1024*1024):.2f} MB)")
            return True
        except Exception as e:
            print(f"[-] Linux dump failed: {e}")
            return False

class TermuxDumper(LinuxDumper):
    def elevate_privileges(self):
        # Termux uses 'tsu' or 'sudo' if installed. tsu is more common.
        for cmd in ['tsu', 'sudo']:
            if subprocess.run(['which', cmd], capture_output=True).returncode == 0:
                print(f"[*] Requesting root privileges via {cmd}...")
                args = [cmd, '-c', f"{sys.executable} " + " ".join(sys.argv)]
                os.execvp(cmd, [cmd, '-c', f"{sys.executable} " + " ".join(sys.argv)])
        
        print("[-] Could not find 'tsu' or 'sudo' for elevation in Termux.")
        sys.exit(1)

def get_dumper():
    os_name = platform.system()
    if os_name == "Windows":
        return WindowsDumper
    elif os_name == "Linux":
        # Check if in Termux
        if "TERMUX_VERSION" in os.environ or os.path.exists("/data/data/com.termux"):
            return TermuxDumper
        return LinuxDumper
    else:
        print(f"[-] Unsupported OS: {os_name}")
        sys.exit(1)

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {os.path.basename(sys.argv[0])} <ProcessName | PID>")
        sys.exit(1)

    DumperClass = get_dumper()
    dumper = DumperClass(sys.argv[1])

    if not dumper.is_privileged():
        dumper.elevate_privileges()
        return

    print(f"[*] Target Process: {dumper.process_name} (PID: {dumper.pid})")
    
    if dumper.pid == os.getpid():
        print("[-] Cannot dump the current process (the dump program itself).")
        if platform.system() == "Windows":
            input("Press Enter to exit...")
        sys.exit(1)

    dumper.dump()
    if platform.system() == "Windows":
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
