# 🔮 QUANTUM SHELL

A reverse shell framework built in Python for **educational purposes only**. This project demonstrates network programming, socket communication, encryption, and system interaction concepts.

⚠️ **IMPORTANT**: This tool is intended **solely for learning purposes** and ethical security research. Use responsibly and only in environments you own or have explicit permission to test.

---

## 📚 Project Overview

QUANTUM SHELL is a reverse shell framework that allows remote command execution on target systems. The project consists of two versions:

- **v1**: Basic reverse shell without keylogger functionality
- **v2**: Enhanced version with integrated keylogger capabilities

Both versions feature:
- Encrypted communication using XOR encryption
- Dynamic IP resolution via HTTP server
- Automatic executable generation
- GUI-based installation interface
- Persistent installation (startup folder)
- Multi-IP connection support (public + localhost)

---

## 🖼️ Screenshots

### Main Menu

![Quantum Shell Menu](https://raw.githubusercontent.com/Edgar-GIT/QUANTUM_SHELL/main/imagens/qmenu.png)

### Commands Menu

![Commands Menu](https://raw.githubusercontent.com/Edgar-GIT/QUANTUM_SHELL/main/imagens/qcommands.png)

### Destructive Commands Warning

![Destructive Commands](https://raw.githubusercontent.com/Edgar-GIT/QUANTUM_SHELL/main/imagens/qdest.png)

### Shell Interface

![Shell Interface](https://raw.githubusercontent.com/Edgar-GIT/QUANTUM_SHELL/main/imagens/menu.png)

---

## 🔄 Version Differences

### Version 1 (v1)

**Features:**
- ✅ Basic reverse shell functionality
- ✅ Encrypted command execution
- ✅ Dynamic IP resolution
- ✅ Executable builder
- ✅ GUI installation interface
- ✅ Automatic startup installation
- ✅ Multi-IP connection support

**Components:**
- `listener.py` - Server/listener component
- `reverseshell.py` - Client/payload component

**Use Case:** Basic remote shell access without logging capabilities.

---

### Version 2 (v2)

**Features:**
- ✅ All v1 features
- ✅ **Keylogger functionality** (start/stop control)
- ✅ Real-time keystroke logging
- ✅ Discord webhook integration for logs
- ✅ Enhanced command menu with keylogger controls

**Components:**
- `qlistener.py` - Enhanced server with keylogger management
- `qshell.py` - Client with integrated keylogger

**Use Case:** Advanced remote access with keystroke logging capabilities.

---

## 🚀 Installation & Setup

### Prerequisites

- Python 3.1 or higher
- Windows OS (keylogger features require Windows)
- Administrator privileges (for some operations)

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/Edgar-GIT/QUANTUM_SHELL.git
cd QUANTUM_SHELL
```

### 2️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

### 3️⃣ Configure Discord Webhook (v2 only)

**⚠️ IMPORTANT**: Before building the executable in v2, you must configure your Discord webhooks:

1. Open `v2/qlistener.py`
2. Find the webhook URLs at the top of the file:
   ```python
   WEBHOOK_INFO = "YOUR_DISCORD_WEBHOOK_URL_HERE"
   WEBHOOK_LOGS = "YOUR_DISCORD_WEBHOOK_URL_HERE"
   ```
3. Replace with your own Discord webhook URLs
4. Save the file

**Note**: If you don't configure the webhooks, keylogger logs will be sent to the default webhooks (if any).

### 4️⃣ Run the Listener

**Version 1:**
```bash
cd v1
python listener.py
```

**Version 2:**
```bash
cd v2
python qlistener.py
```

---

## 🎮 Usage

### Listener (Server)

1. Run the listener script
2. The script will automatically:
   - Get your public IP
   - Start an HTTP server on port 8000
   - Create `current_ip.txt` with your IP
3. **Create the executable** when prompted (this is required for connections)
4. Wait for client connections on port 9999

### Creating and Distributing the Executable

> ⚠️ **WARNING**: The executable **automatically adds itself to Windows Startup** and is **very difficult to remove**. Once executed, it will persist across system reboots and continue running in the background. Only use this on systems you own or have explicit permission to test.

**⚠️ IMPORTANT**: For a connection to be established, you **must**:
1. Create the executable using the listener's built-in builder
2. **Before creating the executable (v2 only)**: Edit `qlistener.py` and change the Discord webhook URLs to your own:
   ```python
   WEBHOOK_INFO = "YOUR_DISCORD_WEBHOOK_URL_HERE"
   WEBHOOK_LOGS = "YOUR_DISCORD_WEBHOOK_URL_HERE"
   ```
3. Send the generated `WindowsNETupdate.exe` to the target system
4. The executable will automatically connect back to your listener

**Note**: The executable is created in the `dist/` folder after building. Make sure to configure your Discord webhooks **before** building the executable, as the webhook URLs are embedded in the payload.

### Client (Payload)

> ⚠️ **WARNING**: The payload **automatically installs itself to Windows Startup** and is **very difficult to remove**. It will persist across reboots and run silently in the background. Use only on systems you own or have explicit permission to test.

The client automatically:
- Connects to the listener using dynamic IP resolution
- **Installs itself to startup folder for persistence** (very difficult to remove)
- Runs commands received from the listener
- (v2 only) Logs keystrokes when activated and sends them to your Discord webhook

---

## 🛠️ Features

### Encryption
- XOR-based encryption for all communications
- Base64 encoding for keylogger data (v2)

### Network
- Dynamic IP resolution via HTTP server
- Automatic public IP detection
- Multi-IP connection support (public + localhost)
- Automatic reconnection with exponential backoff

### Persistence
- Automatic installation to Windows startup folder
- Silent background execution
- GUI-based installation interface

### Keylogger (v2 only)
- Low-level keyboard hook
- Real-time keystroke capture
- Remote start/stop control
- Discord webhook integration (configure your webhook before building the executable)

---

## 📁 Project Structure

```
QUANTUM_SHELL/
├── v1/
│   ├── listener.py          # Server component
│   ├── reverseshell.py      # Client component
│   ├── network.ico          # Executable icon
│   └── setupwizard.png      # GUI image
├── v2/
│   ├── qlistener.py         # Enhanced server with keylogger
│   ├── qshell.py            # Enhanced client with keylogger
│   ├── network.ico          # Executable icon
│   └── setupwizard.png      # GUI image
├── imagens/                 # Screenshots
│   ├── menu.png
│   ├── qmenu.png
│   ├── qcommands.png
│   └── qdest.png
├── requirements.txt         # Python dependencies
├── .gitignore              # Git ignore rules
└── README.md               # This file
```

---

## ⚠️ Legal & Ethical Disclaimer

**This tool is provided for educational and research purposes only.**

- ✅ Use only on systems you own or have explicit written permission to test
- ✅ Use only in isolated lab environments or virtual machines
- ✅ Learn about network security, encryption, and system programming
- ✅ Understand how reverse shells and keyloggers work

- ❌ Do NOT use on systems without authorization
- ❌ Do NOT use for malicious purposes
- ❌ Do NOT use to violate privacy or security
- ❌ Do NOT use in production environments

**The authors and contributors are not responsible for any misuse of this tool. Unauthorized access to computer systems is illegal and may result in criminal prosecution.**

---

## 🎓 Educational Value

This project demonstrates:

- **Network Programming**: Socket communication, TCP/IP protocols
- **Encryption**: XOR encryption, Base64 encoding
- **System Programming**: Process execution, file operations, Windows APIs
- **GUI Development**: Tkinter interface design
- **Threading**: Concurrent operations, async communication
- **Security Concepts**: Reverse shells, persistence mechanisms, keyloggers

---

## 🔧 Technical Details

### Communication Protocol
- **Port**: 9999 (TCP)
- **Encryption**: XOR with secret key
- **IP Resolution**: HTTP server on port 8000

### Keylogger (v2)
- **Method**: Windows Low-Level Keyboard Hook
- **Library**: ctypes (Windows API)
- **Data Format**: Base64 encoded XOR

### Persistence
- **Location**: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`
- **Filename**: `WindowsNETupdate.exe`
- **Execution**: Silent background mode

---

## 📝 License

This project is intended for **educational purposes only**.

**You may:**
- ✔ Study and learn from the code
- ✔ Modify for educational purposes
- ✔ Use in authorized security research

**You may NOT:**
- ❌ Use for malicious purposes
- ❌ Distribute modified versions without proper disclaimers
- ❌ Use on systems without authorization
- ❌ Claim as your own work

---

## 👨‍💻 Author

**Edgar** - The world's greatest programmer

---

## 🌟 Acknowledgments

This project is created for educational purposes to help understand:
- Network security concepts
- Reverse shell mechanisms
- System programming techniques
- Encryption methods

**Remember**: With great power comes great responsibility. Use this knowledge ethically and legally.

---

Enjoy learning! 🔮✨

