import keyboard
import ctypes
import subprocess
import requests
import PIL.ImageGrab
import PIL.Image
import time
import os
import mss
import datetime
import datetime
import webbrowser
import platform
import os.path
import platform
import sys
import json as jsond  
import binascii
import tkinter as tk
import pyperclip
import psutil
from PIL import Image, ImageTk
from PIL import Image as PILImage
from tkinter import messagebox  
from colorama import Fore, Style, init
from uuid import uuid4  
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from requests_toolbelt.adapters.fingerprint import FingerprintAdapter


# Obtenha o diretório atual
diretorio_atual = os.getcwd()

# Substitui o diretório atual pelo nome personalizado
nome_personalizado = "DanyCheats"
titulo_janela = f"{nome_personalizado}"

# Defina o título da janela da console com o nome personalizado
if sys.platform.startswith('win32'):
    # Para sistemas Windows
    import ctypes
    ctypes.windll.kernel32.SetConsoleTitleW(titulo_janela)
else:
    # Para sistemas Unix
    sys.stdout.write(f"\x1b]2;{titulo_janela}\x07")


# Utiliza api de auth do keyauth
class api:
    name = ownerid = secret = version = ""

    def __init__(self, name, ownerid, secret, version):
        self.name = name

        self.ownerid = ownerid

        self.secret = secret

        self.version = version

    sessionid = enckey = ""

    def init(self):

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        self.enckey = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("init").encode()),
            "ver": encryption.encrypt(self.version, self.secret, init_iv),
            "enckey": encryption.encrypt(self.enckey, self.secret, init_iv),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        if response == "KeyAuth_Invalid":
            print("The application doesn't exist")
            time.sleep(2)
            sys.exit()

        response = encryption.decrypt(response, self.secret, init_iv)
        json = jsond.loads(response)

        if not json["success"]:
            print(json["message"])
            time.sleep(2)
            sys.exit()

        self.sessionid = json["sessionid"]

    def register(self, user, password, license, hwid=None):
        if hwid is None:
            hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("register").encode()),
            "username": encryption.encrypt(user, self.enckey, init_iv),
            "pass": encryption.encrypt(password, self.enckey, init_iv),
            "key": encryption.encrypt(license, self.enckey, init_iv),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            print("successfully registered")
            time.sleep(2)
        else:
            print(json["message"])
            time.sleep(2)
            sys.exit()

    def upgrade(self, user, license):

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("upgrade").encode()),
            "username": encryption.encrypt(user, self.enckey, init_iv),
            "key": encryption.encrypt(license, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            print("successfully upgraded user")
            time.sleep(2)
        else:
            print(json["message"])
            time.sleep(2)
            sys.exit()

    def login(self, user, password, hwid=None):
        if hwid is None:
            hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("login").encode()),
            "username": encryption.encrypt(user, self.enckey, init_iv),
            "pass": encryption.encrypt(password, self.enckey, init_iv),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            print("Logado com sucesso!")
            time.sleep(2)
        else:
            print(json["message"])
            time.sleep(2)
            sys.exit()

    def license(self, key, hwid=None):
        if hwid is None:
            hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("license").encode()),
            "key": encryption.encrypt(key, self.enckey, init_iv),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            self.__load_user_data(json["info"])
            print("successfully logged into license")
            time.sleep(2)
        else:
            print(json["message"])
            time.sleep(2)
            sys.exit()

    def var(self, name):

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("var").encode()),
            "varid": encryption.encrypt(name, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            return json["message"]
        else:
            print(json["message"])
            time.sleep(5)
            sys.exit()

    def file(self, fileid):

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("file").encode()),
            "fileid": encryption.encrypt(fileid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if not json["success"]:
            print(json["message"])
            time.sleep(5)
            sys.exit()
        return binascii.unhexlify(json["contents"])

    def webhook(self, webid, param):

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("webhook").encode()),
            "webid": encryption.encrypt(webid, self.enckey, init_iv),
            "params": encryption.encrypt(param, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            return json["message"]
        else:
            print(json["message"])
            time.sleep(5)
            sys.exit()

    def log(self, message):

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("log").encode()),
            "pcuser": encryption.encrypt(os.getenv('username'), self.enckey, init_iv),
            "message": encryption.encrypt(message, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        self.__do_request(post_data)

    def __do_request(self, post_data):

        rq_out = requests.post(
            "https://keyauth.business/1.0/", data=post_data
        )

        return rq_out.text
    class user_data_class:
        key = ""
        expiry = datetime.datetime.now()
        level = 0

    user_data = user_data_class()

    def __load_user_data(self, data):
        self.user_data.username = data["username"]


class others:
    @staticmethod
    def get_hwid():
        if platform.system() != "Windows":
            return "None"

        cmd = subprocess.Popen(
            "wmic useraccount where name='%username%' get sid", stdout=subprocess.PIPE, shell=True)

        (suppost_sid, error) = cmd.communicate()

        suppost_sid = suppost_sid.split(b'\n')[1].strip()

        return suppost_sid.decode()


class encryption:
    @staticmethod
    def encrypt_string(plain_text, key, iv):
        plain_text = pad(plain_text, 16)

        aes_instance = AES.new(key, AES.MODE_CBC, iv)

        raw_out = aes_instance.encrypt(plain_text)

        return binascii.hexlify(raw_out)

    @staticmethod
    def decrypt_string(cipher_text, key, iv):
        cipher_text = binascii.unhexlify(cipher_text)

        aes_instance = AES.new(key, AES.MODE_CBC, iv)

        cipher_text = aes_instance.decrypt(cipher_text)

        return unpad(cipher_text, 16)

    @staticmethod
    def encrypt(message, enc_key, iv):
        try:
            _key = SHA256.new(enc_key.encode()).hexdigest()[:32]

            _iv = SHA256.new(iv.encode()).hexdigest()[:16]

            return encryption.encrypt_string(message.encode(), _key.encode(), _iv.encode()).decode()
        except:
            print("Invalid Application Information. Long text is secret short text is ownerid. Name is supposed to be app name not username")
            sys.exit()

    @staticmethod
    def decrypt(message, enc_key, iv):
        try:
            _key = SHA256.new(enc_key.encode()).hexdigest()[:32]

            _iv = SHA256.new(iv.encode()).hexdigest()[:16]

            return encryption.decrypt_string(message.encode(), _key.encode(), _iv.encode()).decode()
        except:
            print("Invalid Application Information. Long text is secret short text is ownerid. Name is supposed to be app name not username")
            sys.exit()

keyauthapp = api("", "", "","")

keyauthapp.init()
        
os.system("cls")

print (Style.BRIGHT + Fore.CYAN + """
  ___             __   ___         _     
 | _ ) ___ _ __   \ \ / (_)_ _  __| |___ 
 | _ \/ -_) '  \   \ V /| | ' \/ _` / _ \
 
 |___/\___|_|_|_|   \_/ |_|_||_\__,_\___/                                                                
                                  """ + Style.RESET_ALL)

print (Style.BRIGHT + Fore.YELLOW + """
1.Login
2.Registrar
3.Alterar Key
""" + Style.RESET_ALL)
ans=input(Style.BRIGHT + Fore.YELLOW + "Selecione uma opção: ") 
if ans=="1": 
    user = input('Username: ')
    password = input('Password: ')
    keyauthapp.login(user,password)
elif ans=="2":
    user = input('Username: ')
    password = input('Password: ')
    license = input('Sua Key: ')
    keyauthapp.register(user,password,license) 
elif ans=="3":
    user = input('Username: ')
    license = input('Nova Key: ')
    keyauthapp.upgrade(user,license)    
elif ans !="":
  print(Style.BRIGHT + Fore.RED + "\n Opção Invalida")
  time.sleep(2)
  os._exit() 

# Nome do processo a ser verificado
process_names = ["valorant.exe", "VALORANT.exe", "Overwatch.exe"]

# Verifica se o processo está em execução
for proc in psutil.process_iter():
    if proc.name() in process_names:
        messagebox.showerror("DanyCheats", "Finalize o jogo antes de abrir o loader")
        time.sleep(2)
        os._exit()

# Trigger com leitura de pixel, deteccao da cor roxa e execucao de comando
S_HEIGHT, S_WIDTH = (PIL.ImageGrab.grab().size)
PURPLE_R, PURPLE_G, PURPLE_B = (250, 100, 250)
TOLERANCE = 60
GRABZONE = 10
TRIGGER_KEY = "ctrl + alt"
SWITCH_KEY = "ctrl + tab"
GRABZONE_KEY_UP = "ctrl + up"
GRABZONE_KEY_DOWN = "ctrl + down"
mods = ["Lento", "Legit", "Rage"]
 
class FoundEnemy(Exception):
    pass
 
class triggerBot():
    def __init__(self):
        self.toggled = True
        self.mode = 1
        self.last_reac = 0
 
    def toggle(self):
        self.toggled = not self.toggled
 
    def switch(self):
        if self.mode != 2:
            self.mode += 1  
        else:
            self.mode = 0
            
    def click(self):
        ctypes.windll.user32.mouse_event(2, 0, 0, 0,0) # left down
        ctypes.windll.user32.mouse_event(4, 0, 0, 0,0) # left up
        
    def approx(self, r, g ,b):
        return PURPLE_R - TOLERANCE < r < PURPLE_R + TOLERANCE and PURPLE_G - TOLERANCE < g < PURPLE_G + TOLERANCE and PURPLE_B - TOLERANCE < b < PURPLE_B + TOLERANCE
 
    def grab(self):
        with mss.mss() as sct:
            bbox=(int(S_HEIGHT/2-GRABZONE), int(S_WIDTH/2-GRABZONE), int(S_HEIGHT/2+GRABZONE), int(S_WIDTH/2+GRABZONE))
            sct_img = sct.grab(bbox)
            # Convert to PIL/Pillow Image
            return PIL.Image.frombytes('RGB', sct_img.size, sct_img.bgra, 'raw', 'BGRX')
    def scan(self):
        start_time = time.time()
        pmap = self.grab()
        try:
            for x in range(0, GRABZONE*2):
                for y in range(0, GRABZONE*2):
                    r, g, b = pmap.getpixel((x,y))
                    if self.approx(r, g, b):
                        raise FoundEnemy
        except FoundEnemy:
            self.last_reac = int((time.time() - start_time)*1000)
            self.click()
            if self.mode == 0:
                time.sleep(0.40)
            if self.mode == 1:
                time.sleep(0.20)
            if self.mode == 2:
                time.sleep(0.01)
            print_banner(self)
 
def print_banner(bot: triggerBot):
    os.system("cls")
    print(Style.BRIGHT + Fore.CYAN +"""
 ________          __                                          _______              __     
|        \        |  \                                        |       \            |  \    
 \$$$$$$$$______   \$$  ______    ______    ______    ______  | $$$$$$$\  ______  _| $$_   
   | $$  /      \ |  \ /      \  /      \  /      \  /      \ | $$__/ $$ /      \|   $$ \  
   | $$ |  $$$$$$\| $$|  $$$$$$\|  $$$$$$\|  $$$$$$\|  $$$$$$\| $$    $$|  $$$$$$\\$$$$$$  
   | $$ | $$   \$$| $$| $$  | $$| $$  | $$| $$    $$| $$   \$$| $$$$$$$\| $$  | $$ | $$ __ 
   | $$ | $$      | $$| $$__| $$| $$__| $$| $$$$$$$$| $$      | $$__/ $$| $$__/ $$ | $$|  \

   | $$ | $$      | $$ \$$    $$ \$$    $$ \$$     \| $$      | $$    $$ \$$    $$  \$$  $$
    \$$  \$$       \$$  \$$$$$$$  \$$$$$$$  \$$$$$$$ \$$       \$$$$$$$   \$$$$$$    \$$$$ 
                      |  \__| $$|  \__| $$                                            
                       \$$    $$ \$$    $$                                                 
                        \$$$$$$   \$$$$$$

                                          """ + Style.RESET_ALL)


    print("===== Controles =====")
    print("Ativar/Desativar     :", Fore.YELLOW + TRIGGER_KEY + Style.RESET_ALL)
    print("Alterar Modo         :", Fore.YELLOW + SWITCH_KEY + Style.RESET_ALL)
    print("Alterar FOV          :", Fore.YELLOW + GRABZONE_KEY_UP + "/" + GRABZONE_KEY_DOWN + Style.RESET_ALL)
    print("==== Informacoes ====")
    print("Modo                 :", Fore.CYAN + mods[bot.mode] + Style.RESET_ALL)
    print("Fov Atual            :", Fore.CYAN + str(GRABZONE) + "x" + str(GRABZONE) + Style.RESET_ALL)
    print("Status               :", (Fore.GREEN if bot.toggled else Fore.RED) + str(bot.toggled) + Style.RESET_ALL)
    print("Tempo Tiro/ms        :", Fore.CYAN + str(bot.last_reac) + Style.RESET_ALL + " ms ("+str((bot.last_reac)/(GRABZONE*GRABZONE))+"ms/pix)")
 
if __name__ == "__main__":
    bot = triggerBot()
    print_banner(bot)
    while True:
        if keyboard.is_pressed(SWITCH_KEY):
            bot.switch()
            print_banner(bot)
            while keyboard.is_pressed(SWITCH_KEY):
                pass
        if keyboard.is_pressed(GRABZONE_KEY_UP):
            GRABZONE += 2
            print_banner(bot)
            while keyboard.is_pressed(GRABZONE_KEY_UP):
                pass
        if keyboard.is_pressed(GRABZONE_KEY_DOWN):
            GRABZONE -= 2
            print_banner(bot)
            while keyboard.is_pressed(GRABZONE_KEY_DOWN):
                pass
        if keyboard.is_pressed(TRIGGER_KEY):
            bot.toggle()
            print_banner(bot)
            while keyboard.is_pressed(TRIGGER_KEY):
                pass
        if bot.toggled:
            bot.scan()
