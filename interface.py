#!/usr/bin/env python3
import asyncio
import sys
import time
import msgpack
import getpass

# Importamos la librería de interfaz
from prompt_toolkit import Application
from prompt_toolkit.application.current import get_app
from prompt_toolkit.layout import Layout, HSplit, VSplit, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.widgets import Frame, TextArea
from prompt_toolkit.styles import Style
from prompt_toolkit.key_binding import KeyBindings

# Importamos TU código original
from dnie_real import DNIeReal
from network import CompleteNetwork

# --- CLASE PARA CAPTURAR PRINTS (Solo cuando la UI esté lista) ---
class StdoutRedirector:
    def __init__(self, ui_app):
        self.ui = ui_app
        self.buffer = ""

    def write(self, text):
        # Acumulamos texto y lo mandamos al log del sistema
        if not text: return
        self.buffer += text
        if "\n" in self.buffer:
            lines = self.buffer.split("\n")
            for line in lines[:-1]:
                if line.strip():
                    self.ui.log_system(f"⚙️ {line.strip()}")
            self.buffer = lines[-1]

    def flush(self):
        pass

# --- ADAPTADOR DE RED ---
class GuiNetwork(CompleteNetwork):
    def __init__(self, dnie, ui_app):
        super().__init__(dnie)
        self.ui = ui_app

    def add_discovered_peer(self, info):
        fp = info['fingerprint']
        if fp == self.my_fingerprint: return
        super().add_discovered_peer(info)
        self.ui.log_system(f"🔍 Peer detectado: {info.get('name')} ({info.get('ip')})")
        self.ui.update_ui()

    def _handle_text(self, payload, remote_fp):
        try:
            decrypted = self.noise.decrypt_message(payload, remote_fp)
            try:
                data = msgpack.unpackb(decrypted, raw=False)
            except:
                self.ui.log_system(f"⚠️ Error unpack msg de {remote_fp[:8]}")
                return

            text = data.get('text')
            self.ui.add_message(remote_fp, text, is_me=False)
        except Exception as e:
            self.ui.log_system(f"❌ Error recibiendo msg: {e}")

# --- INTERFAZ GRÁFICA (TUI) ---
class TelegramTUI:
    def __init__(self, username, port, pin):
        self.username = username
        self.port = port
        self.pin = pin
        
        self.current_chat_fp = "SYSTEM"
        self.messages = {} 
        self.system_logs = []
        
        self.dnie = DNIeReal()
        self.network = GuiNetwork(self.dnie, self)

        # --- ESTILOS ---
        self.style = Style.from_dict({
            'sidebar': 'bg:#232323 #aaaaaa',
            'sidebar.selected': 'bg:#005fce #ffffff bold',
            'chat.bg': 'bg:#1e1e1e #ffffff',
            'input': 'bg:#333333 #ffffff',
            'top-bar': 'bg:#181818 #81c784 bold',
            'msg.me': '#64b5f6 bold',       
            'msg.them': '#81c784 bold',     
            'msg.time': '#555555 italic',
            'system.log': '#ffb74d italic',
            'system.prefix': '#aaaaaa'
        })

        # --- LAYOUT ---
        self.sidebar_control = FormattedTextControl(text=self.get_sidebar_text)
        self.sidebar_window = Window(content=self.sidebar_control, width=25, style='class:sidebar', wrap_lines=False)

        self.chat_control = FormattedTextControl(text=self.get_chat_text)
        self.chat_window = Window(content=self.chat_control, style='class:chat.bg', wrap_lines=True, always_hide_cursor=True)

        self.input_field = TextArea(height=3, prompt='>>> ', style='class:input', multiline=False, wrap_lines=True)
        self.input_field.accept_handler = self.on_send_enter

        self.header_control = FormattedTextControl(text=self.get_header_text)
        self.header_window = Window(content=self.header_control, height=1, style='class:top-bar')

        self.layout = VSplit([
            HSplit([
                Window(FormattedTextControl([("class:sidebar.header", " DNIe Messenger ")]), height=1),
                self.sidebar_window
            ]),
            HSplit([
                self.header_window,
                self.chat_window,
                Frame(self.input_field, style='class:input')
            ])
        ])

        self.kb = KeyBindings()
        @self.kb.add('c-c')
        @self.kb.add('c-q')
        def _(event): event.app.exit()

        @self.kb.add('tab')
        def _(event): self.cycle_chat()

    # --- TEXTO UI ---
    def get_sidebar_text(self):
        result = []
        if self.current_chat_fp == "SYSTEM":
            result.append(("class:sidebar.selected", " 📢 System Logs\n"))
        else:
            result.append(("", " 📢 System Logs\n"))

        peers = self.network.get_peers()
        for p in peers:
            fp = p['fingerprint']
            name = p.get('name', 'Unknown')[:15].replace("(AUTENTICACIÓN)", "").strip()
            if fp == self.current_chat_fp:
                result.append(("class:sidebar.selected", f" 👤 {name}\n"))
            else:
                result.append(("", f" 👤 {name}\n"))
        return result

    def get_chat_text(self):
        if self.current_chat_fp == "SYSTEM": return self.system_logs[-50:]
        if not self.current_chat_fp: return [("", "\n   Selecciona un usuario con TAB...")]
        
        msgs = self.messages.get(self.current_chat_fp, [])
        if not msgs: return [("", "\n   📭 Chat vacío. ¡Saluda!")]
        return msgs

    def get_header_text(self):
        if self.current_chat_fp == "SYSTEM": return [("", " 🖥️  Logs de Depuración")]
        name = self.current_chat_fp[:8]
        for p in self.network.get_peers():
            if p['fingerprint'] == self.current_chat_fp:
                name = p.get('name', name).replace("(AUTENTICACIÓN)", "").strip()
                break
        return [("", " 💬 Chat con: "), ("bold", f"{name}"), ("", " | NoiseIK Seguro")]

    # --- FUNCIONES ---
    def update_ui(self):
        try: get_app().invalidate()
        except: pass

    def log_system(self, text):
        t = time.strftime("%H:%M")
        self.system_logs.append(("class:system.prefix", f"[{t}] "))
        self.system_logs.append(("class:system.log", f"{text}\n"))
        self.update_ui()

    def add_message(self, fp, text, is_me=True):
        if fp not in self.messages: self.messages[fp] = []
        t = time.strftime("%H:%M")
        if is_me: prefix = [("class:msg.me", "Yo: ")]
        else:
            name = "Peer"
            for p in self.network.get_peers():
                if p['fingerprint'] == fp:
                    name = p['name'].replace("(AUTENTICACIÓN)", "").split()[0]
                    break
            prefix = [("class:msg.them", f"{name}: ")]
        
        self.messages[fp].extend(prefix + [("", f"{text} "), ("class:msg.time", f"{t}\n")])
        self.update_ui()

    def cycle_chat(self):
        peers = self.network.get_peers()
        ids = ["SYSTEM"] + [p['fingerprint'] for p in peers]
        if not ids: return
        if self.current_chat_fp in ids:
            curr = ids.index(self.current_chat_fp)
            self.current_chat_fp = ids[(curr + 1) % len(ids)]
        else: self.current_chat_fp = "SYSTEM"
        self.update_ui()

    def on_send_enter(self, buff):
        text = self.input_field.text.strip()
        if not text: return
        if self.current_chat_fp == "SYSTEM" or not self.current_chat_fp:
            self.log_system("⚠️ Ve a un chat para escribir.")
            self.input_field.buffer.reset()
            return
        asyncio.create_task(self._send_wrapper(self.current_chat_fp, text))

    async def _send_wrapper(self, fp, text):
        self.input_field.buffer.reset()
        if await self.network.send_message(fp, text):
            self.add_message(fp, text, is_me=True)
        else:
            self.log_system(f"❌ Error envío.")

    async def run(self):
        # 1. NO REDIRIGIMOS TODAVÍA (Para ver errores de inicio)
        print("⚡ Cargando identidad DNIe...") 

        # 2. Inicializar Hardware
        if await self.dnie.initialize(self.pin, interactive=False):
            print(f"✅ DNIe OK: {self.dnie.get_user_name()}")
        else:
            print("❌ Error fatal: No se pudo leer el DNIe.")
            print("   - Comprueba que está insertado.")
            print("   - Comprueba que el PIN es correcto.")
            return # SALIMOS AQUÍ si falla, para que veas el error en consola

        # 3. Arrancar Red
        print(f"📡 Iniciando red en puerto {self.port}...")
        self.network.UDP_PORT = self.port 
        await self.network.start(self.username)
        
        # 4. AHORA SÍ: Activamos modo gráfico y ocultamos prints
        # Redirigimos prints al log interno
        sys.stdout = StdoutRedirector(self)
        sys.stderr = StdoutRedirector(self)
        
        self.app = Application(
            layout=Layout(self.layout),
            key_bindings=self.kb,
            style=self.style,
            full_screen=True,
            mouse_support=True
        )
        
        # Log inicial dentro de la app
        self.log_system("🚀 Interfaz Iniciada. Esperando peers...")
        
        await self.app.run_async()
        await self.network.stop()

if __name__ == "__main__":
    print("=== DNIe Messenger TUI v4.1 (Fix Boot) ===")
    u_user = input("Tu Nombre: ") or "Usuario"
    u_port = int(input("Puerto UDP (6666): ") or 6666)
    try:
        u_pin = getpass.getpass("PIN DNIe: ")
    except:
        u_pin = input("PIN: ")

    tui = TelegramTUI(u_user, u_port, u_pin)
    
    try:
        asyncio.run(tui.run())
    except KeyboardInterrupt:
        pass