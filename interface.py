#!/usr/bin/env python3
import asyncio
import struct
import socket
import getpass
import time
import msgpack
import sys

# Importamos la librería de interfaz
from prompt_toolkit import Application
from prompt_toolkit.application.current import get_app
from prompt_toolkit.layout import Layout, HSplit, VSplit, Window, FloatContainer, Float
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.widgets import Frame, TextArea, Box
from prompt_toolkit.styles import Style
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.formatted_text import HTML, merge_formatted_text, to_formatted_text

# Importamos TU código original (sin modificarlo)
from dnie_real import DNIeReal
from network import CompleteNetwork, MessageType

# --- ADAPTADOR DE RED (Bridge) ---
class GuiNetwork(CompleteNetwork):
    """
    Esta clase extiende tu CompleteNetwork para interceptar los eventos
    y mandarlos a la interfaz.
    """
    def __init__(self, dnie, ui_app):
        super().__init__(dnie)
        self.ui = ui_app

    # 1. Interceptamos descubrimiento de peers
    def add_discovered_peer(self, info):
        super().add_discovered_peer(info) 
        self.ui.update_sidebar()

    # 2. Interceptamos mensajes de texto recibidos
    def _handle_text(self, payload, remote_fp):
        try:
            decrypted = self.noise.decrypt_message(payload, remote_fp)
            data = msgpack.unpackb(decrypted, raw=False)
            text = data.get('text')
            self.ui.add_message(remote_fp, text, is_me=False)
        except Exception as e:
            self.ui.log_system(f"Error desencriptando msg de {remote_fp[:8]}")

    # 3. Interceptamos Handshakes
    def _handle_handshake_init(self, cid, payload, addr):
        super()._handle_handshake_init(cid, payload, addr)
        self.ui.log_system(f"🤝 Handshake recibido de {addr[0]}")
        self.ui.update_sidebar()

    def _handle_handshake_response(self, payload, remote_fp):
        super()._handle_handshake_response(payload, remote_fp)
        self.ui.log_system(f"✅ Handshake completado con {self._get_clean_name(remote_fp)}")

# --- LÓGICA DE LA INTERFAZ GRÁFICA ---
class TelegramTUI:
    def __init__(self, username, port, pin):
        self.username = username
        self.port = port
        self.pin = pin
        
        self.current_chat_fp = None
        self.messages = {} 
        self.system_logs = []
        
        self.dnie = DNIeReal()
        self.network = GuiNetwork(self.dnie, self)

        # --- ESTILOS ---
        self.style = Style.from_dict({
            'sidebar': 'bg:#232323 #888888',
            'sidebar.selected': 'bg:#2d2d2d #ffffff bold',
            'chat.bg': 'bg:#1e1e1e #ffffff',
            'input': 'bg:#232323 #ffffff',
            'top-bar': 'bg:#181818 #64b5f6 bold',
            'msg.me': '#64b5f6',       
            'msg.them': '#ffffff',     
            'msg.time': '#555555 italic',
            'system': '#ffb74d italic'
        })

        # --- WIDGETS ---
        self.sidebar_control = FormattedTextControl(text=self.get_sidebar_text)
        self.sidebar_window = Window(content=self.sidebar_control, width=30, style='class:sidebar', wrap_lines=False)

        self.chat_control = FormattedTextControl(text=self.get_chat_text)
        self.chat_window = Window(content=self.chat_control, style='class:chat.bg', wrap_lines=True)

        self.input_field = TextArea(height=3, prompt='>>> ', style='class:input', multiline=False, wrap_lines=True)
        self.input_field.accept_handler = self.on_send_enter

        self.header_control = FormattedTextControl(text=self.get_header_text)
        self.header_window = Window(content=self.header_control, height=1, style='class:top-bar')

        # --- LAYOUT ---
        self.layout = VSplit([
            HSplit([
                Window(FormattedTextControl(HTML(" <b>TelegramTUI v1.0</b>")), height=1, style='class:top-bar'),
                self.sidebar_window
            ]),
            HSplit([
                self.header_window,
                self.chat_window,
                Frame(self.input_field, style='class:input')
            ])
        ])

        self.kb = KeyBindings()
        
        @self.kb.add('c-q')
        def _(event):
            event.app.exit()

        @self.kb.add('tab')
        def _(event):
            self.cycle_chat()

    # --- MÉTODOS DE REDIBUJADO ---
    def get_sidebar_text(self):
        lines = []
        peers = self.network.get_peers()
        
        if self.current_chat_fp == "SYSTEM":
            lines.append(HTML("<class:sidebar.selected> 📢 System Logs</class:sidebar.selected>\n"))
        else:
            lines.append(HTML(" 📢 System Logs\n"))

        for p in peers:
            fp = p['fingerprint']
            name = p.get('name', 'Unknown')[:20]
            name = name.replace("(AUTENTICACIÓN)", "").strip()
            
            if fp == self.current_chat_fp:
                lines.append(HTML(f"<class:sidebar.selected> 👤 {name}</class:sidebar.selected>\n"))
            else:
                lines.append(HTML(f" 👤 {name}\n"))
        return merge_formatted_text(lines)

    def get_chat_text(self):
        if self.current_chat_fp == "SYSTEM":
            return merge_formatted_text(self.system_logs)
        
        if not self.current_chat_fp:
            return HTML("\n\n   <style color='#555555'>Selecciona un chat con TAB...</style>")
        
        msgs = self.messages.get(self.current_chat_fp, [])
        if not msgs:
            return HTML("\n   <style color='#555555'>No hay mensajes. Escribe para iniciar...</style>")
        
        return merge_formatted_text(msgs)

    def get_header_text(self):
        if not self.current_chat_fp: return HTML(" DNIe Messenger")
        if self.current_chat_fp == "SYSTEM": return HTML(" Logs del Sistema")
        
        name = self.current_chat_fp[:8]
        for p in self.network.get_peers():
            if p['fingerprint'] == self.current_chat_fp:
                name = p.get('name', name).replace("(AUTENTICACIÓN)", "").strip()
                break
        return HTML(f" 💬 {name}  |  <style color='#81c784'>Online</style>")

    # --- LÓGICA UI ---
    def update_sidebar(self):
        get_app().invalidate()

    def log_system(self, text):
        t = time.strftime("%H:%M")
        line = HTML(f"<class:msg.time>[{t}]</class:msg.time> <class:system>{text}</class:system>\n")
        self.system_logs.append(line)
        get_app().invalidate()

    def add_message(self, fp, text, is_me=True):
        if fp not in self.messages: self.messages[fp] = []
        
        t = time.strftime("%H:%M")
        if is_me:
            header = f"<class:msg.me><b>Yo:</b></class:msg.me>"
        else:
            name = "Peer"
            for p in self.network.get_peers():
                if p['fingerprint'] == fp:
                    name = p['name'].replace("(AUTENTICACIÓN)", "").strip().split()[0]
                    break
            header = f"<class:msg.them><b>{name}:</b></class:msg.them>"
        
        line = HTML(f"{header} {text} <class:msg.time>{t}</class:msg.time>\n")
        self.messages[fp].append(line)
        get_app().invalidate()

    def cycle_chat(self):
        peers = self.network.get_peers()
        fps = ["SYSTEM"] + [p['fingerprint'] for p in peers]
        if not self.current_chat_fp:
            self.current_chat_fp = fps[0]
        else:
            try:
                idx = fps.index(self.current_chat_fp)
                self.current_chat_fp = fps[(idx + 1) % len(fps)]
            except:
                self.current_chat_fp = fps[0]
        get_app().invalidate()

    def on_send_enter(self, buff):
        text = self.input_field.text.strip()
        if not text: return
        if not self.current_chat_fp or self.current_chat_fp == "SYSTEM":
            self.log_system("⚠️ Selecciona un usuario con TAB para enviar.")
            return
        asyncio.create_task(self._send_wrapper(self.current_chat_fp, text))

    async def _send_wrapper(self, fp, text):
        self.input_field.buffer.reset()
        ok = await self.network.send_message(fp, text)
        if ok:
            self.add_message(fp, text, is_me=True)
        else:
            self.log_system(f"❌ Error enviando mensaje.")

    async def run(self):
        # 1. Inicializar DNIe
        print("Iniciando DNIe (mira el lector)...")
        if await self.dnie.initialize(self.pin, interactive=False):
            print("DNIe OK.")
        else:
            print("Fallo DNIe. Saliendo.")
            return

        # 2. Iniciar Red (CORRECCIÓN AQUÍ)
        # Forzamos el puerto manualmente antes de iniciar, ya que network.start no acepta argumentos
        self.network.UDP_PORT = self.port 
        await self.network.start(self.username)
        
        # 3. Iniciar UI Loop
        self.app = Application(
            layout=Layout(self.layout),
            key_bindings=self.kb,
            style=self.style,
            full_screen=True,
            mouse_support=True
        )
        await self.app.run_async()
        await self.network.stop()

if __name__ == "__main__":
    print("=== DNIe Messenger TUI ===")
    u_user = input("Nombre Usuario: ") or "Usuario"
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