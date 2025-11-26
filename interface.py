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
from prompt_toolkit.layout import Layout, HSplit, VSplit, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.widgets import Frame, TextArea
from prompt_toolkit.styles import Style
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.formatted_text import to_formatted_text
from cryptography.hazmat.primitives import serialization

from dnie_real import DNIeReal
from network import CompleteNetwork, MessageType

# --- ADAPTADOR DE RED BLINDADO (Totalmente Silencioso) ---
class GuiNetwork(CompleteNetwork):
    """
    Versión modificada de la red que REEMPLAZA completamente la lógica
    de impresión para que NADA salga por consola y rompa la interfaz.
    """
    def __init__(self, dnie, ui_app):
        super().__init__(dnie)
        self.ui = ui_app
 
    def add_discovered_peer(self, info):
        fp = info['fingerprint']
        if fp == self.my_fingerprint: return
        
        if fp not in self.discovered:
            # Lógica original pero sin print
            self.discovered[fp] = info
            
            # Log visual en UI
            name = info.get('name', 'Desconocido')
            ip = info.get('ip', '?')
            self.ui.log_system(f"🔍 Peer descubierto: {name} ({ip})")
            self.ui.update_sidebar()

    # REEMPLAZAMOS (Sin llamar a super)
    def _handle_text(self, payload, remote_fp):
        try:
            decrypted = self.noise.decrypt_message(payload, remote_fp)
            data = msgpack.unpackb(decrypted, raw=False)
            text = data.get('text')
            # Enviamos a la ventana de chat
            self.ui.add_message(remote_fp, text, is_me=False)
        except Exception as e:
            self.ui.log_system(f"Error desencriptando msg de {remote_fp[:8]}")

    # REEMPLAZAMOS la lógica completa del Handshake Init
    def _handle_handshake_init(self, cid, payload, addr):
        try:
            content = msgpack.unpackb(payload, raw=False)
            remote_fp = content.get('dnie_fingerprint')
            #static_bytes = content.get('static_public')
            #ephemeral_bytes = content.get('ephemeral_public')
            
            # Log UI limpio
            clean_name = self._get_clean_name(remote_fp)
            self.ui.log_system(f"🤝 Handshake recibido de {clean_name}")
            
            # Lógica crypto original (copiada para evitar el print del padre)
            if self.noise.accept_handshake(content):
                self.ui.log_system(f"🔒 Sesión establecida con {clean_name}")
            
            # Gestión de conexión
            if not self.connection_manager.get_cid_for_peer(remote_fp):
                self.connection_manager.create_connection(remote_fp, {'ip': addr[0], 'port': addr[1]})
                if remote_fp not in self.discovered:
                     self.discovered[remote_fp] = {
                        'fingerprint': remote_fp,
                        'name': "Desconocido", 
                        'ip': addr[0], 
                        'port': addr[1]
                    }
                    
            # Responder
            my_static = self.noise.static_public.public_bytes(
                encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
            ack_payload = msgpack.packb({'ack': True, 'static_public': my_static})
            pkt = self.connection_manager.create_packet(cid, 0, MessageType.HANDSHAKE_RESPONSE, ack_payload)
            self.udp_transport.sendto(pkt, addr)
            
            self.ui.update_sidebar()
            
        except Exception as e:
            self.ui.log_system(f"❌ Error handshake init: {e}")

    # REEMPLAZAMOS la lógica completa del Handshake Response
    def _handle_handshake_response(self, payload, remote_fp):
        try:
            content = msgpack.unpackb(payload, raw=False)
            if content.get('ack') and remote_fp:
                remote_static = content.get('static_public')
                if remote_static:
                    # Lógica crypto
                    if self.noise.update_session_with_peer_key(remote_static, remote_fp):
                         clean_name = self._get_clean_name(remote_fp)
                         # Log UI limpio (El culpable del error anterior era el print de aquí)
                         self.ui.log_system(f"✅ Handshake COMPLETADO con {clean_name}")
        except Exception as e:
            self.ui.log_system(f"❌ Error respuesta handshake: {e}")

# --- LÓGICA DE LA INTERFAZ GRÁFICA (Igual que v2.3) ---
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
            'sidebar.header': 'bg:#00aaaa #ffffff bold',
            'chat.bg': 'bg:#1e1e1e #ffffff',
            'input': 'bg:#232323 #ffffff',
            'top-bar': 'bg:#181818 #64b5f6 bold',
            'msg.me': '#64b5f6',       
            'msg.them': '#81c784',     
            'msg.time': '#555555 italic',
            'system': '#ffb74d italic'
        })

        # --- WIDGETS ---
        self.sidebar_control = FormattedTextControl(text=self.get_sidebar_text)
        self.sidebar_window = Window(
            content=self.sidebar_control, 
            width=30, 
            style='class:sidebar', 
            wrap_lines=False
        )

        self.chat_control = FormattedTextControl(text=self.get_chat_text)
        
        # Scroll fijo al final
        self.chat_window = Window(
            content=self.chat_control, 
            style='class:chat.bg', 
            wrap_lines=True,
            get_vertical_scroll=lambda w: 100000, 
            always_hide_cursor=True
        )

        self.input_field = TextArea(
            height=3, 
            prompt='>>> ', 
            style='class:input', 
            multiline=False, 
            wrap_lines=True
        )
        self.input_field.accept_handler = self.on_send_enter

        self.header_control = FormattedTextControl(text=self.get_header_text)
        self.header_window = Window(content=self.header_control, height=1, style='class:top-bar')

        # --- LAYOUT ---
        self.layout = VSplit([
            HSplit([
                Window(FormattedTextControl([("class:sidebar.header", " TelegramTUI v3.0 ")]), height=1),
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
        result = []
        peers = self.network.get_peers()
        
        style_sys = "class:sidebar.selected" if self.current_chat_fp == "SYSTEM" else ""
        result.append((style_sys, " 📢 System Logs\n"))

        for p in peers:
            fp = p['fingerprint']
            name = p.get('name', 'Unknown')[:20]
            name = name.replace("(AUTENTICACIÓN)", "").strip()
            
            style_peer = "class:sidebar.selected" if fp == self.current_chat_fp else ""
            result.append((style_peer, f" 👤 {name}\n"))
            
        return result

    def get_chat_text(self):
        if self.current_chat_fp == "SYSTEM":
            return self.system_logs
        
        if not self.current_chat_fp:
            return [("", "\n\n   Selecciona un chat con TAB...")]
        
        msgs = self.messages.get(self.current_chat_fp, [])
        if not msgs:
            return [("", "\n   No hay mensajes. Escribe para iniciar...")]
        
        return msgs

    def get_header_text(self):
        if not self.current_chat_fp: return [("", " DNIe Messenger")]
        if self.current_chat_fp == "SYSTEM": return [("", " Logs del Sistema")]
        
        name = self.current_chat_fp[:8]
        for p in self.network.get_peers():
            if p['fingerprint'] == self.current_chat_fp:
                name = p.get('name', name).replace("(AUTENTICACIÓN)", "").strip()
                break
        return [("", f" 💬 {name}  |  "), ("#81c784", "Online")]

    # --- LÓGICA UI ---
    def update_sidebar(self):
        get_app().invalidate()

    def log_system(self, text):
        t = time.strftime("%H:%M")
        self.system_logs.append(("class:msg.time", f"[{t}] "))
        self.system_logs.append(("class:system", f"{text}\n"))
        if self.current_chat_fp == "SYSTEM":
             get_app().invalidate()

    def add_message(self, fp, text, is_me=True):
        if fp not in self.messages: self.messages[fp] = []
        
        t = time.strftime("%H:%M")
        if is_me:
            prefix_style = "class:msg.me bold"
            prefix_text = "Yo: "
        else:
            prefix_style = "class:msg.them bold"
            name = "Peer"
            for p in self.network.get_peers():
                if p['fingerprint'] == fp:
                    name = p['name'].replace("(AUTENTICACIÓN)", "").strip().split()[0]
                    break
            prefix_text = f"{name}: "
        
        msg_line = [
            (prefix_style, prefix_text),
            ("", f"{text} "),
            ("class:msg.time", f"{t}\n")
        ]
        
        self.messages[fp].extend(msg_line)
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
            self.input_field.buffer.reset()
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

        # 2. Iniciar Red
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
    print("=== DNIe Messenger TUI v3.0 (Fixed) ===")
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