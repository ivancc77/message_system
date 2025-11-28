#!/usr/bin/env python3
import asyncio, sys, time, msgpack, getpass
from prompt_toolkit import Application
from prompt_toolkit.layout import Layout, HSplit, VSplit, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.widgets import Frame, TextArea
from prompt_toolkit.styles import Style
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.output import create_output 

from dnie_real import DNIeReal
from network import CompleteNetwork

class StdoutRedirector:
    def __init__(self, ui): self.ui = ui; self.buf = ""
    def write(self, text):
        if not text: return
        self.buf += text
        if "\n" in self.buf:
            lines = self.buf.split("\n")
            for l in lines[:-1]: 
                if l.strip(): self.ui.log_system(f"⚙️ {l.strip()}")
            self.buf = lines[-1]
    def flush(self): pass

class GuiNetwork(CompleteNetwork):
    def __init__(self, dnie, ui): super().__init__(dnie); self.ui = ui
    def add_discovered_peer(self, info):
        super().add_discovered_peer(info)
        self.ui.log_system(f"🔍 Detectado: {info['name']}")
        self.ui.update_ui()
    def remove_discovered_peer(self, name):
        super().remove_discovered_peer(name)
        self.ui.log_system("📉 Peer pasó a Offline")
        self.ui.update_ui()
    def _handle_text(self, payload, remote_fp):
        try:
            txt = msgpack.unpackb(self.noise.decrypt_message(payload, remote_fp))['text']
            self.ui.add_message(remote_fp, txt, is_me=False)
        except: self.ui.log_system("⚠️ Error msg decrypt")

class TelegramTUI:
    def __init__(self, username, port, pin):
        self.username, self.port, self.pin = username, port, pin
        self.chat_fp, self.msgs, self.logs = "SYSTEM", {}, []
        self.dnie = DNIeReal()
        self.network = GuiNetwork(self.dnie, self)
        
        # Estilos y Layout
        self.style = Style.from_dict({'sidebar': 'bg:#232323 #aaa', 'sidebar.sel': 'bg:#005fce #fff bold', 'chat': 'bg:#1e1e1e #fff', 'me': '#64b5f6', 'them': '#81c784', 'log': '#ffb74d italic'})
        self.input = TextArea(height=3, prompt='>>> ', style='bg:#333 #fff', multiline=False)
        self.input.accept_handler = self.on_enter
        
        self.layout = VSplit([
            Window(FormattedTextControl(self.get_sidebar), width=30, style='class:sidebar'),
            HSplit([
                Window(FormattedTextControl(self.get_header), height=1, style='bg:#181818 #81c784 bold'),
                Window(FormattedTextControl(self.get_chat), style='class:chat', wrap_lines=True),
                Frame(self.input)
            ])
        ])
        
        self.kb = KeyBindings()
        self.kb.add('c-c', 'c-q')(lambda e: e.app.exit())
        self.kb.add('tab')(lambda e: self.cycle_chat())

    def get_sidebar(self):
        res = [("class:sidebar.sel" if self.chat_fp=="SYSTEM" else "", " 📢 System Logs\n")]
        for p in self.network.get_peers():
            icon, name = ("💤", p['name']) if p['ip']=='Offline' else ("👤", p['name'])
            res.append(("class:sidebar.sel" if p['fingerprint']==self.chat_fp else "", f" {icon} {name[:15]}\n"))
        return res

    def get_chat(self):
        if self.chat_fp == "SYSTEM": return self.logs[-50:]
        return self.msgs.get(self.chat_fp, [("", "\n   📭 Chat vacío.")])

    def get_header(self):
        if self.chat_fp == "SYSTEM": return " 🖥️  Logs"
        return f" 💬 Chat con: {self.chat_fp[:8]}..."

    def log_system(self, t): self.logs.append(("class:log", f"[{time.strftime('%H:%M')}] {t}\n")); self.update_ui()
    def update_ui(self): 
        try: self.app.invalidate() 
        except: pass

    def add_message(self, fp, text, is_me):
        self.msgs.setdefault(fp, []).append(("class:me" if is_me else "class:them", f"{'Yo' if is_me else 'Peer'}: {text} \n"))
        self.update_ui()

    def cycle_chat(self):
        ids = ["SYSTEM"] + [p['fingerprint'] for p in self.network.get_peers()]
        self.chat_fp = ids[(ids.index(self.chat_fp) + 1) % len(ids)] if self.chat_fp in ids else "SYSTEM"
        self.update_ui()

    def on_enter(self, _):
        txt = self.input.text.strip()
        if not txt or self.chat_fp == "SYSTEM": return
        asyncio.create_task(self.send(self.chat_fp, txt))
        self.input.buffer.reset()

    async def send(self, fp, txt):
        if await self.network.send_message(fp, txt): self.add_message(fp, txt, True)
        else: self.log_system("❌ Error envío")

    async def run(self):
        if not await self.dnie.initialize(self.pin): return
        self.network.UDP_PORT = self.port
        await self.network.start(self.username)
        
        sys.stdout = sys.stderr = StdoutRedirector(self)
        self.app = Application(layout=Layout(self.layout), key_bindings=self.kb, style=self.style, full_screen=True, output=create_output(stdout=sys.__stdout__))
        try: await self.app.run_async()
        finally: await self.network.stop()

if __name__ == "__main__":
    if sys.platform == 'win32': asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    u = input("Tu Nombre: ") or "User"
    p = int(input("Puerto UDP (6666): ") or 6666)
    pin = getpass.getpass("PIN DNIe: ")
    asyncio.run(TelegramTUI(u, p, pin).run())