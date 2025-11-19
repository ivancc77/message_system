#!/usr/bin/env python3
"""
DNI Messenger - Interfaz Gráfica Actualizada
"""
import asyncio
from datetime import datetime
from typing import List, Dict

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, ScrollableContainer
from textual.widgets import Header, Footer, Button, Input, Static, ListItem, ListView, Label

# Importar lógica actualizada
from dnie_real import DNIeReal as DNIeManager
from network import CompleteNetwork 

class MessageView(ScrollableContainer):
    def add_message(self, sender: str, message: str, msg_type: str = "sent"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        color = "green" if msg_type == "sent" else "blue"
        if msg_type == "system": color = "yellow"
        
        self.mount(Label(f"[{timestamp}] {sender}: {message}", style=color))
        self.scroll_end()

class PeersList(ListView):
    def update_peers(self, peers: List[Dict]):
        self.clear()
        for peer in peers:
            name = peer.get('name', 'Desconocido')
            fp = peer.get('fingerprint', '')[:8]
            self.append(ListItem(Label(f"👤 {name} [{fp}]")))

class DNIMessengerGUI(App):
    CSS = """
    Screen { layout: grid; grid-size: 2; grid-columns: 1fr 3fr; }
    .sidebar { height: 100%; dock: left; border-right: solid green; }
    .chat-area { height: 100%; }
    .input-bar { dock: bottom; height: 3; }
    """
    
    BINDINGS = [("ctrl+q", "quit", "Salir"), ("ctrl+r", "refresh_peers", "Refrescar")]

    def __init__(self):
        super().__init__()
        self.dnie = DNIeManager()
        self.network = CompleteNetwork(self.dnie) # Sin crypto explícito
        self.username = "Usuario"

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(classes="sidebar"):
            yield Label("📡 Peers")
            yield PeersList(id="peers_list")
            yield Button("Refrescar", id="btn_refresh")
        with Vertical(classes="chat-area"):
            yield MessageView(id="chat_view")
            with Horizontal(classes="input-bar"):
                yield Input(placeholder="Escribe aquí...", id="inp_msg")
                yield Button("Enviar", id="btn_send")
        yield Footer()

    async def on_mount(self):
        self.query_one("#chat_view").add_message("SYS", "Iniciando DNIe...", "system")
        if await self.dnie.initialize():
            self.username = self.dnie.get_user_name()
            self.query_one("#chat_view").add_message("SYS", f"Identificado como: {self.username}", "system")
            
            await self.network.start(self.username)
            self.query_one("#chat_view").add_message("SYS", "Red P2P lista. Claves cargadas.", "system")
            self.set_interval(5, self.refresh_peers) # Auto-refresco
        else:
            self.query_one("#chat_view").add_message("SYS", "ERROR DNIe", "system")

    def refresh_peers(self):
        peers = self.network.get_peers()
        self.query_one("#peers_list").update_peers(peers)

    async def on_button_pressed(self, event):
        if event.button.id == "btn_send":
            await self.send_message()
        elif event.button.id == "btn_refresh":
            self.refresh_peers()

    async def send_message(self):
        inp = self.query_one("#inp_msg")
        text = inp.value
        if not text: return
        
        peers = self.network.get_peers()
        if peers:
            # Por defecto enviamos al primero para probar
            target = peers[0] 
            self.query_one("#chat_view").add_message("YO", text, "sent")
            await self.network.send_message(target['fingerprint'], text)
            inp.value = ""
        else:
            self.query_one("#chat_view").add_message("SYS", "No hay peers conectados", "system")

if __name__ == "__main__":
    app = DNIMessengerGUI()
    app.run()