#!/usr/bin/env python3
"""
DNI Messenger - Interfaz Gráfica con Red Completa
"""
import asyncio
from datetime import datetime
from typing import List, Dict

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import (
    Header, Footer, Button, Input, TextArea, Static, 
    DataTable, Tabs, Tab, ListItem, ListView, Label
)
from textual.binding import Binding
from textual.message import Message
from textual.reactive import reactive

# Importar lógica actualizada
from dnie_real import DNIeReal as DNIeManager
from crypto import SimpleCrypto
from network import CompleteNetwork  # ✅ Clase actualizada

class MessageView(ScrollableContainer):
    """Vista de mensajes estilo chat"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.messages: List[Dict] = []
    
    def add_message(self, sender: str, message: str, msg_type: str = "sent"):
        """Agrega mensaje al chat"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        msg_widget = Static(
            f"[{timestamp}] {sender}: {message}",
            classes=f"message message-{msg_type}"
        )
        
        self.mount(msg_widget)
        self.scroll_end()

class PeersList(ListView):
    """Lista de peers disponibles"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.peers: List[Dict] = []
    
    def update_peers(self, peers: List[Dict]):
        """Actualiza lista de peers"""
        self.clear()
        self.peers = peers
        
        for peer in peers:
            # Iconos según tipo y estado
            if peer.get('fingerprint'):
                status_icon = "🟢" if peer.get('verified') else "🔶"
            else:
                status_icon = "🎭" if peer.get('type') == 'demo' else "🔗"
            
            peer_name = peer.get('name', peer.get('instance_name', 'Desconocido'))
            peer_item = ListItem(
                Label(f"{status_icon} {peer_name} ({peer['ip']}:{peer['port']})")
            )
            self.append(peer_item)

class DNIMessengerGUI(App):
    """Aplicación principal con interfaz gráfica actualizada"""
    
    CSS = """
    .title {
        dock: top;
        height: 3;
        background: $boost;
        color: $text;
        content-align: center middle;
    }
    
    .sidebar {
        dock: left;
        width: 32;
        background: $surface;
    }
    
    .main-area {
        background: $background;
    }
    
    .message-sent {
        background: $success;
        color: $text;
        margin: 1;
        padding: 1;
    }
    
    .message-received {
        background: $primary;
        color: $text;
        margin: 1;
        padding: 1;
    }
    
    .message-system {
        background: $warning;
        color: $text;
        margin: 1;
        padding: 1;
    }
    
    .input-area {
        dock: bottom;
        height: 3;
        background: $surface;
    }
    
    .status-bar {
        dock: bottom;
        height: 1;
        background: $accent;
    }
    """
    
    BINDINGS = [
        Binding("ctrl+q", "quit", "Salir"),
        Binding("ctrl+p", "show_peers", "Peers"),
        Binding("ctrl+s", "show_status", "Estado"),
        Binding("ctrl+d", "show_debug", "Debug"),
        Binding("ctrl+t", "show_tofu", "TOFU"),
        Binding("enter", "send_message", "Enviar", show=False),
    ]
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        
        # Lógica del messenger actualizada
        self.dnie = DNIeManager('C:/Archivos de programa/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll')
        self.crypto = SimpleCrypto()
        self.network = CompleteNetwork(self.dnie, self.crypto)  # ✅ Con dependencias
        self.username = "Usuario"
        self.manual_peers = []
        
        # UI Components
        self.message_view = None
        self.peers_list = None
        self.message_input = None
        self.status_bar = None
        
    def compose(self) -> ComposeResult:
        """Compone la interfaz"""
        yield Header(show_clock=True)
        
        # Título actualizado
        yield Static("🚀 DNI Messenger - Red P2P Completa", classes="title")
        
        with Horizontal():
            # Sidebar izquierdo
            with Vertical(classes="sidebar"):
                yield Static("📡 Peers Conectados", id="peers-title")
                yield PeersList(id="peers-list")
                
                yield Static("\n🎛️ Controles", id="controls-title")
                yield Button("🔄 Actualizar Peers", id="refresh-peers")
                yield Button("🔗 Conectar Manual", id="connect-manual") 
                yield Button("🎭 Agregar Demo", id="add-demo")
                yield Button("📊 Estado Sistema", id="show-status")
                yield Button("🔍 Debug Info", id="show-debug")
                yield Button("🔐 Estado TOFU", id="show-tofu")
            
            # Área principal de chat
            with Vertical(classes="main-area"):
                # Área de mensajes
                yield MessageView(id="message-view")
                
                # Área de input
                with Horizontal(classes="input-area"):
                    yield Input(placeholder="Escribe tu mensaje aquí...", id="message-input")
                    yield Button("📤 Enviar", id="send-button")
        
        # Barra de estado
        yield Static("Iniciando DNI Messenger P2P...", id="status-bar", classes="status-bar")
        yield Footer()
    
    async def on_mount(self) -> None:
        """Inicializar la aplicación"""
        # Obtener referencias a widgets
        self.message_view = self.query_one("#message-view", MessageView)
        self.peers_list = self.query_one("#peers-list", PeersList) 
        self.message_input = self.query_one("#message-input", Input)
        self.status_bar = self.query_one("#status-bar", Static)
        
        # Configurar input para enviar con Enter
        self.message_input.focus()
        
        # Inicializar DNI Messenger
        await self.initialize_messenger()
    
    async def initialize_messenger(self):
        """Inicializa los componentes del messenger"""
        self.status_bar.update("🔄 Inicializando DNIe...")
        
        # 1. DNIe
        if await self.dnie.initialize():
            self.username = self.dnie.get_user_name()
            self.message_view.add_message("Sistema", f"✅ Usuario: {self.username}", "system")
        
        # 2. Crypto
        self.status_bar.update("🔄 Generando claves...")
        self.crypto.generate_keys()
        self.message_view.add_message("Sistema", "✅ Claves criptográficas generadas", "system")
        
        # 3. Red P2P completa
        self.status_bar.update("🔄 Iniciando red P2P...")
        await self.network.start(self.username, self.crypto.get_public_key())
        self.message_view.add_message("Sistema", "✅ Red P2P completa iniciada", "system")
        
        # 4. Agregar peer demo automáticamente
        await self.add_demo_peer()
        
        # 5. Actualizar UI
        await self.refresh_peers()
        
        # 6. Mostrar estadísticas
        stats = self.network.get_network_stats()
        self.status_bar.update(f"✅ DNI Messenger listo - {stats.get('my_instance_name', self.username[:20])}")
        
        self.message_view.add_message("Sistema", "💬 ¡Bienvenido a DNI Messenger P2P!", "system")
        self.message_view.add_message("Sistema", f"🏷️ Tu instancia: {stats.get('my_instance_name', 'N/A')}", "system")
        self.message_view.add_message("Sistema", f"🔐 Fingerprint: {stats.get('my_fingerprint', 'N/A')[:12]}...", "system")
        self.message_view.add_message("Sistema", "Usa Ctrl+P para peers, Ctrl+S para estado, Ctrl+T para TOFU", "system")
    
    async def add_demo_peer(self):
        """Agrega peer de demostración"""
        demo_peer = {
            'name': 'Usuario-Demo-Remoto',
            'ip': '192.168.1.100',
            'port': 6666,
            'type': 'demo'
        }
        
        if not any(p.get('type') == 'demo' for p in self.manual_peers):
            self.manual_peers.append(demo_peer)
            self.message_view.add_message("Sistema", "🎭 Peer de demostración agregado", "system")
    
    async def refresh_peers(self):
        """Actualiza lista de peers"""
        all_peers = self.network.get_peers() + self.manual_peers
        
        # Marcar peers verificados
        for peer in all_peers:
            fingerprint = peer.get('fingerprint', '')
            if fingerprint and fingerprint in self.network.contact_book:
                peer['verified'] = True
        
        self.peers_list.update_peers(all_peers)
        
        count = len(all_peers)
        verified = len(self.network.get_verified_peers())
        pending = len(self.network.get_pending_contacts())
        
        self.message_view.add_message("Sistema", f"📡 {count} peer(s), ✅ {verified} verificados, ⏳ {pending} pendientes", "system")
    
    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Maneja clicks de botones"""
        button_id = event.button.id
        
        if button_id == "send-button":
            await self.send_message()
        elif button_id == "refresh-peers":
            await self.refresh_peers()
        elif button_id == "connect-manual":
            await self.connect_manual()
        elif button_id == "add-demo":
            await self.add_demo_peer()
            await self.refresh_peers()
        elif button_id == "show-status":
            await self.show_status()
        elif button_id == "show-debug":
            await self.show_debug()
        elif button_id == "show-tofu":
            await self.show_tofu()
    
    async def on_input_submitted(self, event: Input.Submitted) -> None:
        """Enter presionado en input"""
        if event.input.id == "message-input":
            await self.send_message()
    
    async def send_message(self):
        """Envía mensaje"""
        message_text = self.message_input.value.strip()
        if not message_text:
            return
        
        # Limpiar input
        self.message_input.value = ""
        
        # Obtener peers
        all_peers = self.network.get_peers() + self.manual_peers
        
        if not all_peers:
            self.message_view.add_message("Sistema", "❌ No hay peers disponibles", "system")
            return
        
        # Por simplicidad, enviar al primer peer disponible
        peer = all_peers[0]
        peer_name = peer.get('name', peer.get('instance_name', 'Desconocido'))
        
        # Mostrar mensaje enviado
        self.message_view.add_message(f"Tú → {peer_name}", message_text, "sent")
        
        # Enviar usando red completa
        success = await self.network.send_message(peer_name, message_text)
        
        if success:
            self.message_view.add_message("Sistema", "✅ Mensaje enviado", "system")
            
            # Simular respuesta después de 2 segundos (solo para peer demo)
            if peer.get('type') == 'demo':
                await asyncio.sleep(2)
                self.message_view.add_message(peer_name, "¡Hola! Mensaje recibido correctamente 👋", "received")
        else:
            self.message_view.add_message("Sistema", "❌ Error enviando mensaje", "system")
    
    async def connect_manual(self):
        """Conecta peer manual"""
        peer_info = {
            'name': f'Localhost-{self.username}',
            'ip': '127.0.0.1',
            'port': 6666,
            'type': 'manual'
        }
        
        if not any(p['ip'] == peer_info['ip'] for p in self.manual_peers):
            self.manual_peers.append(peer_info)
            self.message_view.add_message("Sistema", "✅ Peer localhost agregado", "system")
            await self.refresh_peers()
    
    async def show_status(self):
        """Muestra estado del sistema"""
        stats = self.network.get_network_stats()
        
        self.message_view.add_message("Sistema", "📊 ESTADO DEL SISTEMA COMPLETO", "system")
        self.message_view.add_message("Sistema", f"👤 Usuario: {self.username}", "system")
        self.message_view.add_message("Sistema", f"🏷️ Instancia: {stats.get('my_instance_name', 'N/A')}", "system")
        self.message_view.add_message("Sistema", f"🔐 DNIe: {'Mock' if self.dnie.is_mock_mode() else 'Real'}", "system")
        self.message_view.add_message("Sistema", f"📡 Peers: {stats.get('peers_discovered', 0)}", "system")
        self.message_view.add_message("Sistema", f"✅ Verificados: {stats.get('peers_verified', 0)}", "system")
        self.message_view.add_message("Sistema", f"🔗 Conexiones: {stats.get('active_connections', 0)}", "system")
        self.message_view.add_message("Sistema", f"🌐 IP: {stats.get('local_ip', 'N/A')}", "system")
    
    async def show_debug(self):
        """Muestra información de debug"""
        stats = self.network.get_network_stats()
        
        self.message_view.add_message("Sistema", "🔍 DEBUG INFO COMPLETO", "system")
        self.message_view.add_message("Sistema", f"🔑 Claves: {'✅' if self.crypto.private_key else '❌'}", "system")
        self.message_view.add_message("Sistema", f"📡 Puerto: {stats.get('udp_port', 'N/A')}", "system")
        self.message_view.add_message("Sistema", f"🔍 Servicio: {self.network.SERVICE_TYPE}", "system")
        self.message_view.add_message("Sistema", f"⏱️ Activo: {stats.get('uptime_seconds', 0)}s", "system")
        self.message_view.add_message("Sistema", f"📤 Enviados: {stats.get('messages_sent', 0)}", "system")
        self.message_view.add_message("Sistema", f"📥 Recibidos: {stats.get('messages_received', 0)}", "system")
    
    async def show_tofu(self):
        """Muestra estado TOFU"""
        verified = len(self.network.get_verified_peers())
        pending = len(self.network.get_pending_contacts())
        
        self.message_view.add_message("Sistema", "🔐 ESTADO TRUST-ON-FIRST-USE", "system")
        self.message_view.add_message("Sistema", f"✅ Contactos verificados: {verified}", "system")
        self.message_view.add_message("Sistema", f"⏳ Contactos pendientes: {pending}", "system")
        
        # Listar contactos pendientes
        for peer in self.network.get_pending_contacts():
            name = peer.get('name', 'Desconocido')
            fingerprint = peer.get('fingerprint', 'N/A')[:8]
            self.message_view.add_message("Sistema", f"   ⏳ {name} ({fingerprint}...)", "system")
    
    def action_show_peers(self) -> None:
        """Mostrar peers (Ctrl+P)"""
        asyncio.create_task(self.refresh_peers())
    
    def action_show_status(self) -> None:
        """Mostrar estado (Ctrl+S)"""
        asyncio.create_task(self.show_status())
    
    def action_show_debug(self) -> None:
        """Mostrar debug (Ctrl+D)"""
        asyncio.create_task(self.show_debug())
    
    def action_show_tofu(self) -> None:
        """Mostrar TOFU (Ctrl+T)"""
        asyncio.create_task(self.show_tofu())

def main():
    """Función principal"""
    app = DNIMessengerGUI()
    app.title = "DNI Messenger - Red P2P Completa"
    app.run()

if __name__ == "__main__":
    main()
