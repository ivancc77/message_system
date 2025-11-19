#!/usr/bin/env python3
"""
DNI Messenger - Versión Completa con Red Mejorada
Sistema P2P de mensajería con DNIe
"""
import asyncio
import sys
from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# IMPORTACIONES ACTUALIZADAS:
from dnie_real import DNIeReal as DNIeManager
from crypto import SimpleCrypto
from network import CompleteNetwork  # ✅ Clase actualizada

console = Console()

class DNIMessenger:
    def __init__(self):
        self.dnie = DNIeManager('C:/Archivos de programa/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll')
        self.crypto = SimpleCrypto()
        self.network = CompleteNetwork(self.dnie, self.crypto)  # ✅ Pasar dependencias
        self.running = False
        self.username = "Usuario"
        self.manual_peers = []  # Para peers agregados manualmente
        
    async def start(self):
        console.print(Panel.fit("🚀 DNI Messenger - Red P2P Completa", style="bold blue"))
        
        # 1. DNIe
        console.print("1️⃣ Inicializando DNIe...")
        if await self.dnie.initialize():
            self.username = self.dnie.get_user_name()
            console.print(f"✅ Usuario: {self.username}", style="green")
        
        # 2. Crypto
        console.print("2️⃣ Generando claves...")
        self.crypto.generate_keys()
        console.print("✅ Claves OK", style="green")
        
        # 3. Red completa
        console.print("3️⃣ Iniciando red P2P completa...")
        await self.network.start(self.username, self.crypto.get_public_key())
        console.print("✅ Red OK", style="green")
        
        # 4. Interfaz mejorada
        await self.run_chat()
    
    async def run_chat(self):
        console.print("\n" + "="*60)
        console.print("💬 CHAT INICIADO - DNI Messenger P2P")
        console.print("="*60)
        
        # Mostrar comandos disponibles
        self.show_help()
        
        # Agregar peer demo automáticamente
        await self.add_demo_peer()
        
        while True:
            try:
                cmd = await asyncio.to_thread(Prompt.ask, f"[{self.username[:20]}]")
                
                if cmd == "/peers":
                    await self.show_peers()
                    
                elif cmd == "/help":
                    self.show_help()
                    
                elif cmd.startswith("/connect"):
                    await self.connect_manual()
                    
                elif cmd.startswith("/demo"):
                    await self.add_demo_peer()
                    
                elif cmd == "/send":
                    await self.send_message_interface()
                    
                elif cmd == "/debug":
                    await self.show_debug_info()
                    
                elif cmd == "/status":
                    await self.show_status()
                    
                elif cmd == "/tofu":
                    await self.show_tofu_status()
                    
                elif cmd == "/quit":
                    break
                    
                else:
                    console.print("❓ Comando no reconocido. Usa /help para ver comandos.", style="red")
                    
            except KeyboardInterrupt:
                break
        
        await self.network.stop()
        console.print("\n👋 ¡Hasta luego!")
    
    def show_help(self):
        """Muestra ayuda de comandos"""
        table = Table(title="📋 Comandos Disponibles")
        table.add_column("Comando", style="cyan", no_wrap=True)
        table.add_column("Descripción", style="white")
        
        table.add_row("/peers", "Ver peers disponibles (mDNS discovery)")
        table.add_row("/connect", "Conectar manualmente a localhost:6666")
        table.add_row("/demo", "Agregar peer de demostración")
        table.add_row("/send", "Enviar mensaje a un peer")
        table.add_row("/debug", "Información de debug de red")
        table.add_row("/status", "Estado completo del sistema")
        table.add_row("/tofu", "Estado Trust-On-First-Use")
        table.add_row("/help", "Mostrar esta ayuda")
        table.add_row("/quit", "Salir de la aplicación")
        
        console.print(table)
    
    async def show_peers(self):
        """Muestra peers disponibles (mDNS + manuales)"""
        # Peers de mDNS (red completa)
        mdns_peers = self.network.get_peers()
        
        # Crear tabla de peers
        table = Table(title="📡 Peers Disponibles")
        table.add_column("Tipo", style="cyan")
        table.add_column("Nombre Real", style="green")
        table.add_column("Instancia mDNS", style="yellow")
        table.add_column("Dirección", style="blue")
        table.add_column("Estado", style="magenta")
        
        total_peers = 0
        
        # Agregar peers mDNS
        if mdns_peers:
            for peer in mdns_peers:
                fingerprint = peer.get('fingerprint', '')
                status = "🟢 Verificado" if fingerprint and fingerprint in self.network.contact_book else "🔶 Pendiente TOFU"
                
                table.add_row(
                    "mDNS", 
                    peer.get('name', 'Desconocido'),
                    peer.get('instance_name', 'N/A'),
                    f"{peer['ip']}:{peer['port']}", 
                    status
                )
                total_peers += 1
        
        # Agregar peers manuales
        if self.manual_peers:
            for peer in self.manual_peers:
                table.add_row(
                    "Manual", 
                    peer['name'], 
                    "N/A",
                    f"{peer['ip']}:{peer['port']}", 
                    "🔶 Manual"
                )
                total_peers += 1
        
        if total_peers == 0:
            table.add_row("Ninguno", "No hay peers", "N/A", "Usa /connect o /demo", "⚪ Vacío")
        
        console.print(table)
        console.print(f"\n📊 Total: {total_peers} peer(s) disponible(s)")
        
        # Mostrar estadísticas adicionales
        verified = len(self.network.get_verified_peers())
        pending = len(self.network.get_pending_contacts())
        console.print(f"✅ Verificados (TOFU): {verified}")
        console.print(f"⏳ Pendientes: {pending}")
    
    async def connect_manual(self):
        """Conecta manualmente a localhost"""
        try:
            # Por defecto conectar a localhost (otra instancia)
            peer_info = {
                'name': f'Localhost-{self.username}',
                'ip': '127.0.0.1',
                'port': 6666,
                'type': 'manual'
            }
            
            # Verificar si ya existe
            exists = any(p['ip'] == peer_info['ip'] and p['port'] == peer_info['port'] 
                        for p in self.manual_peers)
            
            if not exists:
                self.manual_peers.append(peer_info)
                console.print(f"✅ Peer manual agregado: {peer_info['ip']}:{peer_info['port']}", style="green")
            else:
                console.print("⚠️ Este peer ya existe", style="yellow")
                
        except Exception as e:
            console.print(f"❌ Error conectando: {e}", style="red")
    
    async def add_demo_peer(self):
        """Agrega peer de demostración"""
        demo_peer = {
            'name': 'Usuario-Demo-Remoto',
            'ip': '192.168.1.100',
            'port': 6666,
            'type': 'demo'
        }
        
        # Verificar si ya existe
        exists = any(p.get('type') == 'demo' for p in self.manual_peers)
        
        if not exists:
            self.manual_peers.append(demo_peer)
            console.print("🎭 Peer de demostración agregado", style="cyan")
        else:
            console.print("ℹ️ Peer demo ya existe", style="dim")
    
    async def send_message_interface(self):
        """Interfaz para enviar mensajes"""
        # Obtener todos los peers
        all_peers = self.network.get_peers() + self.manual_peers
        
        if not all_peers:
            console.print("❌ No hay peers disponibles. Usa /peers para buscar o /demo para demo", style="red")
            return
        
        # Mostrar peers disponibles
        console.print("\n📋 Selecciona destinatario:")
        for i, peer in enumerate(all_peers, 1):
            tipo_icon = "🌐" if peer.get('fingerprint') else "🎭" if peer.get('type') == 'demo' else "🔗"
            name = peer.get('name', peer.get('instance_name', 'Desconocido'))
            console.print(f"  {i}. {tipo_icon} {name} ({peer['ip']}:{peer['port']})")
        
        try:
            choice = await asyncio.to_thread(Prompt.ask, "Número del destinatario")
            peer_idx = int(choice) - 1
            
            if 0 <= peer_idx < len(all_peers):
                peer = all_peers[peer_idx]
                message = await asyncio.to_thread(Prompt.ask, "Escribe tu mensaje")
                
                # Obtener nombre del peer
                peer_name = peer.get('name', peer.get('instance_name', 'Desconocido'))
                
                console.print(f"📤 Enviando a {peer_name}...", style="blue")
                
                # Enviar usando la red completa
                success = await self.network.send_message(peer_name, message)
                
                if success:
                    console.print("✅ Mensaje enviado correctamente", style="green")
                else:
                    console.print("❌ Error enviando mensaje", style="red")
            else:
                console.print("❌ Selección inválida", style="red")
                
        except (ValueError, KeyboardInterrupt):
            console.print("❌ Operación cancelada", style="yellow")
    
    async def show_debug_info(self):
        """Muestra información de debug"""
        console.print("\n🔍 INFORMACIÓN DE DEBUG")
        console.print("=" * 40)
        
        stats = self.network.get_network_stats()
        
        console.print(f"👤 Usuario: {self.username}")
        console.print(f"🏷️ Instancia mDNS: {stats.get('my_instance_name', 'N/A')}")
        console.print(f"🔐 Fingerprint: {stats.get('my_fingerprint', 'N/A')}")
        console.print(f"🌐 IP Local: {stats.get('local_ip', 'N/A')}")
        console.print(f"📡 Puerto UDP: {stats.get('udp_port', 'N/A')}")
        console.print(f"🔍 Servicio mDNS: {self.network.SERVICE_TYPE}")
        console.print(f"⏱️ Tiempo activo: {stats.get('uptime_seconds', 0)} segundos")
        
        # Estado de claves
        has_keys = self.crypto.private_key is not None
        console.print(f"🔑 Claves generadas: {'✅' if has_keys else '❌'}")
        
        # Estado de red
        console.print(f"📊 Peers descubiertos: {stats.get('peers_discovered', 0)}")
        console.print(f"📊 Peers verificados: {stats.get('peers_verified', 0)}")
        console.print(f"📊 Contactos pendientes: {stats.get('pending_contacts', 0)}")
        console.print(f"📊 Conexiones activas: {stats.get('active_connections', 0)}")
        console.print(f"📊 Mensajes enviados: {stats.get('messages_sent', 0)}")
        console.print(f"📊 Mensajes recibidos: {stats.get('messages_received', 0)}")
        
        console.print("\n💡 Usando red P2P completa con Noise IK + CIDs")
    
    async def show_status(self):
        """Muestra estado del sistema"""
        table = Table(title="📊 Estado del Sistema Completo")
        table.add_column("Componente", style="cyan")
        table.add_column("Estado", style="green")
        table.add_column("Detalles", style="white")
        
        stats = self.network.get_network_stats()
        
        table.add_row("DNIe", "✅ Activo", f"Modo: {'Mock' if self.dnie.is_mock_mode() else 'Real'}")
        table.add_row("Criptografía", "✅ Activo", "X25519 + ChaCha20Poly1305")
        table.add_row("Noise IK", "✅ Implementado", "Handshake + Session Management")
        table.add_row("Red mDNS", "✅ Completa", f"Servicio: {self.network.SERVICE_TYPE}")
        table.add_row("Connection IDs", "✅ Activo", f"Conexiones: {stats.get('active_connections', 0)}")
        table.add_row("TOFU", "✅ Activo", f"Verificados: {stats.get('peers_verified', 0)}")
        table.add_row("Interfaz", "✅ Activo", "TUI con Rich")
        table.add_row("Peers", f"📡 {stats.get('peers_discovered', 0)}", "mDNS Discovery")
        
        console.print(table)
    
    async def show_tofu_status(self):
        """Muestra estado TOFU (Trust On First Use)"""
        console.print("\n🔐 ESTADO TRUST-ON-FIRST-USE (TOFU)")
        console.print("=" * 50)
        
        verified_peers = self.network.get_verified_peers()
        pending_contacts = self.network.get_pending_contacts()
        
        if verified_peers:
            console.print("✅ Contactos Verificados:")
            for peer in verified_peers:
                console.print(f"   • {peer['name']} ({peer.get('fingerprint', 'N/A')[:8]}...)")
        else:
            console.print("✅ No hay contactos verificados aún")
        
        if pending_contacts:
            console.print("\n⏳ Contactos Pendientes de Verificación:")
            for peer in pending_contacts:
                console.print(f"   • {peer['name']} ({peer.get('fingerprint', 'N/A')[:8]}...)")
        else:
            console.print("\n⏳ No hay contactos pendientes")
        
        console.print(f"\n📊 Total verificados: {len(verified_peers)}")
        console.print(f"📊 Total pendientes: {len(pending_contacts)}")

def main():
    """Función principal"""
    if sys.version_info < (3, 8):
        console.print("❌ Se requiere Python 3.8+", style="red")
        sys.exit(1)
    
    messenger = DNIMessenger()
    
    try:
        asyncio.run(messenger.start())
    except KeyboardInterrupt:
        console.print("\n👋 Interrumpido por usuario")
    except Exception as e:
        console.print(f"❌ Error: {e}", style="red")

if __name__ == "__main__":
    main()
