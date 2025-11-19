#!/usr/bin/env python3
"""
DNI Messenger - Versión Completa
Sistema P2P seguro con identidad DNIe
"""
import asyncio
import sys
from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel
from rich.table import Table

# IMPORTACIONES ACTUALIZADAS:
from dnie_real import DNIeReal as DNIeManager
# Ya no importamos crypto, la red se encarga
from network import CompleteNetwork

console = Console()

class DNIMessenger:
    def __init__(self):
        # 1. Inicializar gestor de DNIe
        # Ajusta la ruta de la librería PKCS#11 si es necesario
        self.dnie = DNIeManager() 
        
        # 2. Inicializar Red (La red ahora gestiona su propia criptografía)
        self.network = CompleteNetwork(self.dnie)
        
        self.username = "Usuario"
        self.running = False
        
    async def start(self):
        console.print(Panel.fit("🚀 DNI Messenger - Red P2P Segura", style="bold blue"))
        
        # 1. Inicializar DNIe (Pide PIN si es necesario)
        console.print("1️⃣ Inicializando DNIe...")
        if await self.dnie.initialize():
            self.username = self.dnie.get_user_name()
            console.print(f"✅ Identidad DNIe cargada: {self.username}", style="green")
        else:
            console.print("❌ Fallo al leer DNIe. Saliendo.", style="red")
            return
        
        # 2. Iniciar Red (Esto cargará/generará identity.pem automáticamente)
        console.print("2️⃣ Iniciando red P2P y Criptografía...")
        await self.network.start(self.username)
        
        # 3. Interfaz de Chat
        await self.run_chat()
    
    async def run_chat(self):
        console.print("\n" + "="*60)
        console.print(f"💬 CHAT INICIADO - {self.username}")
        console.print("="*60)
        self.show_help()
        
        while True:
            try:
                # El prompt muestra tu fingerprint abreviado
                fp_short = self.network.my_fingerprint[:8] if self.network.my_fingerprint else "..."
                cmd = await asyncio.to_thread(Prompt.ask, f"[{self.username}::{fp_short}]")
                
                if cmd == "/peers":
                    await self.show_peers()
                elif cmd == "/help":
                    self.show_help()
                elif cmd.startswith("/send "):
                    # Formato: /send NOMBRE mensaje...
                    parts = cmd.split(" ", 2)
                    if len(parts) < 3:
                        console.print("❌ Uso: /send <NombrePeer> <Mensaje>", style="yellow")
                    else:
                        target = parts[1]
                        msg = parts[2]
                        await self.network.send_message(target, msg)
                elif cmd == "/stats":
                    console.print(self.network.get_network_stats())
                elif cmd == "/quit":
                    break
                else:
                    if not cmd.startswith("/"):
                        console.print("⚠️ Usa /send para enviar mensajes o /help", style="dim")
            except KeyboardInterrupt:
                break
        
        await self.network.stop()
        console.print("\n👋 ¡Hasta luego!")

    def show_help(self):
        table = Table(title="Comandos")
        table.add_row("/peers", "Ver usuarios descubiertos")
        table.add_row("/send <nombre> <txt>", "Enviar mensaje a alguien")
        table.add_row("/stats", "Ver estadísticas de red")
        table.add_row("/quit", "Salir")
        console.print(table)
    
    async def show_peers(self):
        peers = self.network.get_peers()
        table = Table(title="📡 Peers Descubiertos (mDNS)")
        table.add_column("Nombre", style="cyan")
        table.add_column("Fingerprint", style="magenta")
        table.add_column("IP:Port", style="green")
        
        if not peers:
            table.add_row("---", "Buscando...", "---")
        
        for p in peers:
            table.add_row(
                p['name'], 
                p.get('fingerprint', 'N/A')[:12]+"...", 
                f"{p['ip']}:{p['port']}"
            )
        console.print(table)

def main():
    if sys.version_info < (3, 8):
        print("Python 3.8+ requerido")
        return
    
    app = DNIMessenger()
    try:
        asyncio.run(app.start())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        console.print(f"❌ Error fatal: {e}", style="red")

if __name__ == "__main__":
    main()