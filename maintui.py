#!/usr/bin/env python3
"""
DNI Messenger - Versión Final TUI
Lanzador principal con interfaz gráfica estilo Telegram
"""
import asyncio
import sys
from dnie_real import DNIeReal as DNIeManager
from network import CompleteNetwork
from tui import TelegramStyleTUI

class DNIMessenger:
    def __init__(self):
        self.dnie = DNIeManager() 
        self.network = CompleteNetwork(self.dnie)
        self.username = "Victor"

    async def start(self):
        print("🚀 Cargando DNI Messenger TUI...")
        print("   Por favor, espera mientras se lee el DNIe...")

        # 1. Inicialización del Hardware
        if await self.dnie.initialize():
            self.username = self.dnie.get_user_name()
            print(f"✅ Identidad verificada: {self.username}")
        else:
            print("❌ Error: No se pudo leer el DNIe. Revisa el lector.")
            return

        # 2. Iniciar Red
        print("📡 Iniciando listeners de red...")
        await self.network.start(self.username)
        
        # 3. Iniciar Interfaz Gráfica
        # Creamos la instancia de la TUI pasándole la app completa
        tui = TelegramStyleTUI(self)
        
        # Vinculamos la aplicación UI a la red para que la red pueda forzar redibujados
        self.network.ui_app = tui.application 
        
        print("🖥️  Abriendo interfaz...")
        await asyncio.sleep(1) # Pequeña pausa para leer logs antes de borrar pantalla
        
        # Ejecutamos la interfaz (esto bloquea hasta que se pulsa Ctrl+C en la TUI)
        try:
            await tui.application.run_async()
        except Exception as e:
            # En caso de crash de la UI, intentamos cerrar limpio
            pass
        
        # 4. Limpieza al salir
        print("Apagando red...")
        await self.network.stop()
        print("👋 ¡Hasta luego!")

def main():
    if sys.version_info < (3, 8):
        print("Python 3.8+ requerido")
        return
        
    app = DNIMessenger()
    try:
        # Usamos asyncio.run para gestionar el loop principal
        asyncio.run(app.start())
    except KeyboardInterrupt:
        # Captura Ctrl+C si ocurre fuera de la TUI
        pass
    except Exception as e:
        print(f"❌ Error fatal: {e}")

if __name__ == "__main__":
    main()