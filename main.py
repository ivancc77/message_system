#!/usr/bin/env python3
import asyncio, sys, getpass
from dnie_real import DNIeReal
from network import CompleteNetwork

async def main():
    print("🚀 CLI Mode - DNIe Messenger")
    pin = getpass.getpass("PIN DNIe: ")
    
    dnie = DNIeReal()
    if not await dnie.initialize(pin): return

    net = CompleteNetwork(dnie)
    await net.start(dnie.get_user_name())
    
    print(f"✅ Conectado como {dnie.get_user_name()}. Comandos: /list, /send <nombre> <msg>, /quit")
    
    while True:
        try:
            cmd = await asyncio.to_thread(input, ">>> ")
            if cmd == "/quit": break
            elif cmd == "/list":
                for p in net.get_peers(): print(f"- {p['name']} ({p['ip']})")
            elif cmd.startswith("/send "):
                _, target, msg = cmd.split(" ", 2)
                await net.send_message(target, msg)
        except Exception as e: print(f"Error: {e}")

    await net.stop()

if __name__ == "__main__":
    if sys.platform == 'win32': asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try: asyncio.run(main())
    except KeyboardInterrupt: pass
