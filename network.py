"""
Red P2P Completa - VERSION ACADÉMICA (CORREGIDA)
Cumple requisitos: BLAKE2s, Verificación Firma DNIe, Cola Offline
"""
import asyncio
import socket
import time
import struct
import hashlib
import os
import json
from typing import Tuple

from zeroconf.asyncio import AsyncZeroconf, AsyncServiceBrowser
from zeroconf import ServiceInfo, ServiceListener, ServiceStateChange

import msgpack
# Imports Criptografía Asimétrica (ECC + RSA)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding # Para verificar DNIe
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509 # Para parsear certificados

# Imports Criptografía Simétrica y KDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class MessageType:
    HANDSHAKE_INIT = 1
    HANDSHAKE_RESPONSE = 2
    TEXT_MESSAGE = 3
    PING = 8
    PONG = 9
    DISCONNECT = 10

class NoiseIKProtocol:
    def __init__(self, static_private_key, dnie_manager):
        self.static_private = static_private_key
        self.static_public = static_private_key.public_key()
        self.dnie = dnie_manager
        self.sessions = {} 
        
    def initiate_handshake(self, remote_static_key_bytes: bytes, remote_fingerprint: str) -> Tuple[bytes, dict]:
        ephemeral_private = X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key()
        
        # Si es la primera vez (TOFU), asumimos una clave temporal, 
        # pero idealmente deberíamos tener la clave del peer guardada.
        if not remote_static_key_bytes:
             remote_static = X25519PrivateKey.generate().public_key() 
        else:
            remote_static = X25519PublicKey.from_public_bytes(remote_static_key_bytes)
        
        self.temp_ephemeral = ephemeral_private
        
        # Intercambio Diffie-Hellman (X25519)
        es = ephemeral_private.exchange(remote_static)
        ss = self.static_private.exchange(remote_static)
        
        session = self._derive_session(es, ss, remote_fingerprint, is_initiator=True)
        self.sessions[remote_fingerprint] = session
        
        ephemeral_bytes = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        static_bytes = self.static_public.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        
        # Firmamos nuestra clave estática con el DNIe
        signature = self.dnie.sign_data(static_bytes)
        
        handshake_message = {
            'ephemeral_public': ephemeral_bytes,
            'static_public': static_bytes,
            'dnie_fingerprint': self.dnie.get_fingerprint(),
            'dnie_signature': signature,
            # [CORRECCIÓN] Enviamos el certificado para que el otro pueda verificar
            'dnie_cert_data': self.dnie.get_certificate_der(), 
            'protocol_version': '1.0'
        }
        
        return msgpack.packb(handshake_message), session

    def accept_handshake(self, payload_dict):
        """
        [CORRECCIÓN CRÍTICA] Verifica la firma del DNIe del remitente
        """
        try:
            sender_static_bytes = payload_dict['static_public']
            sender_ephemeral_bytes = payload_dict['ephemeral_public']
            sender_fp = payload_dict['dnie_fingerprint']
            signature = payload_dict['dnie_signature']
            cert_data = payload_dict.get('dnie_cert_data')

            # 1. Verificar Firma Digital del DNIe (Autenticación Real)
            if not cert_data:
                print("⚠️ Handshake rechazado: Falta certificado DNIe")
                return False

            cert = x509.load_der_x509_certificate(cert_data)
            # Verificar que el fingerprint coincide con el certificado enviado
            computed_fp = hashlib.sha256(cert_data).hexdigest()
            if computed_fp != sender_fp:
                print("⚠️ Handshake rechazado: Fingerprint no coincide")
                return False

            # Verificar la firma RSA sobre la clave estática Noise
            public_key_rsa = cert.public_key()
            public_key_rsa.verify(
                signature,
                sender_static_bytes,
                rsa_padding.PKCS1v15(), # El DNIe usa PKCS#1 v1.5 habitualmente
                hashes.SHA256()
            )
            print(f"✅ Firma DNIe verificada para {sender_fp[:8]}")

            # 2. Continuar con criptografía Noise
            sender_static = X25519PublicKey.from_public_bytes(sender_static_bytes)
            sender_ephemeral = X25519PublicKey.from_public_bytes(sender_ephemeral_bytes)
            
            es = self.static_private.exchange(sender_ephemeral)
            ss = self.static_private.exchange(sender_static)
            
            session = self._derive_session(es, ss, sender_fp, is_initiator=False)
            self.sessions[sender_fp] = session
            return True

        except Exception as e:
            print(f"❌ Error crypto handshake: {e}")
            return False

    def update_session_with_peer_key(self, remote_static_bytes, remote_fingerprint):
        try:
            remote_static = X25519PublicKey.from_public_bytes(remote_static_bytes)
            es = self.temp_ephemeral.exchange(remote_static)
            ss = self.static_private.exchange(remote_static)
            session = self._derive_session(es, ss, remote_fingerprint, is_initiator=True)
            self.sessions[remote_fingerprint] = session
            return True
        except Exception as e:
            print(f"❌ Error actualizando sesión: {e}")
            return False

    def _derive_session(self, es, ss, fp, is_initiator: bool):
        # Derivación HKDF (Igual que tenías)
        hkdf = HKDF(
            algorithm=hashes.BLAKE2s(digest_size=32),
            length=64,
            salt=None,
            info=b'DNI-IM-v2',
        )
        key_material = hkdf.derive(es + ss)
        
        # --- CORRECCIÓN DE SIMETRÍA ---
        k1 = key_material[:32]
        k2 = key_material[32:64]
        
        if is_initiator:
            send_key = k1
            recv_key = k2
        else:
            # Si soy el que responde, cruzo las claves
            send_key = k2
            recv_key = k1
            
        return {
            'send_cipher': ChaCha20Poly1305(send_key),
            'recv_cipher': ChaCha20Poly1305(recv_key),
            'remote_fingerprint': fp,
            'established': True
        }
    
    def encrypt_message(self, plaintext: bytes, remote_fingerprint: str) -> bytes:
        session = self.sessions.get(remote_fingerprint)
        if not session: return plaintext
        try:
            nonce = os.urandom(12)
            ciphertext = session['send_cipher'].encrypt(nonce, plaintext, None)
            return nonce + ciphertext
        except: return plaintext

    def decrypt_message(self, ciphertext: bytes, remote_fingerprint: str) -> bytes:
        session = self.sessions.get(remote_fingerprint)
        if not session: return ciphertext
        try:
            nonce = ciphertext[:12]
            encrypted = ciphertext[12:]
            return session['recv_cipher'].decrypt(nonce, encrypted, None)
        except Exception as e: 
            raise e

# --- ConnectionManager y SimpleListener se mantienen igual que tu original ---
class ConnectionManager:
    # (Copiar código original de ConnectionManager aquí, no cambia)
    def __init__(self):
        self.connections = {}
        self.next_cid = 1
        self.cid_to_peer = {}
        self.peer_to_cid = {}
        
    def create_connection(self, peer_fingerprint: str, peer_info: dict) -> int:
        cid = self.next_cid
        self.next_cid += 1
        self.connections[cid] = {'peer_info': peer_info, 'streams': {}, 'next_stream_id': 1}
        self.cid_to_peer[cid] = peer_fingerprint
        self.peer_to_cid[peer_fingerprint] = cid
        return cid

    def get_cid_for_peer(self, fp): return self.peer_to_cid.get(fp)
    def get_peer_for_cid(self, cid): return self.cid_to_peer.get(cid)

    def create_stream(self, cid: int, stype: str) -> int:
        if cid not in self.connections: return 0
        conn = self.connections[cid]
        sid = conn['next_stream_id']
        conn['next_stream_id'] += 1
        return sid

    def create_packet(self, cid: int, sid: int, mtype: int, payload: bytes) -> bytes:
        header = struct.pack('!IIHH', cid, sid, mtype, len(payload))
        return header + payload

    def parse_packet(self, packet: bytes):
        if len(packet) < 12: raise ValueError("Packet too short")
        cid, sid, mtype, length = struct.unpack('!IIHH', packet[:12])
        return cid, sid, mtype, packet[12:12+length]

class SimpleListener(ServiceListener):
    def __init__(self, network):
        self.network = network
    
    def update_service(self, zc, type_, name): pass
    
    def remove_service(self, zc, type_, name):
        # AVISO DE DESCONEXIÓN
        print(f"DEBUG: Recibido evento REMOVE para {name}")
        # Limpiamos el nombre exactamente igual que al añadirlo
        clean_name = name.replace("." + type_, "")
        # Quitamos el punto final si ha quedado alguno (frecuente en mDNS)
        if clean_name.endswith('.'):
            clean_name = clean_name[:-1]
            
        self.network.remove_discovered_peer(clean_name)

    def add_service(self, zc, type_, name):
        asyncio.create_task(self.resolve_async(zc, type_, name))

    def __call__(self, zeroconf, service_type, name, state_change):
        if state_change == ServiceStateChange.Added:
            self.add_service(zeroconf, service_type, name)
        elif state_change == ServiceStateChange.Removed:
            self.remove_service(zeroconf, service_type, name)
    
    async def resolve_async(self, zc, type_, name):
        try:
            info = await zc.async_get_service_info(type_, name)
            if info:
                props = {k.decode('utf-8', 'ignore'): v.decode('utf-8', 'ignore') 
                         for k, v in info.properties.items()}
                
                clean_name = name.replace("." + type_, "")
                if clean_name.endswith('.'): clean_name = clean_name[:-1]

                peer_info = {
                    'name': props.get('real_name', clean_name),
                    'fingerprint': props.get('fingerprint', ''),
                    'ip': socket.inet_ntoa(info.addresses[0]),
                    'port': info.port,
                    'instance_name': clean_name
                }
                self.network.add_discovered_peer(peer_info)
        except: pass

class CompleteNetwork:
    def __init__(self, dnie_manager):
        self.dnie = dnie_manager
        self.connection_manager = ConnectionManager()
        self.noise = None
        self.udp_transport = None
        self.zeroconf = None 
        self.peers = {} 
        self.discovered = {}
        
        # [CORRECCIÓN] Cola de mensajes para entrega diferida (Postcards)
        self.message_queue = {} 

        self.contacts_file = "contacts.json"
        self.trusted_contacts = self._load_contacts()

        self.UDP_PORT = 6666
        self.SERVICE_TYPE = "_dni-im._udp.local."
        self.my_fingerprint = ""
        self.my_name = ""
    
    def _load_contacts(self):
        if os.path.exists(self.contacts_file):
            try:
                with open(self.contacts_file, 'r') as f:
                    return json.load(f)
            except: return {}
        return {}

    def _save_contacts(self):
        try:
            with open(self.contacts_file, 'w') as f:
                json.dump(self.trusted_contacts, f, indent=4)
        except: pass

    def _load_identity(self) -> X25519PrivateKey:
        # Se mantiene igual
        key_file = "identity.pem"
        if os.path.exists(key_file):
            with open(key_file, "rb") as f: return X25519PrivateKey.from_private_bytes(f.read())
        else:
            key = X25519PrivateKey.generate()
            with open(key_file, "wb") as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()))
            return key

    async def start(self, username: str):
        # Se mantiene igual
        self.my_name = username
        self.my_fingerprint = self.dnie.get_fingerprint()
        static_private = self._load_identity()
        self.noise = NoiseIKProtocol(static_private, self.dnie)
        
        loop = asyncio.get_event_loop()
        self.udp_transport, _ = await loop.create_datagram_endpoint(
            lambda: CompleteUDPProtocol(self),
            local_addr=('0.0.0.0', self.UDP_PORT)
        )
        await self._start_mdns()

    async def _start_mdns(self):
        # Se mantiene igual
        self.zeroconf = AsyncZeroconf()
        local_ip = self._get_local_ip()
        desc = {'fingerprint': self.my_fingerprint, 'real_name': self.my_name}
        service_name = f"User-{self.my_fingerprint[:6]}.{self.SERVICE_TYPE}"
        info = ServiceInfo(
            self.SERVICE_TYPE, service_name,
            addresses=[socket.inet_aton(local_ip)],
            port=self.UDP_PORT, properties=desc
        )
        await self.zeroconf.async_register_service(info)
        self.browser = AsyncServiceBrowser(self.zeroconf.zeroconf, self.SERVICE_TYPE, [SimpleListener(self)])

    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except: return "127.0.0.1"

    def add_discovered_peer(self, info):
        fp = info['fingerprint']
        if fp == self.my_fingerprint: return
        
        name = info['name']
        
        # --- LÓGICA TOFU (Trust On First Use) ---
        if fp in self.trusted_contacts:
            # Ya lo conocemos, actualizamos nombre si ha cambiado (opcional)
            stored_name = self.trusted_contacts[fp]['name']
            info['name'] = stored_name # Mantenemos el nombre que nosotros confiamos
        else:
            # ¿Es un nombre que ya conocemos pero con OTRA clave? (ALERTA DE SEGURIDAD)
            for trusted_fp, data in self.trusted_contacts.items():
                if data['name'] == name and trusted_fp != fp:
                    print(f"🚨 ALERTA: '{name}' ha cambiado de DNIe/Clave! Podría ser un ataque.")
                    info['name'] = f"{name} (NO VERIFICADO)"
            
            # Si es totalmente nuevo, lo guardamos (Trust First Use)
            if fp not in self.trusted_contacts:
                self.trusted_contacts[fp] = {'name': name, 'added': time.time()}
                self._save_contacts()
        # [CORRECCIÓN] Si el peer reaparece, intentamos enviar cola
        is_new = fp not in self.discovered
        self.discovered[fp] = info
        
        if is_new or fp in self.message_queue:
            asyncio.create_task(self._flush_message_queue(fp))

    def remove_discovered_peer(self, instance_name):
        fp_to_remove = None
        
        # Buscamos coincidencias (exactas o parciales)
        for fp, info in self.discovered.items():
            stored_name = info.get('instance_name', '')
            # Comparamos ignorando mayúsculas y posibles puntos finales
            if stored_name.strip('.') == instance_name.strip('.'):
                fp_to_remove = fp
                break
        
        if fp_to_remove:
            # Borramos de la lista de ONLINE
            del self.discovered[fp_to_remove]
            # Si estamos usando interfaz gráfica, esto disparará el update_ui
            # en el archivo interface.py, y como ya no está en 'discovered',
            # get_peers() lo cogerá del JSON y le pondrá el (OFF).
            print(f"📉 Peer pasado a OFFLINE: {fp_to_remove[:8]}")

    # [NUEVO] Método para procesar cola de mensajes (Postcards)
    async def _flush_message_queue(self, fp):
        if fp in self.message_queue and self.message_queue[fp]:
            print(f"📬 Entregando mensajes en cola a {fp[:8]}...")
            peer_info = self.discovered.get(fp)
            if not peer_info: return
            
            # Copiar cola y vaciar original
            pending = self.message_queue[fp][:]
            self.message_queue[fp] = []
            
            for txt in pending:
                await self.send_message(fp, txt)
                await asyncio.sleep(0.1)

    def get_peers(self):
        # 1. Cogemos a los que están ONLINE (detectados ahora mismo)
        all_peers = list(self.discovered.values())
        online_fps = {p['fingerprint'] for p in all_peers}

        # 2. Añadimos a los de la AGENDA (contacts.json) si no están online
        if hasattr(self, 'trusted_contacts'):
            for fp, info in self.trusted_contacts.items():
                if fp not in online_fps:
                    # Creamos un "peer fantasma" para que salga en la lista
                    # Le ponemos (OFF) en el nombre para que sepas que no está conectado
                    clean_name = info['name'].replace("(AUTENTICACIÓN)", "").strip()
                    offline_peer = {
                        'fingerprint': fp,
                        'name': f"{clean_name} (OFF)", 
                        'ip': 'Offline',
                        'port': 0,
                        'instance_name': 'offline'
                    }
                    all_peers.append(offline_peer)
        
        return all_peers
    
    def _get_clean_name(self, fp):
        peer = self.discovered.get(fp)
        raw_name = peer.get('name', fp[:8]) if peer else fp[:8]
        return raw_name.replace("(AUTENTICACIÓN)", "").replace("(FIRMA)", "").strip()

    async def send_message(self, target_name_or_fp, text):
        # 1. Intentar encontrar al usuario en la lista de ONLINE (discovered)
        peer_info = self.discovered.get(target_name_or_fp)
        target_fp = target_name_or_fp
        
        # Si nos han pasado un nombre en vez de un fingerprint, lo buscamos
        if not peer_info:
             target_lower = target_name_or_fp.lower()
             for fp, p in self.discovered.items():
                 # Buscamos por nombre o por nombre de instancia
                 p_name = p.get('name', '').lower()
                 p_inst = p.get('instance_name', '').lower()
                 if target_lower in p_name or target_lower in p_inst:
                     peer_info = p
                     target_fp = fp
                     break
        
        # Si no lo encontramos en ONLINE, miramos si es un contacto de la AGENDA
        if not peer_info and hasattr(self, 'trusted_contacts'):
             if target_fp in self.trusted_contacts:
                 # Es un contacto conocido, pero está OFFLINE
                 pass # peer_info sigue siendo None, lo manejaremos abajo
             else:
                 # Quizás el user pasó un nombre de la agenda
                 for fp, info in self.trusted_contacts.items():
                     if info['name'].lower() == target_name_or_fp.lower():
                         target_fp = fp
                         break

        # 2. LOGICA OFFLINE / POSTCARDS
        # Si peer_info es None, o la IP es "Offline" (del apaño anterior), ENCOLAMOS
        is_offline = (peer_info is None) or (peer_info.get('ip') == 'Offline')

        if is_offline:
            print(f"💤 Usuario offline. Mensaje encolado para {target_fp[:8]}")
            
            # Guardamos en la cola de memoria
            if target_fp not in self.message_queue:
                self.message_queue[target_fp] = []
            
            self.message_queue[target_fp].append(text)
            
            # Devolvemos True para que la Interfaz Gráfica muestre el mensaje
            # como si se hubiera enviado (aunque se entregará luego)
            return True 

        # 3. LOGICA ONLINE (Solo llegamos aquí si tenemos IP y Puerto)
        try:
            cid = self.connection_manager.get_cid_for_peer(target_fp)
            if not cid:
                cid = self.connection_manager.create_connection(target_fp, peer_info)
                await self._send_handshake(cid, peer_info)
                # Pequeña espera para handshake
                await asyncio.sleep(0.2)
                
            sid = self.connection_manager.create_stream(cid, 'text')
            msg_bytes = msgpack.packb({'text': text, 'ts': time.time()})
            encrypted = self.noise.encrypt_message(msg_bytes, target_fp)
            
            pkt = self.connection_manager.create_packet(cid, sid, MessageType.TEXT_MESSAGE, encrypted)
            self.udp_transport.sendto(pkt, (peer_info['ip'], peer_info['port']))
            return True
        except Exception as e:
            print(f"❌ Error enviando UDP: {e}")
            return False

    async def _send_handshake(self, cid, peer_info):
        data, session = self.noise.initiate_handshake(None, peer_info['fingerprint'])
        sid = self.connection_manager.create_stream(cid, 'handshake')
        pkt = self.connection_manager.create_packet(cid, sid, MessageType.HANDSHAKE_INIT, data)
        self.udp_transport.sendto(pkt, (peer_info['ip'], peer_info['port']))

    def handle_packet(self, data, addr):
        try:
            cid, sid, mtype, payload = self.connection_manager.parse_packet(data)
            peer_fp = self.connection_manager.get_peer_for_cid(cid)
            
            if mtype == MessageType.HANDSHAKE_INIT:
                self._handle_handshake_init(cid, payload, addr)
            elif mtype == MessageType.HANDSHAKE_RESPONSE:
                self._handle_handshake_response(payload, peer_fp)
            elif mtype == MessageType.TEXT_MESSAGE and peer_fp:
                self._handle_text(payload, peer_fp)
            elif mtype == MessageType.DISCONNECT and peer_fp:
                print(f"🔌 Recibida señal de desconexión de {peer_fp[:8]}")
                self._handle_disconnect(peer_fp)
        except Exception as e: print(f"Packet Error: {e}")

    def _handle_handshake_init(self, cid, payload, addr):
        try:
            content = msgpack.unpackb(payload, raw=False)
            remote_fp = content.get('dnie_fingerprint')
            
            # [CORRECCIÓN] Pasamos el contenido completo al noise para validar firma
            if self.noise.accept_handshake(content):
                print(f"🔒 Sesión segura establecida con {self._get_clean_name(remote_fp)}")
                
                if not self.connection_manager.get_cid_for_peer(remote_fp):
                    self.connection_manager.create_connection(remote_fp, {'ip': addr[0], 'port': addr[1]})
                
                my_static = self.noise.static_public.public_bytes(
                    encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
                
                ack_payload = msgpack.packb({'ack': True, 'static_public': my_static})
                pkt = self.connection_manager.create_packet(cid, 0, MessageType.HANDSHAKE_RESPONSE, ack_payload)
                self.udp_transport.sendto(pkt, addr)
            else:
                print("⛔ Handshake fallido: Firma inválida o error crypto")

        except Exception as e:
            print(f"❌ Error procesando handshake: {e}")

    def _handle_handshake_response(self, payload, remote_fp):
        # Se mantiene (casi) igual
        try:
            content = msgpack.unpackb(payload, raw=False)
            if content.get('ack') and remote_fp:
                remote_static = content.get('static_public')
                if remote_static:
                    if self.noise.update_session_with_peer_key(remote_static, remote_fp):
                         print(f"✅ Handshake COMPLETADO con {self._get_clean_name(remote_fp)}")
                         # Intentar vaciar cola si había mensajes pendientes
                         asyncio.create_task(self._flush_message_queue(remote_fp))
        except Exception as e:
            print(f"❌ Error respuesta handshake: {e}")

    def _handle_text(self, payload, remote_fp):
        # Se mantiene igual
        try:
            decrypted = self.noise.decrypt_message(payload, remote_fp)
            data = msgpack.unpackb(decrypted, raw=False)
            print(f"\n📨 MENSAJE de {self._get_clean_name(remote_fp)}: {data.get('text')}")
        except: 
            print("\n❌ Error desencriptando mensaje")
    
    def _handle_disconnect(self, remote_fp):
        """
        Se llama cuando recibimos un paquete explícito de desconexión.
        Fuerza la eliminación del peer de la lista de descubiertos.
        """
        peer_info = self.discovered.get(remote_fp)
        if peer_info:
            # Obtenemos el instance_name para usar el método estándar de borrado
            instance_name = peer_info.get('instance_name')
            if instance_name:
                self.remove_discovered_peer(instance_name)
            else:
                # Fallback por si no tiene instance_name, lo borramos a mano
                del self.discovered[remote_fp]

    async def broadcast_goodbye(self):
        print("👋 Enviando señales de desconexión (x3)...")
        active_peers = list(self.discovered.values())
        
        for peer in active_peers:
            fp = peer['fingerprint']
            cid = self.connection_manager.get_cid_for_peer(fp)
            if cid:
                try:
                    # Enviar 3 veces para asegurar llegada (UDP no garantiza entrega)
                    for _ in range(3):
                        payload = msgpack.packb({'bye': True})
                        encrypted = self.noise.encrypt_message(payload, fp)
                        pkt = self.connection_manager.create_packet(cid, 0, MessageType.DISCONNECT, encrypted)
                        self.udp_transport.sendto(pkt, (peer['ip'], peer['port']))
                except Exception as e:
                    print(f"Error bye a {fp[:8]}: {e}")
    def force_disconnect_peer(self, fp):
        """
        Borra un peer directamente usando su Fingerprint.
        Este método será sobreescrito en interface.py para actualizar la UI.
        """
        if fp in self.discovered:
            del self.discovered[fp]
            print(f"📉 Peer eliminado de la lista interna: {fp[:8]}")
        
    async def stop(self):
        # Primero enviamos el adiós
        await self.broadcast_goodbye()
        # Pequeña pausa para asegurar que los paquetes UDP salgan
        await asyncio.sleep(0.2)
        
        if self.udp_transport: self.udp_transport.close()
        if self.zeroconf: await self.zeroconf.async_close()

class CompleteUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, net): self.net = net
    def datagram_received(self, data, addr): self.net.handle_packet(data, addr)