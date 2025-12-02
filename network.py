"""
Red P2P Completa 
Cumple requisitos: BLAKE2s, Verificación Firma DNIe, Cola Offline, TOFU Seguro (Real Name Bidireccional)
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
# Imports Criptografía
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding 
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509 
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class MessageType:
    HANDSHAKE_INIT = 1
    HANDSHAKE_RESPONSE = 2
    TEXT_MESSAGE = 3
    PING = 8
    PONG = 9

class NoiseIKProtocol:
    def __init__(self, static_private_key, dnie_manager):
        self.static_private = static_private_key
        self.static_public = static_private_key.public_key()
        self.dnie = dnie_manager
        self.sessions = {} 
        
    def initiate_handshake(self, remote_static_key_bytes: bytes, remote_fingerprint: str) -> Tuple[bytes, dict]:
        ephemeral_private = X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key()
        
        if not remote_static_key_bytes:
             remote_static = X25519PrivateKey.generate().public_key() 
        else:
            remote_static = X25519PublicKey.from_public_bytes(remote_static_key_bytes)
        
        self.temp_ephemeral = ephemeral_private
        
        es = ephemeral_private.exchange(remote_static)
        ss = self.static_private.exchange(remote_static)
        
        session = self._derive_session(es, ss, remote_fingerprint, is_initiator=True)
        self.sessions[remote_fingerprint] = session
        
        ephemeral_bytes = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        static_bytes = self.static_public.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        
        # Firmar nuestra clave estática con DNIe
        signature = self.dnie.sign_data(static_bytes)
        
        handshake_message = {
            'ephemeral_public': ephemeral_bytes,
            'static_public': static_bytes,
            'dnie_fingerprint': self.dnie.get_fingerprint(),
            'dnie_signature': signature,
            'dnie_cert_data': self.dnie.get_certificate_der(), 
            'protocol_version': '1.0'
        }
        
        return msgpack.packb(handshake_message), session

    def verify_identity(self, static_bytes, cert_data, signature, fingerprint):
        """
        Función auxiliar para verificar DNIe y extraer nombre.
        Se usa tanto en Handshake Init como en Response.
        """
        try:
            if not cert_data: return None
            
            # 1. Verificar Fingerprint
            computed_fp = hashlib.sha256(cert_data).hexdigest()
            if computed_fp != fingerprint:
                print("⚠️ Fingerprint no coincide con certificado")
                return None

            # 2. Verificar Firma RSA
            cert = x509.load_der_x509_certificate(cert_data)
            public_key_rsa = cert.public_key()
            public_key_rsa.verify(
                signature,
                static_bytes,
                rsa_padding.PKCS1v15(), 
                hashes.SHA256()
            )

            # 3. Extraer Nombre Real (CN)
            subject = cert.subject
            real_name = "Desconocido"
            for attr in subject:
                if attr.oid == x509.NameOID.COMMON_NAME:
                    real_name = attr.value
                    break
            
            return real_name
        except Exception as e:
            print(f"❌ Error verificando identidad: {e}")
            return None

    def accept_handshake(self, payload_dict):
        """Procesa el mensaje inicial de handshake (INIT)"""
        try:
            sender_static_bytes = payload_dict['static_public']
            sender_ephemeral_bytes = payload_dict['ephemeral_public']
            sender_fp = payload_dict['dnie_fingerprint']
            
            # --- VERIFICACIÓN DE IDENTIDAD ---
            real_name = self.verify_identity(
                sender_static_bytes, 
                payload_dict.get('dnie_cert_data'), 
                payload_dict.get('dnie_signature'),
                sender_fp
            )
            
            if not real_name:
                print("⛔ Firma inválida en Handshake Init")
                return None

            print(f"✅ Firma DNIe (Init) verificada. Real: {real_name}")

            # --- CRYPTO NOISE ---
            sender_static = X25519PublicKey.from_public_bytes(sender_static_bytes)
            sender_ephemeral = X25519PublicKey.from_public_bytes(sender_ephemeral_bytes)
            
            es = self.static_private.exchange(sender_ephemeral)
            ss = self.static_private.exchange(sender_static)
            
            session = self._derive_session(es, ss, sender_fp, is_initiator=False)
            self.sessions[sender_fp] = session
            
            return real_name

        except Exception as e:
            print(f"❌ Error crypto handshake: {e}")
            return None

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
        hkdf = HKDF(
            algorithm=hashes.BLAKE2s(digest_size=32),
            length=64,
            salt=None,
            info=b'DNI-IM-v2',
        )
        key_material = hkdf.derive(es + ss)
        k1 = key_material[:32]
        k2 = key_material[32:64]
        
        if is_initiator:
            send_key = k1
            recv_key = k2
        else:
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

# --- ConnectionManager y SimpleListener ---
class ConnectionManager:
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
        asyncio.get_event_loop().call_soon_threadsafe(
            self.network.remove_discovered_peer, name
        )

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
        self.discovered = {}
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

    def _update_contact_real_name(self, fp, real_name):
        """Guarda o actualiza el nombre real en el JSON"""
        if fp not in self.trusted_contacts:
            self.trusted_contacts[fp] = {
                'name': real_name, 
                'added': time.time(),
                'dnie_real_name': real_name
            }
        else:
            self.trusted_contacts[fp]['dnie_real_name'] = real_name
        self._save_contacts()

    def _load_identity(self) -> X25519PrivateKey:
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
        if fp in self.trusted_contacts:
            stored_name = self.trusted_contacts[fp]['name']
            info['name'] = stored_name 
        else:
            for trusted_fp, data in self.trusted_contacts.items():
                if data['name'] == name and trusted_fp != fp:
                    print(f"🚨 ALERTA: '{name}' ha cambiado de DNIe/Clave!")
                    info['name'] = f"{name} (NO VERIFICADO)"
            
            if fp not in self.trusted_contacts:
                self.trusted_contacts[fp] = {'name': name, 'added': time.time()}
                self._save_contacts()
                
        is_new = fp not in self.discovered
        self.discovered[fp] = info
        
        if is_new or fp in self.message_queue:
            asyncio.create_task(self._flush_message_queue(fp))

    async def _flush_message_queue(self, fp):
        if fp in self.message_queue and self.message_queue[fp]:
            print(f"📬 Entregando mensajes en cola a {fp[:8]}...")
            peer_info = self.discovered.get(fp)
            if not peer_info: return
            
            pending = self.message_queue[fp][:]
            self.message_queue[fp] = []
            
            for txt in pending:
                await self.send_message(fp, txt)
                await asyncio.sleep(0.1)

    def get_peers(self):
        all_peers = list(self.discovered.values())
        online_fps = {p['fingerprint'] for p in all_peers}

        if hasattr(self, 'trusted_contacts'):
            for fp, info in self.trusted_contacts.items():
                if fp not in online_fps:
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
        if fp in self.trusted_contacts and 'dnie_real_name' in self.trusted_contacts[fp]:
             return self.trusted_contacts[fp]['dnie_real_name']
        peer = self.discovered.get(fp)
        raw_name = peer.get('name', fp[:8]) if peer else fp[:8]
        return raw_name.replace("(AUTENTICACIÓN)", "").replace("(FIRMA)", "").strip()

    async def send_message(self, target_name_or_fp, text):
        peer_info = self.discovered.get(target_name_or_fp)
        target_fp = target_name_or_fp
        
        if not peer_info:
             target_lower = target_name_or_fp.lower()
             for fp, p in self.discovered.items():
                 p_name = p.get('name', '').lower()
                 p_inst = p.get('instance_name', '').lower()
                 if target_lower in p_name or target_lower in p_inst:
                     peer_info = p
                     target_fp = fp
                     break
        
        if not peer_info and hasattr(self, 'trusted_contacts'):
             if target_fp in self.trusted_contacts:
                 pass 
             else:
                 for fp, info in self.trusted_contacts.items():
                     if info['name'].lower() == target_name_or_fp.lower():
                         target_fp = fp
                         break

        is_offline = (peer_info is None) or (peer_info.get('ip') == 'Offline')

        if is_offline:
            print(f"💤 Usuario offline. Mensaje encolado para {target_fp[:8]}")
            if target_fp not in self.message_queue:
                self.message_queue[target_fp] = []
            self.message_queue[target_fp].append(text)
            return True 

        try:
            cid = self.connection_manager.get_cid_for_peer(target_fp)
            if not cid:
                cid = self.connection_manager.create_connection(target_fp, peer_info)
                await self._send_handshake(cid, peer_info)
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
        except Exception as e: print(f"Packet Error: {e}")

    def _handle_handshake_init(self, cid, payload, addr):
        try:
            content = msgpack.unpackb(payload, raw=False)
            remote_fp = content.get('dnie_fingerprint')
            
            # 1. Verificar firma del que inicia y obtener nombre
            real_name_dnie = self.noise.accept_handshake(content)
            
            if real_name_dnie:
                print(f"🔒 Sesión segura con {real_name_dnie} (Init Recibido)")
                
                # GUARDAR NOMBRE (Como Receptor)
                self._update_contact_real_name(remote_fp, real_name_dnie)

                if not self.connection_manager.get_cid_for_peer(remote_fp):
                    self.connection_manager.create_connection(remote_fp, {'ip': addr[0], 'port': addr[1]})
                
                # 2. Preparar Respuesta (ACK) incluyendo MI CERTIFICADO
                my_static = self.noise.static_public.public_bytes(
                    encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
                
                # Firmar mi clave estática también para enviársela de vuelta
                my_sig = self.dnie.sign_data(my_static)

                ack_payload = msgpack.packb({
                    'ack': True, 
                    'static_public': my_static,
                    'dnie_cert_data': self.dnie.get_certificate_der(), # ENVIO MI CERT
                    'dnie_signature': my_sig, # ENVIO MI FIRMA
                    'dnie_fingerprint': self.dnie.get_fingerprint()
                })

                pkt = self.connection_manager.create_packet(cid, 0, MessageType.HANDSHAKE_RESPONSE, ack_payload)
                self.udp_transport.sendto(pkt, addr)
            else:
                print("⛔ Handshake fallido: Firma inválida")

        except Exception as e:
            print(f"❌ Error procesando handshake: {e}")

    def _handle_handshake_response(self, payload, remote_fp):
        try:
            content = msgpack.unpackb(payload, raw=False)
            if content.get('ack') and remote_fp:
                remote_static = content.get('static_public')
                
                # --- NUEVO: Verificar también la respuesta (Bidireccional) ---
                cert_data = content.get('dnie_cert_data')
                signature = content.get('dnie_signature')
                
                if cert_data and signature and remote_static:
                    real_name_resp = self.noise.verify_identity(remote_static, cert_data, signature, remote_fp)
                    if real_name_resp:
                        print(f"✅ Identidad del Peer (Resp) verificada: {real_name_resp}")
                        # GUARDAR NOMBRE (Como Iniciador)
                        self._update_contact_real_name(remote_fp, real_name_resp)
                    else:
                        print("⚠️ Respuesta de handshake con firma inválida")
                # -------------------------------------------------------------

                if remote_static:
                    if self.noise.update_session_with_peer_key(remote_static, remote_fp):
                         print(f"✅ Handshake COMPLETADO con {self._get_clean_name(remote_fp)}")
                         asyncio.create_task(self._flush_message_queue(remote_fp))
        except Exception as e:
            print(f"❌ Error respuesta handshake: {e}")

    def _handle_text(self, payload, remote_fp):
        try:
            decrypted = self.noise.decrypt_message(payload, remote_fp)
            data = msgpack.unpackb(decrypted, raw=False)
            print(f"\n📨 MENSAJE de {self._get_clean_name(remote_fp)}: {data.get('text')}")
        except: 
            print("\n❌ Error desencriptando mensaje")
    
    def remove_discovered_peer(self, service_name):
        fingerprint_to_remove = None
        for fp, info in self.discovered.items():
            if info['instance_name'] in service_name:
                fingerprint_to_remove = fp
                break
        
        if fingerprint_to_remove:
            print(f"📉 Peer desconectado detectado: {fingerprint_to_remove[:8]}")
            del self.discovered[fingerprint_to_remove]
        
    async def stop(self):
        if self.udp_transport: self.udp_transport.close()
        if self.zeroconf: await self.zeroconf.async_close()

class CompleteUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, net): self.net = net
    def datagram_received(self, data, addr): self.net.handle_packet(data, addr)