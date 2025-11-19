"""
Red P2P Completa - VERSION 3.0 (ROBUSTA)
"""
import asyncio
import socket
import time
import struct
import hashlib
import os
from typing import Tuple

# Zeroconf
from zeroconf import ServiceInfo, ServiceStateChange
from zeroconf.asyncio import AsyncZeroconf, AsyncServiceBrowser

import msgpack
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization

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
        es = ephemeral_private.exchange(remote_static)
        ss = self.static_private.exchange(remote_static)
        h = hashlib.blake2s(digest_size=64)
        h.update(b"DNI-IM-NoiseIK-v1")
        h.update(es)
        h.update(ss)
        key_material = h.digest()
        session = {
            'send_cipher': ChaCha20Poly1305(key_material[:32]),
            'recv_cipher': ChaCha20Poly1305(key_material[32:64]),
            'send_nonce': 0,
            'recv_nonce': 0,
            'remote_fingerprint': remote_fingerprint,
            'established': True
        }
        self.sessions[remote_fingerprint] = session
        ephemeral_bytes = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        static_bytes = self.static_public.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        signature = self.dnie.sign_data(static_bytes)
        handshake_message = {
            'ephemeral_public': ephemeral_bytes,
            'static_public': static_bytes,
            'dnie_fingerprint': self.dnie.get_fingerprint(),
            'dnie_signature': signature,
            'protocol_version': '1.0'
        }
        return msgpack.packb(handshake_message), session

    def process_handshake_response(self, response_data: bytes, remote_fingerprint: str) -> bool:
        try:
            response = msgpack.unpackb(response_data, raw=False)
            if response.get('ack'):
                session = self.sessions.get(remote_fingerprint)
                if session:
                    session['handshake_complete'] = True
                    return True
            return False
        except: return False

    def encrypt_message(self, plaintext: bytes, remote_fingerprint: str) -> bytes:
        session = self.sessions.get(remote_fingerprint)
        if not session: return plaintext
        try:
            nonce = session['send_nonce'].to_bytes(12, 'little')
            session['send_nonce'] += 1
            return nonce + session['send_cipher'].encrypt(nonce, plaintext, None)
        except: return plaintext

    def decrypt_message(self, ciphertext: bytes, remote_fingerprint: str) -> bytes:
        session = self.sessions.get(remote_fingerprint)
        if not session: return ciphertext
        try:
            nonce = ciphertext[:12]
            encrypted = ciphertext[12:]
            return session['recv_cipher'].decrypt(nonce, encrypted, None)
        except: return b"Error_Decrypt"

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

class SimpleListener:
    def __init__(self, network):
        self.network = network

    def __call__(self, zeroconf, service_type, name, state_change):
        if state_change is ServiceStateChange.Added:
            asyncio.create_task(self.resolve_async(zeroconf, service_type, name))
        elif state_change is ServiceStateChange.Removed:
            self.remove_service(zeroconf, service_type, name)
        elif state_change is ServiceStateChange.Updated:
            self.update_service(zeroconf, service_type, name)

    async def resolve_async(self, zeroconf, service_type, name):
        try:
            info = await zeroconf.async_get_service_info(service_type, name)
            if info:
                props = {k.decode('utf-8', 'ignore'): v.decode('utf-8', 'ignore')
                         for k, v in info.properties.items()}
                clean_name = name.replace("." + service_type, "")
                peer_info = {
                    'name': props.get('real_name', clean_name),
                    'fingerprint': props.get('fingerprint', ''),
                    'ip': socket.inet_ntoa(info.addresses[0]),
                    'port': info.port
                }
                self.network.add_discovered_peer(peer_info)
        except Exception as e:
            print(f"Error mDNS: {e}")

    def remove_service(self, zeroconf, service_type, name):
        print(f"Servicio eliminado: {name}")

    def update_service(self, zeroconf, service_type, name):
        print(f"Servicio actualizado: {name}")

class CompleteNetwork:
    def __init__(self, dnie_manager):
        self.dnie = dnie_manager
        self.connection_manager = ConnectionManager()
        self.noise = None
        self.udp_transport = None
        self.zeroconf = None 
        self.peers = {} 
        self.discovered = {}
        self.contact_book = {}
        self.UDP_PORT = 6666
        self.SERVICE_TYPE = "_dni-im._udp.local."
        self.my_fingerprint = ""
        self.my_name = ""

    def _load_identity(self) -> X25519PrivateKey:
        key_file = "identity.pem"
        if os.path.exists(key_file):
            with open(key_file, "rb") as f: return X25519PrivateKey.from_private_bytes(f.read())
        else:
            print("🆕 Generando NUEVA identidad de red...")
            key = X25519PrivateKey.generate()
            with open(key_file, "wb") as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()))
            return key

    async def start(self, username: str):
        print(f"🚀 Iniciando Red P2P (Version 3.0)...")
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
        print(f"✅ Red lista en puerto {self.UDP_PORT}")

    async def _start_mdns(self):
        self.zeroconf = AsyncZeroconf()
        local_ip = self._get_local_ip()
        desc = {
            'fingerprint': self.my_fingerprint,
            'real_name': self.my_name,
            'version': '2.0'
        }
        service_name = f"User-{self.my_fingerprint[:6]}.{self.SERVICE_TYPE}"
        info = ServiceInfo(
            self.SERVICE_TYPE, service_name,
            addresses=[socket.inet_aton(local_ip)],
            port=self.UDP_PORT,
            properties=desc
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
        if fp not in self.discovered:
            print(f"🔍 Peer descubierto: {info['name']} ({info['ip']})")
            self.discovered[fp] = info

    def get_peers(self): return list(self.discovered.values())
    def get_network_stats(self):
        return {'peers': len(self.discovered), 'my_fp': self.my_fingerprint}

    async def send_message(self, target_fp, text):
        peer_info = self.discovered.get(target_fp)
        if not peer_info:
            for p in self.discovered.values():
                if p['name'] == target_fp:
                    peer_info = p
                    target_fp = p['fingerprint']
                    break
        if not peer_info:
            print("❌ Peer no encontrado")
            return False
        if target_fp not in self.contact_book:
            self.contact_book[target_fp] = peer_info
        cid = self.connection_manager.get_cid_for_peer(target_fp)
        if not cid:
            cid = self.connection_manager.create_connection(target_fp, peer_info)
            await self._send_handshake(cid, peer_info)
        sid = self.connection_manager.create_stream(cid, 'text')
        msg_bytes = msgpack.packb({'text': text, 'ts': time.time()})
        encrypted = self.noise.encrypt_message(msg_bytes, target_fp)
        pkt = self.connection_manager.create_packet(cid, sid, MessageType.TEXT_MESSAGE, encrypted)
        self.udp_transport.sendto(pkt, (peer_info['ip'], peer_info['port']))
        return True

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
            elif mtype == MessageType.TEXT_MESSAGE and peer_fp:
                self._handle_text(payload, peer_fp)
        except: pass

    def _handle_handshake_init(self, cid, payload, addr):
        try:
            content = msgpack.unpackb(payload, raw=False)
            remote_fp = content.get('dnie_fingerprint')
            print(f"🤝 Handshake recibido de {remote_fp[:8]}...")
            if not self.connection_manager.get_cid_for_peer(remote_fp):
                self.connection_manager.create_connection(remote_fp, {'ip': addr[0], 'port': addr[1]})
            ack = msgpack.packb({'ack': True})
            pkt = self.connection_manager.create_packet(cid, 0, MessageType.HANDSHAKE_RESPONSE, ack)
            self.udp_transport.sendto(pkt, addr)
        except: pass

    def _handle_text(self, payload, remote_fp):
        try:
            decrypted = self.noise.decrypt_message(payload, remote_fp)
            data = msgpack.unpackb(decrypted, raw=False)
            print(f"\n📨 MENSAJE: {data.get('text')}")
        except: pass

    async def stop(self):
        if self.udp_transport: self.udp_transport.close()
        if self.zeroconf: await self.zeroconf.async_close()

class CompleteUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, net): self.net = net
    def datagram_received(self, data, addr): self.net.handle_packet(data, addr)

