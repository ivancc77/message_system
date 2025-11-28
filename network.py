import asyncio
import socket
import time
import struct
import hashlib
import os
import json
import msgpack
from zeroconf.asyncio import AsyncZeroconf, AsyncServiceBrowser
from zeroconf import ServiceInfo, ServiceListener, ServiceStateChange

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

class NoiseIKProtocol:
    def __init__(self, static_private_key, dnie_manager):
        self.static_private = static_private_key
        self.static_public = static_private_key.public_key()
        self.dnie = dnie_manager
        self.sessions = {} 

    def initiate_handshake(self, remote_static_key_bytes, remote_fingerprint):
        ephemeral_private = X25519PrivateKey.generate()
        remote_static = X25519PublicKey.from_public_bytes(remote_static_key_bytes) if remote_static_key_bytes else X25519PrivateKey.generate().public_key()
        
        self.temp_ephemeral = ephemeral_private
        es = ephemeral_private.exchange(remote_static)
        ss = self.static_private.exchange(remote_static)
        session = self._derive_session(es, ss, remote_fingerprint, True)
        self.sessions[remote_fingerprint] = session
        
        # Payload
        static_bytes = self.static_public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        msg = {
            'ephemeral_public': ephemeral_private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
            'static_public': static_bytes,
            'dnie_fingerprint': self.dnie.get_fingerprint(),
            'dnie_signature': self.dnie.sign_data(static_bytes),
            'dnie_cert_data': self.dnie.get_certificate_der()
        }
        return msgpack.packb(msg), session

    def accept_handshake(self, payload):
        try:
            cert = x509.load_der_x509_certificate(payload['dnie_cert_data'])
            if hashlib.sha256(payload['dnie_cert_data']).hexdigest() != payload['dnie_fingerprint']: return False
            
            cert.public_key().verify(payload['dnie_signature'], payload['static_public'], rsa_padding.PKCS1v15(), hashes.SHA256())
            
            sender_ephemeral = X25519PublicKey.from_public_bytes(payload['ephemeral_public'])
            sender_static = X25519PublicKey.from_public_bytes(payload['static_public'])
            
            es = self.static_private.exchange(sender_ephemeral)
            ss = self.static_private.exchange(sender_static)
            self.sessions[payload['dnie_fingerprint']] = self._derive_session(es, ss, payload['dnie_fingerprint'], False)
            return True
        except: return False

    def update_session_with_peer_key(self, remote_static_bytes, fp):
        try:
            remote = X25519PublicKey.from_public_bytes(remote_static_bytes)
            es = self.temp_ephemeral.exchange(remote)
            ss = self.static_private.exchange(remote)
            self.sessions[fp] = self._derive_session(es, ss, fp, True)
            return True
        except: return False

    def _derive_session(self, es, ss, fp, is_initiator):
        km = HKDF(hashes.BLAKE2s(32), 64, None, b'DNI-IM-v2').derive(es + ss)
        return {'send': ChaCha20Poly1305(km[:32] if is_initiator else km[32:]), 
                'recv': ChaCha20Poly1305(km[32:] if is_initiator else km[:32])}

    def encrypt_message(self, plaintext, fp):
        sess = self.sessions.get(fp)
        if not sess: return plaintext
        nonce = os.urandom(12)
        return nonce + sess['send'].encrypt(nonce, plaintext, None)

    def decrypt_message(self, ciphertext, fp):
        sess = self.sessions.get(fp)
        return sess['recv'].decrypt(ciphertext[:12], ciphertext[12:], None) if sess else ciphertext

class ConnectionManager:
    def __init__(self):
        self.connections = {}
        self.next_cid = 1
        self.cid_map = {} # cid -> fp

    def get_cid(self, fp): return next((k for k,v in self.cid_map.items() if v == fp), None)
    
    def create_connection(self, fp, info):
        cid = self.next_cid
        self.next_cid += 1
        self.connections[cid] = {'info': info, 'next_sid': 1}
        self.cid_map[cid] = fp
        return cid

    def create_packet(self, cid, sid, mtype, payload):
        return struct.pack('!IIHH', cid, sid, mtype, len(payload)) + payload

    def parse_packet(self, data):
        if len(data) < 12: raise ValueError
        cid, sid, mtype, length = struct.unpack('!IIHH', data[:12])
        return cid, sid, mtype, data[12:12+length]

class SimpleListener(ServiceListener):
    def __init__(self, net): self.net = net
    def update_service(self, zc, type_, name): pass
    def remove_service(self, zc, type_, name):
        asyncio.get_event_loop().call_soon_threadsafe(self.net.remove_discovered_peer, name)
    def add_service(self, zc, type_, name):
        asyncio.create_task(self._resolve(zc, type_, name))
        
    async def _resolve(self, zc, type_, name):
        info = await zc.async_get_service_info(type_, name)
        if info:
            props = {k.decode(): v.decode() for k,v in info.properties.items()}
            self.net.add_discovered_peer({
                'name': props.get('real_name', name), 'fingerprint': props.get('fingerprint'),
                'ip': socket.inet_ntoa(info.addresses[0]), 'port': info.port, 'instance_name': name.replace("."+type_, "")
            })

class CompleteNetwork:
    def __init__(self, dnie):
        self.dnie = dnie
        self.conn_mgr = ConnectionManager()
        self.discovered = {}
        self.msg_queue = {}
        self.trusted = self._load_contacts()
        self.UDP_PORT = 6666

    def _load_contacts(self):
        try: return json.load(open("contacts.json"))
        except: return {}

    async def start(self, username):
        key_file = "identity.pem"
        if not os.path.exists(key_file):
            with open(key_file, "wb") as f: 
                f.write(X25519PrivateKey.generate().private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
        
        with open(key_file, "rb") as f: self.noise = NoiseIKProtocol(X25519PrivateKey.from_private_bytes(f.read()), self.dnie)
        
        loop = asyncio.get_event_loop()
        self.transport, _ = await loop.create_datagram_endpoint(lambda: UDP(self), local_addr=('0.0.0.0', self.UDP_PORT))
        
        self.zc = AsyncZeroconf()
        info = ServiceInfo("_dni-im._udp.local.", f"User-{self.dnie.get_fingerprint()[:6]}._dni-im._udp.local.",
                           addresses=[socket.inet_aton(self._get_local_ip())], port=self.UDP_PORT, 
                           properties={'fingerprint': self.dnie.get_fingerprint(), 'real_name': username})
        await self.zc.async_register_service(info)
        AsyncServiceBrowser(self.zc.zeroconf, "_dni-im._udp.local.", [SimpleListener(self)])

    def _get_local_ip(self):
        try: s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8", 80)); return s.getsockname()[0]
        except: return "127.0.0.1"

    def add_discovered_peer(self, info):
        fp = info['fingerprint']
        if fp == self.dnie.get_fingerprint(): return
        
        # TOFU: Guardar si es nuevo
        if fp not in self.trusted:
            self.trusted[fp] = {'name': info['name']}
            json.dump(self.trusted, open("contacts.json", 'w'))
        else:
            info['name'] = self.trusted[fp]['name']

        if fp not in self.discovered:
            self.discovered[fp] = info
            if fp in self.msg_queue: asyncio.create_task(self._flush_queue(fp))

    async def _flush_queue(self, fp):
        for txt in self.msg_queue.pop(fp, []): await self.send_message(fp, txt); await asyncio.sleep(0.1)

    def remove_discovered_peer(self, instance_name):
        fp = next((f for f, i in self.discovered.items() if i['instance_name'] in instance_name), None)
        if fp: del self.discovered[fp]

    def get_peers(self):
        online = list(self.discovered.values())
        online_fps = {p['fingerprint'] for p in online}
        for fp, v in self.trusted.items():
            if fp not in online_fps:
                online.append({'fingerprint': fp, 'name': f"{v['name']} (OFF)", 'ip': 'Offline', 'port': 0})
        return online

    async def send_message(self, target, text):
        # Resolver fingerprint
        fp = target
        if target not in self.discovered and target not in self.trusted:
            found = next((k for k,v in self.trusted.items() if v['name'] == target), None)
            if found: fp = found

        peer = self.discovered.get(fp)
        if not peer: # Offline
            print(f"💤 Encolando para {fp[:8]}")
            self.msg_queue.setdefault(fp, []).append(text)
            return True

        cid = self.conn_mgr.get_cid(fp)
        if not cid:
            cid = self.conn_mgr.create_connection(fp, peer)
            data, _ = self.noise.initiate_handshake(None, fp)
            self.transport.sendto(self.conn_mgr.create_packet(cid, 1, MessageType.HANDSHAKE_INIT, data), (peer['ip'], peer['port']))
            await asyncio.sleep(0.2)
            
        enc = self.noise.encrypt_message(msgpack.packb({'text': text}), fp)
        self.transport.sendto(self.conn_mgr.create_packet(cid, 2, MessageType.TEXT_MESSAGE, enc), (peer['ip'], peer['port']))
        return True

    def handle_packet(self, data, addr):
        try:
            cid, _, mtype, pay = self.conn_mgr.parse_packet(data)
            fp = self.conn_mgr.cid_map.get(cid)
            
            if mtype == MessageType.HANDSHAKE_INIT:
                c = msgpack.unpackb(pay)
                if self.noise.accept_handshake(c):
                    if not self.conn_mgr.get_cid(c['dnie_fingerprint']):
                        self.conn_mgr.create_connection(c['dnie_fingerprint'], {'ip': addr[0]})
                    ack = msgpack.packb({'ack': True, 'static_public': self.noise.static_public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)})
                    self.transport.sendto(self.conn_mgr.create_packet(cid, 0, MessageType.HANDSHAKE_RESPONSE, ack), addr)
            
            elif mtype == MessageType.HANDSHAKE_RESPONSE:
                c = msgpack.unpackb(pay)
                if c.get('ack'): self.noise.update_session_with_peer_key(c['static_public'], fp); asyncio.create_task(self._flush_queue(fp))
            
            elif mtype == MessageType.TEXT_MESSAGE:
                self._handle_text(pay, fp)
        except: pass

    def _handle_text(self, pay, fp):
        try:
            txt = msgpack.unpackb(self.noise.decrypt_message(pay, fp))['text']
            print(f"MSG from {fp[:8]}: {txt}")
        except: pass

    async def stop(self):
        if self.transport: self.transport.close()
        if self.zc: await self.zc.async_close()

class UDP(asyncio.DatagramProtocol):
    def __init__(self, n): self.n = n
    def datagram_received(self, d, a): self.n.handle_packet(d, a)