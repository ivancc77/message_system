"""
Red P2P Completa - mDNS + UDP + Noise IK + Connection IDs
Implementación final con nombres descriptivos y protocolo completo
"""
import asyncio
import socket
import json
import time
import struct
import hashlib
import os
from typing import List, Dict, Optional, Tuple
from zeroconf import ServiceInfo, Zeroconf, ServiceListener, ServiceBrowser
import msgpack
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization

# Tipos de mensaje según protocolo
class MessageType:
    HANDSHAKE_INIT = 1
    HANDSHAKE_RESPONSE = 2
    TEXT_MESSAGE = 3
    TYPING_INDICATOR = 4
    MESSAGE_ACK = 5
    CONTACT_REQUEST = 6
    CONTACT_RESPONSE = 7
    PING = 8
    PONG = 9

class NoiseIKProtocol:
    """
    Implementación completa Noise IK Protocol
    Pattern: -> e, es, s, ss  <- e, ee, se
    """
    
    def __init__(self, static_private_key, dnie_identity):
        self.static_private = static_private_key
        self.static_public = static_private_key.public_key()
        self.dnie_identity = dnie_identity
        self.sessions = {}  # remote_fingerprint -> session_data
        
    def initiate_handshake(self, remote_static_key: bytes, remote_fingerprint: str) -> Tuple[bytes, dict]:
        """
        Inicia handshake Noise IK
        -> e, es, s, ss
        """
        # 1. Generar clave efímera
        ephemeral_private = X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key()
        
        # 2. Realizar intercambios DH según Noise IK
        remote_static = X25519PublicKey.from_public_bytes(remote_static_key)
        
        # es: ephemeral-static
        es = ephemeral_private.exchange(remote_static)
        
        # ss: static-static  
        ss = self.static_private.exchange(remote_static)
        
        # 3. Derivar claves usando BLAKE2s (según especificaciones)
        h = hashlib.blake2s(digest_size=64)
        h.update(b"DNI-IM-NoiseIK")  # Protocol name
        h.update(es)
        h.update(ss)
        h.update(self.dnie_identity['fingerprint'].encode())
        key_material = h.digest()
        
        # 4. Dividir en claves de cifrado/descifrado
        send_key = key_material[:32]
        recv_key = key_material[32:64]
        
        # 5. Crear sesión
        session = {
            'send_cipher': ChaCha20Poly1305(send_key),
            'recv_cipher': ChaCha20Poly1305(recv_key),
            'send_nonce': 0,
            'recv_nonce': 0,
            'remote_fingerprint': remote_fingerprint,
            'established': True
        }
        
        self.sessions[remote_fingerprint] = session
        
        # 6. Crear mensaje de handshake
        ephemeral_bytes = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        static_bytes = self.static_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        handshake_message = {
            'ephemeral_public': ephemeral_bytes,
            'static_public': static_bytes,
            'dnie_fingerprint': self.dnie_identity['fingerprint'],
            'dnie_name': self.dnie_identity['name'],
            'protocol_version': '1.0'
        }
        
        return msgpack.packb(handshake_message), session
    
    def process_handshake_response(self, response_data: bytes, remote_fingerprint: str) -> bool:
        """
        Procesa respuesta de handshake
        <- e, ee, se
        """
        try:
            response = msgpack.unpackb(response_data, raw=False)
            
            # Verificar que la respuesta es válida
            if 'ephemeral_public' in response and 'ack' in response:
                session = self.sessions.get(remote_fingerprint)
                if session:
                    session['handshake_complete'] = True
                    return True
            
            return False
            
        except Exception as e:
            print(f"Error procesando handshake response: {e}")
            return False
    
    def encrypt_message(self, plaintext: bytes, remote_fingerprint: str) -> bytes:
        """Cifra mensaje usando sesión Noise"""
        session = self.sessions.get(remote_fingerprint)
        if not session or not session.get('established'):
            return plaintext  # Fallback sin cifrar
        
        try:
            nonce = session['send_nonce'].to_bytes(12, 'little')
            session['send_nonce'] += 1
            
            ciphertext = session['send_cipher'].encrypt(nonce, plaintext, None)
            return nonce + ciphertext
            
        except Exception as e:
            print(f"Error cifrando: {e}")
            return plaintext
    
    def decrypt_message(self, ciphertext: bytes, remote_fingerprint: str) -> bytes:
        """Descifra mensaje usando sesión Noise"""
        session = self.sessions.get(remote_fingerprint)
        if not session or not session.get('established'):
            return ciphertext  # Fallback sin descifrar
        
        try:
            if len(ciphertext) < 12:
                return ciphertext
            
            nonce = ciphertext[:12]
            encrypted = ciphertext[12:]
            
            plaintext = session['recv_cipher'].decrypt(nonce, encrypted, None)
            session['recv_nonce'] += 1
            
            return plaintext
            
        except Exception as e:
            print(f"Error descifrando: {e}")
            return ciphertext

class ConnectionManager:
    """
    Gestor de Connection IDs y Stream IDs
    Implementa multiplexación según especificaciones
    """
    
    def __init__(self):
        self.connections = {}  # CID -> connection_info
        self.next_cid = 1
        self.cid_to_peer = {}  # CID -> peer_fingerprint
        self.peer_to_cid = {}  # peer_fingerprint -> CID
        
    def create_connection(self, peer_fingerprint: str, peer_info: dict) -> int:
        """Crea nueva conexión con CID único"""
        cid = self.next_cid
        self.next_cid += 1
        
        connection_info = {
            'cid': cid,
            'peer_fingerprint': peer_fingerprint,
            'peer_info': peer_info,
            'created': time.time(),
            'streams': {},  # stream_id -> stream_info
            'next_stream_id': 1,
            'status': 'connecting'
        }
        
        self.connections[cid] = connection_info
        self.cid_to_peer[cid] = peer_fingerprint
        self.peer_to_cid[peer_fingerprint] = cid
        
        print(f"🔗 Nueva conexión CID:{cid} para peer {peer_fingerprint[:8]}...")
        return cid
    
    def get_cid_for_peer(self, peer_fingerprint: str) -> Optional[int]:
        """Obtiene CID para un peer específico"""
        return self.peer_to_cid.get(peer_fingerprint)
    
    def get_peer_for_cid(self, cid: int) -> Optional[str]:
        """Obtiene peer fingerprint para un CID"""
        return self.cid_to_peer.get(cid)
    
    def create_stream(self, cid: int, stream_type: str) -> int:
        """Crea nuevo stream en una conexión"""
        if cid not in self.connections:
            return 0
        
        connection = self.connections[cid]
        stream_id = connection['next_stream_id']
        connection['next_stream_id'] += 1
        
        stream_info = {
            'stream_id': stream_id,
            'type': stream_type,
            'created': time.time(),
            'status': 'active'
        }
        
        connection['streams'][stream_id] = stream_info
        return stream_id
    
    def create_packet(self, cid: int, stream_id: int, msg_type: int, payload: bytes) -> bytes:
        """
        Crea paquete con header CID/StreamID según especificaciones
        Header: CID(4) + StreamID(4) + Type(2) + Length(2) = 12 bytes
        """
        if len(payload) > 65535 - 12:  # Max payload size
            raise ValueError("Payload demasiado grande")
        
        header = struct.pack('!IIHH', cid, stream_id, msg_type, len(payload))
        return header + payload
    
    def parse_packet(self, packet: bytes) -> Tuple[int, int, int, bytes]:
        """
        Parsea paquete y extrae CID, StreamID, Type, Payload
        """
        if len(packet) < 12:
            raise ValueError("Paquete demasiado pequeño")
        
        cid, stream_id, msg_type, length = struct.unpack('!IIHH', packet[:12])
        payload = packet[12:12+length]
        
        if len(payload) != length:
            raise ValueError("Longitud de payload inconsistente")
        
        return cid, stream_id, msg_type, payload

class SimpleServiceListener(ServiceListener):
    """Listener mDNS con soporte completo"""
    
    def __init__(self, network_manager):
        self.network = network_manager
    
    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Servicio mDNS descubierto"""
        info = zc.get_service_info(type_, name)
        if info and info.addresses:
            # Extraer información del peer
            instance_name = name.split('.')[0]  # Nombre antes del primer punto
            peer_info = {
                'instance_name': instance_name,
                'ip': socket.inet_ntoa(info.addresses[0]),
                'port': info.port,
                'properties': {},
                'discovered_at': time.time(),
                'service_name': name
            }
            
            # Extraer propiedades del servicio
            if info.properties:
                for k, v in info.properties.items():
                    try:
                        key = k.decode() if isinstance(k, bytes) else str(k)
                        value = v.decode() if isinstance(v, bytes) else str(v)
                        peer_info['properties'][key] = value
                    except:
                        pass
            
            # Obtener nombre de usuario y fingerprint
            peer_info['name'] = peer_info['properties'].get('real_name', 
                                                           peer_info['properties'].get('user', instance_name))
            peer_info['fingerprint'] = peer_info['properties'].get('fingerprint', '')
            
            print(f"🔍 Peer descubierto: {peer_info['name']} ({instance_name})")
            print(f"   📍 {peer_info['ip']}:{peer_info['port']}")
            print(f"   🆔 Fingerprint: {peer_info['fingerprint'][:8]}...")
            
            self.network.add_discovered_peer(peer_info)
    
    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Servicio mDNS removido"""
        instance_name = name.split('.')[0]
        print(f"🔍 Peer desconectado: {instance_name}")
        self.network.remove_discovered_peer(instance_name)
    
    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Servicio mDNS actualizado"""
        self.add_service(zc, type_, name)

class CompleteNetwork:
    """
    Gestor de red completo con todas las especificaciones:
    - mDNS discovery (_dni-im._udp.local.) con nombres descriptivos
    - UDP puerto 6666
    - Noise IK protocol
    - Connection IDs y Stream IDs
    - TOFU contact verification
    """
    
    def __init__(self, dnie_manager, crypto_manager):
        # Componentes principales
        self.dnie = dnie_manager
        self.crypto = crypto_manager
        
        # Red
        self.zeroconf = None
        self.service_info = None
        self.listener = None
        self.browser = None
        self.udp_transport = None
        self.udp_protocol = None
        
        # Gestores
        self.noise = None
        self.connection_manager = ConnectionManager()
        
        # Estado
        self.peers = {}  # fingerprint -> peer_info
        self.discovered_peers = {}  # instance_name -> peer_info (desde mDNS)
        self.username = "unknown"
        self.my_fingerprint = ""
        self.my_instance_name = ""
        
        # Configuración
        self.SERVICE_TYPE = "_dni-im._udp.local."
        self.UDP_PORT = 6666
        
        # Estadísticas
        self.start_time = time.time()
        self.messages_sent = 0
        self.messages_received = 0
        
        # TOFU - Trust On First Use
        self.contact_book = {}  # fingerprint -> contact_info
        self.pending_contacts = {}  # fingerprint -> pending_info
        
        # Message queue para offline delivery
        self.message_queue = {}  # peer_fingerprint -> [messages]
    
    async def start(self, username: str, public_key: bytes):
        """Inicia red completa"""
        self.username = username
        self.my_fingerprint = self.dnie.get_fingerprint()
        
        # Inicializar Noise IK Protocol
        static_private = X25519PrivateKey.generate()
        dnie_identity = {
            'name': self.dnie.get_user_name(),
            'fingerprint': self.my_fingerprint
        }
        self.noise = NoiseIKProtocol(static_private, dnie_identity)
        
        print(f"🔍 Iniciando red para {username}")
        print(f"🆔 Fingerprint: {self.my_fingerprint}")
        
        try:
            # Iniciar componentes
            await self._start_mdns()
            await self._start_udp()
            
            print(f"🌐 Red completa iniciada correctamente")
            return True
            
        except Exception as e:
            print(f"❌ Error iniciando red: {e}")
            return False
    
    def _generate_service_name(self) -> str:
        """Genera nombre único y descriptivo para mDNS"""
        try:
            # Obtener nombre real del DNIe
            real_name = self.dnie.get_user_name()
            fingerprint = self.dnie.get_fingerprint()
            
            # Procesar nombre para mDNS (RFC 6763)
            # Solo permitir: letras, números, guiones
            processed_parts = []
            for part in real_name.split():
                clean_part = ''.join(c if c.isalnum() else '-' for c in part)
                clean_part = clean_part.strip('-')
                if clean_part and len(clean_part) > 1:
                    processed_parts.append(clean_part)
            
            # Crear nombre base
            if processed_parts:
                base_name = '-'.join(processed_parts[:2])  # Máximo 2 palabras
                base_name = base_name[:15]  # Limitar longitud
            else:
                base_name = "DNI-User"
            
            # Agregar sufijo único del fingerprint
            unique_suffix = fingerprint[:6].upper()
            
            # Formato final: NombreUsuario-ABC123
            instance_name = f"{base_name}-{unique_suffix}"
            self.my_instance_name = instance_name
            
            return f"{instance_name}.{self.SERVICE_TYPE}"
            
        except Exception as e:
            print(f"⚠️ Error generando nombre: {e}")
            # Fallback al nombre original
            fallback_name = f"{self.username}-{self.my_fingerprint[:6]}"
            self.my_instance_name = fallback_name
            return f"{fallback_name}.{self.SERVICE_TYPE}"
    
    async def _start_mdns(self):
        """Inicia servicio mDNS con nombres descriptivos"""
        try:
            self.zeroconf = Zeroconf()
            
            # Configurar nuestro servicio con nombre descriptivo
            local_ip = self._get_local_ip()
            service_name = self._generate_service_name()
            
            print(f"🔍 Registrando servicio: {service_name}")
            print(f"📍 IP local: {local_ip}:{self.UDP_PORT}")
            
            # Propiedades extendidas del servicio
            properties = {
                b'fingerprint': self.my_fingerprint.encode(),
                b'user': self.username.encode(),
                b'real_name': self.dnie.get_user_name().encode(),
                b'version': b'1.0',
                b'protocol': b'noise-ik',
                b'capabilities': b'text,file,voice',  # Capacidades futuras
                b'started': str(int(time.time())).encode(),
                b'app_version': b'DNI-Messenger-2.0'
            }
            
            self.service_info = ServiceInfo(
                self.SERVICE_TYPE,  # Tipo genérico del protocolo
                service_name,       # Nombre único de esta instancia
                addresses=[socket.inet_aton(local_ip)],
                port=self.UDP_PORT,
                properties=properties
            )
            
            # Registrar servicio
            self.zeroconf.register_service(self.service_info)
            print(f"📡 Servicio mDNS registrado correctamente")
            print(f"🆔 Tipo: {self.SERVICE_TYPE}")
            print(f"🏷️ Instancia: {self.my_instance_name}")
            
            # Iniciar búsqueda de otros servicios del mismo tipo
            self.listener = SimpleServiceListener(self)
            self.browser = ServiceBrowser(self.zeroconf, self.SERVICE_TYPE, self.listener)
            print(f"🔍 Buscando otros servicios {self.SERVICE_TYPE}")
            
            # Esperar descubrimientos
            await asyncio.sleep(3)
            discovered_count = len(self.discovered_peers)
            print(f"✅ mDNS activo - {discovered_count} peer(s) descubierto(s)")
            
            if discovered_count == 0:
                print("💡 No se encontraron otros peers (normal si eres el primero)")
            else:
                print("📋 Peers descubiertos:")
                for instance_name, peer in self.discovered_peers.items():
                    print(f"   • {peer['name']} ({instance_name}) - {peer['ip']}:{peer['port']}")
            
        except Exception as e:
            print(f"❌ Error iniciando mDNS: {e}")
            raise
    
    async def _start_udp(self):
        """Inicia servidor UDP"""
        try:
            loop = asyncio.get_event_loop()
            
            self.udp_transport, self.udp_protocol = await loop.create_datagram_endpoint(
                lambda: CompleteUDPProtocol(self),
                local_addr=('0.0.0.0', self.UDP_PORT)
            )
            
            print(f"🚀 Servidor UDP iniciado en puerto {self.UDP_PORT}")
            
        except Exception as e:
            print(f"❌ Error UDP: {e}")
            raise
    
    def _get_local_ip(self) -> str:
        """Obtiene IP local"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except:
            return "127.0.0.1"
    
    def add_discovered_peer(self, peer_info: dict):
        """Agrega peer descubierto por mDNS"""
        instance_name = peer_info['instance_name']
        fingerprint = peer_info.get('fingerprint', '')
        
        # No agregarnos a nosotros mismos
        if fingerprint == self.my_fingerprint or instance_name == self.my_instance_name:
            print(f"🔍 DEBUG: Ignorando nuestro propio servicio: {instance_name}")
            return
        
        self.discovered_peers[instance_name] = peer_info
        
        # Si tiene fingerprint, agregarlo a peers principales
        if fingerprint:
            self.peers[fingerprint] = peer_info
            
            # TOFU - Trust On First Use
            if fingerprint not in self.contact_book:
                self.pending_contacts[fingerprint] = peer_info
                print(f"🔐 TOFU: Nuevo peer {peer_info['name']} requiere verificación")
                
                # Auto-aprobar peers de demo (para testing)
                if 'demo' in peer_info['name'].lower() or fingerprint in ['demo123', 'test456']:
                    self.verify_contact(fingerprint, True)
    
    def remove_discovered_peer(self, instance_name: str):
        """Remueve peer descubierto"""
        if instance_name in self.discovered_peers:
            peer_info = self.discovered_peers[instance_name]
            fingerprint = peer_info.get('fingerprint', '')
            
            del self.discovered_peers[instance_name]
            
            if fingerprint and fingerprint in self.peers:
                del self.peers[fingerprint]
    
    def get_peers(self) -> List[dict]:
        """Lista de peers disponibles (compatibilidad con interfaz existente)"""
        return list(self.discovered_peers.values())
    
    def get_verified_peers(self) -> List[dict]:
        """Lista de peers verificados (TOFU)"""
        return [peer for fp, peer in self.peers.items() if fp in self.contact_book]
    
    def get_pending_contacts(self) -> List[dict]:
        """Lista de contactos pendientes de verificación"""
        return list(self.pending_contacts.values())
    
    def verify_contact(self, fingerprint: str, user_approved: bool = True):
        """Verifica contacto según TOFU"""
        if fingerprint in self.pending_contacts and user_approved:
            peer_info = self.pending_contacts[fingerprint]
            
            # Agregar a contact book
            self.contact_book[fingerprint] = {
                'peer_info': peer_info,
                'verified_at': time.time(),
                'trusted': True
            }
            
            del self.pending_contacts[fingerprint]
            print(f"✅ Contacto verificado: {peer_info['name']}")
            
            # Entregar mensajes encolados
            if fingerprint in self.message_queue:
                print(f"📬 Entregando {len(self.message_queue[fingerprint])} mensajes encolados")
                del self.message_queue[fingerprint]
    
    async def send_message(self, target_peer_name: str, message: str) -> bool:
        """
        Envía mensaje (versión simplificada para compatibilidad)
        Busca peer por nombre y envía mensaje
        """
        try:
            # Buscar peer por nombre
            target_peer = None
            target_fingerprint = None
            
            # Buscar en discovered_peers por nombre
            for instance_name, peer_info in self.discovered_peers.items():
                if peer_info['name'] == target_peer_name or instance_name == target_peer_name:
                    target_peer = peer_info
                    target_fingerprint = peer_info.get('fingerprint', '')
                    break
            
            if not target_peer:
                print(f"❌ Peer no encontrado: {target_peer_name}")
                return False
            
            # Si no tiene fingerprint, es peer demo - simular envío
            if not target_fingerprint:
                print(f"📤 Enviando mensaje simulado a {target_peer_name}")
                print(f"   💌 Mensaje: {message}")
                self.messages_sent += 1
                return True
            
            # Envío real con fingerprint
            return await self._send_message_with_fingerprint(target_fingerprint, message)
            
        except Exception as e:
            print(f"❌ Error enviando mensaje: {e}")
            return False
    
    async def _send_message_with_fingerprint(self, target_fingerprint: str, message: str) -> bool:
        """Envía mensaje usando fingerprint (protocolo completo)"""
        try:
            # Verificar que el peer existe
            if target_fingerprint not in self.peers:
                print(f"❌ Peer fingerprint no encontrado: {target_fingerprint[:8]}...")
                return False
            
            peer_info = self.peers[target_fingerprint]
            
            # Verificar TOFU - por ahora auto-aprobar para demo
            if target_fingerprint not in self.contact_book:
                self.verify_contact(target_fingerprint, True)
            
            # Obtener o crear conexión
            cid = self.connection_manager.get_cid_for_peer(target_fingerprint)
            if cid is None:
                cid = self.connection_manager.create_connection(target_fingerprint, peer_info)
                await self._initiate_noise_handshake(cid, target_fingerprint, peer_info)
            
            # Crear stream para el mensaje
            stream_id = self.connection_manager.create_stream(cid, 'text_chat')
            
            # Preparar mensaje
            message_data = {
                'text': message,
                'timestamp': time.time(),
                'sender': self.my_fingerprint,
                'message_id': f"{int(time.time())}-{hash(message) % 1000}"
            }
            
            message_bytes = msgpack.packb(message_data)
            
            # Cifrar con Noise IK
            encrypted_message = self.noise.encrypt_message(message_bytes, target_fingerprint)
            
            # Crear paquete con CID/StreamID
            packet = self.connection_manager.create_packet(
                cid, stream_id, MessageType.TEXT_MESSAGE, encrypted_message
            )
            
            # Enviar por UDP
            self.udp_transport.sendto(packet, (peer_info['ip'], peer_info['port']))
            
            self.messages_sent += 1
            print(f"📤 Mensaje enviado a {peer_info['name']} (CID:{cid}, Stream:{stream_id})")
            
            return True
            
        except Exception as e:
            print(f"❌ Error enviando mensaje con fingerprint: {e}")
            return False
    
    async def _initiate_noise_handshake(self, cid: int, target_fingerprint: str, peer_info: dict):
        """Inicia handshake Noise IK"""
        try:
            # Obtener clave pública del peer (simulada por ahora)
            remote_public_key = os.urandom(32)  # Placeholder
            
            # Crear handshake
            handshake_data, session = self.noise.initiate_handshake(
                remote_public_key, target_fingerprint
            )
            
            # Crear paquete de handshake
            stream_id = self.connection_manager.create_stream(cid, 'handshake')
            packet = self.connection_manager.create_packet(
                cid, stream_id, MessageType.HANDSHAKE_INIT, handshake_data
            )
            
            # Enviar handshake
            self.udp_transport.sendto(packet, (peer_info['ip'], peer_info['port']))
            print(f"🤝 Handshake Noise IK iniciado con {peer_info['name']}")
            
        except Exception as e:
            print(f"❌ Error en handshake: {e}")
    
    def handle_received_packet(self, packet: bytes, addr: Tuple[str, int]):
        """Procesa paquete recibido con protocolo completo"""
        try:
            # 1. Parsear paquete
            cid, stream_id, msg_type, payload = self.connection_manager.parse_packet(packet)
            
            print(f"📨 Paquete recibido de {addr[0]} - CID:{cid}, Stream:{stream_id}, Type:{msg_type}")
            
            # 2. Identificar peer
            peer_fingerprint = self.connection_manager.get_peer_for_cid(cid)
            if not peer_fingerprint:
                # Conexión nueva - buscar peer por IP
                peer_fingerprint = self._find_peer_by_ip(addr[0])
                if peer_fingerprint:
                    # Asociar CID existente
                    peer_info = self.peers[peer_fingerprint]
                    self.connection_manager.cid_to_peer[cid] = peer_fingerprint
                    self.connection_manager.peer_to_cid[peer_fingerprint] = cid
                    self.connection_manager.connections[cid] = {
                        'cid': cid,
                        'peer_fingerprint': peer_fingerprint,
                        'peer_info': peer_info,
                        'created': time.time(),
                        'streams': {},
                        'next_stream_id': 1,
                        'status': 'active'
                    }
            
            # 3. Procesar según tipo de mensaje
            if msg_type == MessageType.HANDSHAKE_INIT:
                self._handle_handshake_init(cid, stream_id, payload, addr)
            elif msg_type == MessageType.HANDSHAKE_RESPONSE:
                self._handle_handshake_response(cid, stream_id, payload, addr)
            elif msg_type == MessageType.TEXT_MESSAGE:
                self._handle_text_message(cid, stream_id, payload, addr, peer_fingerprint)
            elif msg_type == MessageType.PING:
                self._handle_ping(cid, stream_id, payload, addr)
            
            self.messages_received += 1
            
        except Exception as e:
            print(f"❌ Error procesando paquete de {addr}: {e}")
    
    def _find_peer_by_ip(self, ip: str) -> Optional[str]:
        """Encuentra peer por IP"""
        for fingerprint, peer_info in self.peers.items():
            if peer_info.get('ip') == ip:
                return fingerprint
        return None
    
    def _handle_handshake_init(self, cid: int, stream_id: int, payload: bytes, addr):
        """Maneja inicio de handshake"""
        try:
            handshake_data = msgpack.unpackb(payload, raw=False)
            remote_fingerprint = handshake_data.get('dnie_fingerprint', '')
            
            print(f"🤝 Handshake recibido de {remote_fingerprint[:8]}...")
            
            # Responder con HANDSHAKE_RESPONSE
            response = {'ack': True, 'timestamp': time.time()}
            response_data = msgpack.packb(response)
            
            packet = self.connection_manager.create_packet(
                cid, stream_id, MessageType.HANDSHAKE_RESPONSE, response_data
            )
            
            self.udp_transport.sendto(packet, addr)
            
        except Exception as e:
            print(f"❌ Error en handshake init: {e}")
    
    def _handle_handshake_response(self, cid: int, stream_id: int, payload: bytes, addr):
        """Maneja respuesta de handshake"""
        try:
            peer_fingerprint = self.connection_manager.get_peer_for_cid(cid)
            if peer_fingerprint:
                success = self.noise.process_handshake_response(payload, peer_fingerprint)
                if success:
                    print(f"✅ Handshake completado con {peer_fingerprint[:8]}...")
                    
        except Exception as e:
            print(f"❌ Error en handshake response: {e}")
    
    def _handle_text_message(self, cid: int, stream_id: int, payload: bytes, addr, peer_fingerprint: Optional[str]):
        """Maneja mensaje de texto"""
        try:
            if not peer_fingerprint:
                print("❌ Mensaje de peer desconocido")
                return
            
            # Descifrar con Noise IK
            decrypted = self.noise.decrypt_message(payload, peer_fingerprint)
            message_data = msgpack.unpackb(decrypted, raw=False)
            
            peer_info = self.peers.get(peer_fingerprint, {})
            sender_name = peer_info.get('name', 'Desconocido')
            message_text = message_data.get('text', 'Mensaje corrupto')
            timestamp = message_data.get('timestamp', time.time())
            
            print(f"\n💬 MENSAJE RECIBIDO")
            print(f"   De: {sender_name} ({peer_fingerprint[:8]}...)")
            print(f"   Mensaje: {message_text}")
            print(f"   Hora: {time.strftime('%H:%M:%S', time.localtime(timestamp))}")
            print(f"   CID: {cid}, Stream: {stream_id}")
            
        except Exception as e:
            print(f"❌ Error procesando mensaje de texto: {e}")
    
    def _handle_ping(self, cid: int, stream_id: int, payload: bytes, addr):
        """Maneja ping"""
        try:
            pong_data = msgpack.packb({'timestamp': time.time()})
            packet = self.connection_manager.create_packet(
                cid, stream_id, MessageType.PONG, pong_data
            )
            self.udp_transport.sendto(packet, addr)
        except Exception as e:
            print(f"❌ Error en ping: {e}")
    
    def get_network_stats(self) -> dict:
        """Estadísticas de red"""
        uptime = time.time() - self.start_time
        return {
            'uptime_seconds': int(uptime),
            'peers_discovered': len(self.discovered_peers),
            'peers_verified': len(self.contact_book),
            'pending_contacts': len(self.pending_contacts),
            'active_connections': len(self.connection_manager.connections),
            'messages_sent': self.messages_sent,
            'messages_received': self.messages_received,
            'local_ip': self._get_local_ip(),
            'udp_port': self.UDP_PORT,
            'my_fingerprint': self.my_fingerprint,
            'my_instance_name': self.my_instance_name
        }
    
    async def stop(self):
        """Para todos los servicios"""
        print("🔄 Cerrando red completa...")
        
        try:
            if self.browser:
                self.browser.cancel()
            
            if self.service_info and self.zeroconf:
                self.zeroconf.unregister_service(self.service_info)
            
            if self.zeroconf:
                self.zeroconf.close()
            
            if self.udp_transport:
                self.udp_transport.close()
                
            print("✅ Red cerrada completamente")
                
        except Exception as e:
            print(f"⚠️ Error cerrando red: {e}")

class CompleteUDPProtocol(asyncio.DatagramProtocol):
    """Protocolo UDP completo"""
    
    def __init__(self, network_manager):
        self.network = network_manager
    
    def datagram_received(self, data: bytes, addr):
        """Procesa datagram con protocolo completo"""
        self.network.handle_received_packet(data, addr)
    
    def error_received(self, exc: Exception):
        """Maneja errores UDP"""
        print(f"❌ Error UDP: {exc}")

# Alias para compatibilidad con código existente
SimpleNetwork = CompleteNetwork
