"""
Criptografía Simplificada
"""
import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization
import msgpack

class SimpleCrypto:
    """Criptografía simplificada sin Noise Protocol completo"""
    
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.cipher = None
        
    def generate_keys(self):
        """Genera claves X25519"""
        self.private_key = X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        
        # Clave simétrica para cifrado rápido (simplificado)
        symmetric_key = os.urandom(32)
        self.cipher = ChaCha20Poly1305(symmetric_key)
    
    def get_public_key(self) -> bytes:
        """Obtiene clave pública en bytes"""
        if not self.public_key:
            return b""
        
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def encrypt_message(self, message: str) -> bytes:
        """Cifra mensaje (versión simplificada)"""
        if not self.cipher:
            return message.encode()
        
        try:
            # Nonce aleatorio
            nonce = os.urandom(12)
            
            # Datos a cifrar
            data = {
                'message': message,
                'timestamp': __import__('time').time()
            }
            
            plaintext = msgpack.packb(data)
            ciphertext = self.cipher.encrypt(nonce, plaintext, None)
            
            # Retornar nonce + ciphertext
            return nonce + ciphertext
            
        except Exception as e:
            print(f"Error cifrando: {e}")
            return message.encode()
    
    def decrypt_message(self, encrypted_data: bytes) -> str:
        """Descifra mensaje"""
        if not self.cipher:
            return encrypted_data.decode()
        
        try:
            # Separar nonce y ciphertext
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            
            # Descifrar
            plaintext = self.cipher.decrypt(nonce, ciphertext, None)
            data = msgpack.unpackb(plaintext, raw=False)
            
            return data.get('message', 'Mensaje corrupto')
            
        except Exception as e:
            print(f"Error descifrando: {e}")
            return "Mensaje no descifrable"
    
    def create_handshake(self, remote_public_key: bytes) -> bytes:
        """Crea handshake simplificado"""
        if not self.private_key:
            return b"no_handshake"
        
        try:
            # Crear shared secret (simplificado)
            remote_key = X25519PublicKey.from_public_bytes(remote_public_key)
            shared_secret = self.private_key.exchange(remote_key)
            
            return shared_secret[:16]  # Usar primeros 16 bytes como token
            
        except Exception as e:
            print(f"Error en handshake: {e}")
            return b"error_handshake"
