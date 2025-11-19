"""
DNIe Simplificado para el proyecto
"""
import hashlib
import time
import os

class DNIeManager:
    """Gestor DNIe simplificado"""
    
    def __init__(self):
        # Crear usuario único por instancia
        process_id = os.getpid()  # ID del proceso
        timestamp = int(time.time() * 1000) % 10000  # Últimos 4 dígitos del timestamp
        
        self.user_name = f"Usuario-{process_id}-{timestamp}"
        
        # Fingerprint único basado en usuario
        unique_data = f"simulated-{process_id}-{timestamp}".encode()
        self.fingerprint = hashlib.sha256(unique_data).hexdigest()[:8]
        
    async def initialize(self) -> bool:
        """Inicializa DNIe"""
        print(f"🎫 DNIe simulado inicializado: {self.user_name}")
        return True
        
    def get_user_name(self) -> str:
        """Nombre del usuario"""
        return self.user_name
        
    def get_fingerprint(self) -> str:
        """Huella digital"""
        return self.fingerprint
        
    def is_mock_mode(self) -> bool:
        """Siempre en modo simulado"""
        return True
