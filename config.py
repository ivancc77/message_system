import os
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import ConfigDict

class DNIMessengerConfig(BaseSettings):
    """Configuración global del sistema"""
    
    model_config = ConfigDict(env_file=".env", case_sensitive=True)
    
    # Red y puertos
    UDP_PORT: int = 6666  # Puerto UDP según especificaciones
    MDNS_PORT: int = 5353
    SERVICE_NAME: str = "_dni-im._udp.local."
    
    # DNIe y criptografía
    PKCS11_LIB_PATH: str = 'C:/Archivos de Programa/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll'
    CERT_SIGNATURE_LABEL: str = "CertFirmaDigital"
    
    # Archivos de almacenamiento
    CONTACT_BOOK_FILE: str = "contacts.json"
    MESSAGE_QUEUE_FILE: str = "message_queue.db"
    LOG_FILE: str = "dni_messenger.log"
    
    # Configuración de red
    DISCOVERY_INTERVAL: int = 30  # segundos
    MESSAGE_TIMEOUT: int = 5000   # millisegundos
    MAX_CONNECTIONS: int = 50
    
    # Trust On First Use (TOFU)
    ENABLE_TOFU: bool = True
