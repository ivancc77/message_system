"""
DNIe Real con Smart Card Reader
Implementación completa PKCS#11 para DNIe español
"""
import pkcs11
from pkcs11 import ObjectClass, Attribute, Mechanism
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib
import time
import os
from typing import Optional, Dict, Any
from rich.console import Console
from rich.prompt import Prompt

console = Console()

class DNIeReal:
    """Gestor DNIe real con smart card reader"""
    
    def __init__(self, pkcs11_lib_path: Optional[str] = None):
        # Rutas comunes de librerías PKCS#11 para DNIe
        self.pkcs11_paths = [
            pkcs11_lib_path,
            # Windows
            'C:/Windows/System32/DNIe_P11.dll',
            'C:/Windows/System32/opensc-pkcs11.dll',
            'C:/Program Files/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll',
            # Linux
            '/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so',
            '/usr/lib/opensc-pkcs11.so',
            '/usr/local/lib/opensc-pkcs11.so',
            # macOS
            '/usr/local/lib/opensc-pkcs11.so',
            '/opt/homebrew/lib/opensc-pkcs11.so'
        ]
        
        self.lib = None
        self.session = None
        self.certificate = None
        self.private_key = None
        self.identity = {}
        
    async def initialize(self, pin: Optional[str] = None, interactive: bool = True) -> bool:
        """Inicializa DNIe real"""
        try:
            console.print("🎫 Inicializando DNIe real...", style="cyan")
            
            # 1. Buscar y cargar librería PKCS#11
            if not await self._load_pkcs11_library():
                return False
            
            # 2. Buscar lector y tarjeta
            if not await self._find_card_reader():
                return False
            
            # 3. Solicitar PIN si es necesario
            if not pin and interactive:
                pin = await self._request_pin()
            
            if not pin:
                console.print("❌ PIN requerido para DNIe", style="red")
                return False
            
            # 4. Abrir sesión con PIN
            if not await self._open_session(pin):
                return False
            
            # 5. Cargar certificado de autenticación
            if not await self._load_certificate():
                return False
            
            # 6. Cargar clave privada
            if not await self._load_private_key():
                return False
            
            # 7. Extraer identidad del certificado
            if not await self._extract_identity():
                return False
            
            console.print("✅ DNIe real inicializado correctamente", style="green")
            console.print(f"👤 Usuario: {self.identity.get('name', 'Desconocido')}", style="green")
            console.print(f"🔐 NIF: {self.identity.get('nif', 'N/A')}", style="green")
            
            return True
            
        except Exception as e:
            console.print(f"❌ Error inicializando DNIe real: {e}", style="red")
            return False
    
    async def _load_pkcs11_library(self) -> bool:
        """Busca y carga librería PKCS#11"""
        console.print("🔍 Buscando librería PKCS#11...", style="yellow")
        
        for lib_path in self.pkcs11_paths:
            if not lib_path or not os.path.exists(lib_path):
                continue
            
            try:
                self.lib = pkcs11.lib(lib_path)
                console.print(f"✅ Librería cargada: {lib_path}", style="green")
                return True
            except Exception as e:
                console.print(f"⚠️ Error con {lib_path}: {e}", style="yellow")
                continue
        
        console.print("❌ No se encontró librería PKCS#11 válida", style="red")
        console.print("💡 Instala OpenSC o el middleware oficial del DNIe", style="blue")
        return False
    
    async def _find_card_reader(self) -> bool:
        """Busca lector de tarjetas con DNIe"""
        console.print("🔍 Buscando lector de tarjetas...", style="yellow")
        
        try:
            slots = self.lib.get_slots(token_present=True)
            
            if not slots:
                console.print("❌ No se detecta ninguna tarjeta en el lector", style="red")
                console.print("💡 Asegúrate de que:", style="blue")
                console.print("   • El DNIe está insertado correctamente", style="blue")
                console.print("   • El lector está conectado", style="blue")
                console.print("   • Los drivers están instalados", style="blue")
                return False
            
            # Buscar slot con DNIe
            for slot in slots:
                try:
                    token = slot.get_token()
                    token_info = token.token_info
                    
                    console.print(f"🔍 Token encontrado: {token_info.label}", style="yellow")
                    console.print(f"   Fabricante: {token_info.manufacturer_id}", style="dim")
                    console.print(f"   Modelo: {token_info.model}", style="dim")
                    
                    # Verificar que es un DNIe
                    if any(keyword in token_info.label.lower() for keyword in ['dnie', 'dni electronico', 'fnmt']):
                        self.token = token
                        console.print("✅ DNIe detectado correctamente", style="green")
                        return True
                        
                except Exception as e:
                    console.print(f"⚠️ Error leyendo token: {e}", style="yellow")
                    continue
            
            # Si no encontramos DNIe específicamente, usar el primer token
            self.token = slots[0].get_token()
            console.print("⚠️ Usando primer token disponible (puede ser DNIe)", style="yellow")
            return True
            
        except Exception as e:
            console.print(f"❌ Error buscando lector: {e}", style="red")
            return False
    
    async def _request_pin(self) -> Optional[str]:
        """Solicita PIN del DNIe de forma segura"""
        console.print("🔐 Se requiere el PIN del DNIe", style="cyan")
        console.print("💡 El PIN del DNIe son 4 dígitos numéricos", style="blue")
        
        try:
            # Usando Rich para input seguro
            pin = Prompt.ask("Introduce tu PIN", password=True)
            
            if len(pin) != 4 or not pin.isdigit():
                console.print("⚠️ El PIN del DNIe debe ser 4 dígitos", style="yellow")
                return None
            
            return pin
            
        except KeyboardInterrupt:
            console.print("❌ Operación cancelada por el usuario", style="red")
            return None
    
    async def _open_session(self, pin: str) -> bool:
        """Abre sesión con el DNIe usando PIN"""
        console.print("🔐 Abriendo sesión con PIN...", style="yellow")
        
        try:
            self.session = self.token.open(user_pin=pin)
            console.print("✅ Sesión abierta correctamente", style="green")
            return True
            
        except pkcs11.exceptions.PinIncorrect:
            console.print("❌ PIN incorrecto", style="red")
            console.print("⚠️ Cuidado: Demasiados intentos fallidos bloquearán el DNIe", style="yellow")
            return False
        except pkcs11.exceptions.PinLocked:
            console.print("❌ DNIe bloqueado por demasiados intentos fallidos", style="red")
            console.print("💡 Contacta con la oficina del DNI para desbloquearlo", style="blue")
            return False
        except Exception as e:
            console.print(f"❌ Error abriendo sesión: {e}", style="red")
            return False
    
    async def _load_certificate(self) -> bool:
        """Carga certificado de autenticación del DNIe"""
        console.print("📋 Cargando certificado de autenticación...", style="yellow")
        
        try:
            # Buscar certificados en el DNIe
            certificates = list(self.session.get_objects({
                Attribute.CLASS: ObjectClass.CERTIFICATE,
                Attribute.CERTIFICATE_TYPE: pkcs11.CertificateType.X_509
            }))
            
            if not certificates:
                console.print("❌ No se encontraron certificados", style="red")
                return False
            
            # Buscar certificado de autenticación
            for cert in certificates:
                try:
                    label = str(cert[Attribute.LABEL]).lower()
                    console.print(f"🔍 Certificado encontrado: {cert[Attribute.LABEL]}", style="dim")
                    
                    # El certificado de autenticación suele tener estas etiquetas
                    if any(keyword in label for keyword in ['autenticacion', 'authentication', 'auth']):
                        self.certificate = cert
                        console.print("✅ Certificado de autenticación cargado", style="green")
                        return True
                        
                except Exception as e:
                    console.print(f"⚠️ Error leyendo certificado: {e}", style="yellow")
                    continue
            
            # Si no encontramos específicamente de autenticación, usar el primero
            self.certificate = certificates[0]
            console.print("⚠️ Usando primer certificado disponible", style="yellow")
            return True
            
        except Exception as e:
            console.print(f"❌ Error cargando certificado: {e}", style="red")
            return False
    
    async def _load_private_key(self) -> bool:
        """Carga clave privada correspondiente al certificado"""
        console.print("🔑 Cargando clave privada...", style="yellow")
        
        try:
            # Buscar claves privadas
            private_keys = list(self.session.get_objects({
                Attribute.CLASS: ObjectClass.PRIVATE_KEY
            }))
            
            if not private_keys:
                console.print("❌ No se encontraron claves privadas", style="red")
                return False
            
            # Buscar clave que coincida con el certificado
            for key in private_keys:
                try:
                    label = str(key[Attribute.LABEL]).lower()
                    console.print(f"🔍 Clave privada encontrada: {key[Attribute.LABEL]}", style="dim")
                    
                    if any(keyword in label for keyword in ['autenticacion', 'authentication', 'auth']):
                        self.private_key = key
                        console.print("✅ Clave privada de autenticación cargada", style="green")
                        return True
                        
                except Exception as e:
                    console.print(f"⚠️ Error leyendo clave privada: {e}", style="yellow")
                    continue
            
            # Usar primera clave disponible
            self.private_key = private_keys[0]
            console.print("⚠️ Usando primera clave privada disponible", style="yellow")
            return True
            
        except Exception as e:
            console.print(f"❌ Error cargando clave privada: {e}", style="red")
            return False
    
    async def _extract_identity(self) -> bool:
        """Extrae identidad del certificado DNIe"""
        console.print("👤 Extrayendo identidad del certificado...", style="yellow")
        
        try:
            # Obtener datos del certificado
            cert_data = bytes(self.certificate[Attribute.VALUE])
            cert_obj = x509.load_der_x509_certificate(cert_data)
            
            # Extraer información del subject
            subject = cert_obj.subject
            
            # Valores por defecto
            name = "Usuario DNIe"
            nif = "Desconocido"
            
            # Extraer campos específicos del DNIe
            for attribute in subject:
                oid_name = attribute.oid._name
                value = attribute.value
                
                if oid_name == 'commonName':
                    name = value
                elif oid_name == 'serialNumber':
                    nif = value
                elif oid_name == 'givenName':
                    self.identity['given_name'] = value
                elif oid_name == 'surname':
                    self.identity['surname'] = value
            
            # Crear fingerprint único del certificado
            fingerprint = hashlib.sha256(cert_data).hexdigest()[:16]
            
            # Almacenar identidad
            self.identity = {
                'name': name,
                'nif': nif,
                'fingerprint': fingerprint,
                'certificate': cert_data,
                'serial_number': str(cert_obj.serial_number),
                'issuer': str(cert_obj.issuer),
                'valid_from': cert_obj.not_valid_before,
                'valid_to': cert_obj.not_valid_after,
                'real_dnie': True
            }
            
            console.print("✅ Identidad extraída correctamente", style="green")
            return True
            
        except Exception as e:
            console.print(f"❌ Error extrayendo identidad: {e}", style="red")
            return False
    
    def get_user_name(self) -> str:
        """Obtiene nombre del usuario"""
        return self.identity.get('name', 'Usuario DNIe Real')
    
    def get_fingerprint(self) -> str:
        """Obtiene fingerprint único del certificado"""
        return self.identity.get('fingerprint', 'unknown')
    
    def get_nif(self) -> str:
        """Obtiene NIF del DNIe"""
        return self.identity.get('nif', 'Desconocido')
    
    def sign_data(self, data: bytes) -> bytes:
        """Firma datos con la clave privada del DNIe"""
        if not self.private_key or not self.session:
            return b'no_signature'
        
        try:
            console.print("🔏 Firmando datos con DNIe...", style="yellow")
            
            # Firmar usando PKCS#11
            signature = self.private_key.sign(
                data,
                mechanism=Mechanism.SHA256_RSA_PKCS
            )
            
            console.print("✅ Datos firmados con DNIe", style="green")
            return signature
            
        except Exception as e:
            console.print(f"❌ Error firmando datos: {e}", style="red")
            return b'error_signature'
    
    def verify_signature(self, data: bytes, signature: bytes) -> bool:
        """Verifica firma usando certificado público"""
        try:
            cert_data = self.identity.get('certificate')
            if not cert_data:
                return False
            
            cert_obj = x509.load_der_x509_certificate(cert_data)
            public_key = cert_obj.public_key()
            
            public_key.verify(
                signature,
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            
            return True
            
        except Exception as e:
            console.print(f"❌ Error verificando firma: {e}", style="red")
            return False
    
    def is_mock_mode(self) -> bool:
        """Indica si es modo simulado (siempre False para DNIe real)"""
        return False
    
    def get_certificate_info(self) -> Dict[str, Any]:
        """Obtiene información detallada del certificado"""
        if not self.identity:
            return {}
        
        return {
            'name': self.identity.get('name'),
            'nif': self.identity.get('nif'),
            'fingerprint': self.identity.get('fingerprint'),
            'serial_number': self.identity.get('serial_number'),
            'issuer': self.identity.get('issuer'),
            'valid_from': self.identity.get('valid_from'),
            'valid_to': self.identity.get('valid_to'),
            'is_real': True
        }
    
    def close(self):
        """Cierra sesión DNIe de forma segura"""
        try:
            if self.session:
                self.session.close()
                console.print("✅ Sesión DNIe cerrada", style="green")
        except Exception as e:
            console.print(f"⚠️ Error cerrando sesión: {e}", style="yellow")

# Alias para compatibilidad
DNIeManager = DNIeReal
