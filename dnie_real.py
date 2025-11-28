"""
DNIe Real - Versión Robusta
"""
import pkcs11
from pkcs11 import ObjectClass, Attribute, Mechanism
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib
import os
from typing import Optional, Dict, Any
from rich.console import Console
from rich.prompt import Prompt

console = Console()

class DNIeReal:
    """Gestor DNIe real con smart card reader"""

    def __init__(self, pkcs11_lib_path: Optional[str] = None):
        self.pkcs11_paths = [
            'C:/Archivos de Programa/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll',
            'C:/Program Files/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll',
            'C:/Windows/System32/opensc-pkcs11.dll',
            '/usr/lib/opensc-pkcs11.so', # Linux
            '/usr/local/lib/opensc-pkcs11.so', # Mac
        ]
        if pkcs11_lib_path:
            self.pkcs11_paths.insert(0, pkcs11_lib_path)
        self.lib = None
        self.session = None
        self.token = None
        self.certificate = None
        self.private_key = None
        self.identity = {}

    async def initialize(self, pin: Optional[str] = None, interactive: bool = True) -> bool:
        try:
            console.print("🎫 Inicializando DNIe real...", style="cyan")
            if not await self._load_pkcs11_library(): return False
            if not await self._find_card_reader(): return False
            if not pin and interactive:
                pin = await self._request_pin()
            if not pin: return False
            if not await self._open_session(pin): return False
            if not await self._load_certificate_and_key(): return False
            if not await self._extract_identity(): return False
            return True
        except Exception as e:
            console.print(f"❌ Error inicializando: {e}", style="red")
            return False

    async def _load_pkcs11_library(self) -> bool:
        console.print("🔍 Buscando librería PKCS#11...", style="yellow")
        for lib_path in self.pkcs11_paths:
            if not lib_path or not os.path.exists(lib_path): continue
            try:
                self.lib = pkcs11.lib(lib_path)
                console.print(f"✅ Librería cargada: {lib_path}", style="green")
                return True
            except Exception: continue
        console.print("❌ No se encontró librería OpenSC.", style="red")
        return False

    async def _find_card_reader(self) -> bool:
        try:
            slots = self.lib.get_slots(token_present=True)
            if not slots:
                console.print("❌ No hay DNIe insertado.", style="red")
                return False
            self.token = slots[0].get_token()
            label = getattr(self.token, "label", "DNIe Desconocido")
            console.print(f"✅ Token detectado: {label}", style="green")
            return True
        except Exception as e:
            console.print(f"❌ Error lector: {e}", style="red")
            return False

    async def _request_pin(self) -> Optional[str]:
        try:
            return Prompt.ask("🔐 Introduce PIN del DNIe", password=True)
        except: return None

    async def _open_session(self, pin: str) -> bool:
        try:
            self.session = self.token.open(user_pin=pin)
            console.print("✅ Sesión abierta correctamente", style="green")
            return True
        except Exception as e:
            console.print(f"❌ Error PIN/Sesión: {e}", style="red")
            return False

    async def _load_certificate_and_key(self) -> bool:
        console.print("🔍 Buscando par de claves (Certificado + Privada)...", style="yellow")
        try:
            certs = list(self.session.get_objects({
                Attribute.CLASS: ObjectClass.CERTIFICATE,
                Attribute.CERTIFICATE_TYPE: pkcs11.CertificateType.X_509
            }))
            if not certs:
                console.print("❌ No se encontraron certificados.", style="red")
                return False
            target_cert = None
            for cert in certs:
                label = cert[Attribute.LABEL].lower()
                if "autenticacion" in label or "auth" in label:
                    target_cert = cert
                    console.print("✅ Certificado de AUTENTICACIÓN encontrado.", style="green")
                    break
            if not target_cert:
                for cert in certs:
                    label = cert[Attribute.LABEL].lower()
                    if "firma" in label:
                        target_cert = cert
                        console.print("⚠️ Usando certificado de FIRMA.", style="yellow")
                        break
            if not target_cert:
                target_cert = certs[0]
                console.print("⚠️ Usando el primer certificado disponible.", style="yellow")
            self.certificate = target_cert
            cert_id = target_cert[Attribute.ID]
            console.print(f"🔗 Buscando clave privada con ID: {cert_id.hex()[:8]}...", style="dim")
            priv_key_obj = self.session.get_key(ObjectClass.PRIVATE_KEY, id=cert_id)
            self.private_key = priv_key_obj
            console.print("✅ Clave privada cargada correctamente.", style="green")
            return True
        except Exception as e:
            console.print(f"❌ Error crítico cargando claves: {e}", style="red")
            return False

    async def _extract_identity(self) -> bool:
        try:
            cert_data = self.certificate[Attribute.VALUE]
            cert_obj = x509.load_der_x509_certificate(cert_data)
            subject = cert_obj.subject
            name = "Usuario DNIe"
            for attr in subject:
                if attr.oid == x509.NameOID.COMMON_NAME:
                    name = attr.value
                    break
            fingerprint = hashlib.sha256(cert_data).hexdigest()
            self.identity = {'name': name, 'fingerprint': fingerprint}
            return True
        except Exception as e:
            console.print(f"Error identidad: {e}", style="red")
            return False

    def get_user_name(self) -> str:
        return self.identity.get('name', 'Desconocido')
    def get_fingerprint(self) -> str:
        return self.identity.get('fingerprint', 'unknown')

    def sign_data(self, data: bytes) -> bytes:
        try:
            return self.private_key.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
        except Exception as e:
            console.print(f"❌ Error firmando: {e}", style="red")
            return b''
    
    def get_certificate_der(self) -> bytes:
        if self.certificate:
            try:
                return self.certificate[Attribute.VALUE]
            except:
                return b''
        return b''