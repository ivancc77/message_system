import pkcs11
from pkcs11 import ObjectClass, Attribute, Mechanism
from cryptography import x509
import hashlib
import os

class DNIeReal:
    def __init__(self):
        # Rutas comunes para Windows, Linux y Mac
        self.pkcs11_paths = [
            r'C:\Windows\System32\opensc-pkcs11.dll',
            r'C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll',
            '/usr/lib/opensc-pkcs11.so',
            '/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so',
            '/usr/local/lib/opensc-pkcs11.so'
        ]
        self.session = None
        self.certificate = None
        self.private_key = None
        self.identity = {}

    async def initialize(self, pin, interactive=False):
        try:
            lib_path = next((p for p in self.pkcs11_paths if os.path.exists(p)), None)
            if not lib_path:
                print("❌ No se encontró la librería OpenSC (PKCS#11).")
                return False

            lib = pkcs11.lib(lib_path)
            slots = lib.get_slots(token_present=True)
            if not slots:
                print("❌ No se detectó ningún DNIe insertado.")
                return False

            token = slots[0].get_token()
            print(f"💳 Token detectado: {token.label}")

            self.session = token.open(user_pin=pin)
            
            # Cargar certificados y claves
            certs = list(self.session.get_objects({
                Attribute.CLASS: ObjectClass.CERTIFICATE,
                Attribute.CERTIFICATE_TYPE: pkcs11.CertificateType.X_509
            }))

            # Priorizar certificado de Autenticación, sino Firma, sino el primero
            target = None
            for c in certs:
                if "autenticacion" in c[Attribute.LABEL].lower(): target = c; break
            if not target and certs: target = certs[0]
            
            if not target: return False

            self.certificate = target
            self.private_key = self.session.get_key(ObjectClass.PRIVATE_KEY, id=target[Attribute.ID])
            
            # Extraer identidad
            cert_data = self.certificate[Attribute.VALUE]
            cert_obj = x509.load_der_x509_certificate(cert_data)
            
            cn = next((a.value for a in cert_obj.subject if a.oid == x509.NameOID.COMMON_NAME), "Usuario DNIe")
            fp = hashlib.sha256(cert_data).hexdigest()
            
            self.identity = {'name': cn, 'fingerprint': fp}
            return True

        except Exception as e:
            print(f"❌ Error DNIe: {e}")
            return False

    def get_user_name(self): return self.identity.get('name', 'Desconocido')
    def get_fingerprint(self): return self.identity.get('fingerprint', 'unknown')
    
    def sign_data(self, data: bytes) -> bytes:
        try:
            return self.private_key.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
        except: return b''

    def get_certificate_der(self) -> bytes:
        return self.certificate[Attribute.VALUE] if self.certificate else b''