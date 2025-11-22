# 🔒 DNIe Messenger P2P

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Security](https://img.shields.io/badge/Security-DNIe%20%2B%20Noise-green)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

Una aplicación de mensajería instantánea descentralizada (Peer-to-Peer) diseñada para ofrecer **máxima privacidad y seguridad**. Utiliza el **DNI electrónico español (DNIe)** para garantizar la identidad real de los usuarios y cifra todas las comunicaciones punto a punto.

---

## ✨ Características Principales

-   **🆔 Identidad Real Verificada**: Tu "usuario" en el chat es tu nombre legal extraído del chip del DNIe. Nadie puede suplantarte.
-   **🛡️ Cifrado Militar (Noise IK)**: Protocolo de seguridad avanzado (X25519 + ChaCha20-Poly1305) que asegura que solo tú y el destinatario podéis leer los mensajes.
-   **📡 Sin Servidores (P2P Puro)**: Los mensajes viajan directamente de ordenador a ordenador mediante UDP. Nada se guarda en la nube.
-   **🔎 Descubrimiento Automático**: No necesitas saber la IP de tus amigos. El sistema usa **mDNS (Zeroconf)** para encontrar automáticamente a otros usuarios en tu red WiFi/LAN.
-   **🖥️ Interfaz Moderna (Dark Mode)**: GUI de escritorio nativa con diseño oscuro, burbujas de chat, notificaciones visuales y scroll infinito.
-   **✍️ Firma Digital**: El handshake inicial de conexión está firmado digitalmente con tu DNIe para evitar ataques "Man-in-the-Middle".

---

## 🚀 Instalación y Requisitos

### 1. Requisitos Previos
* **Hardware**: Un lector de tarjetas inteligentes y tu DNIe activo (con el PIN a mano).
* **Drivers**: Tener instalado el software oficial del DNIe (Cuerpo Nacional de Policía).
* **OpenSC**: Librería necesaria para que el sistema "hable" con el lector.
    * *Windows*: [Descargar instalador (win64.msi)](https://github.com/OpenSC/OpenSC/releases).

### 2. Configuración del Entorno

1.  **Clona el repositorio**:
    ```bash
    git clone [https://github.com/tu-usuario/message_system.git](https://github.com/tu-usuario/message_system.git)
    cd message_system
    ```

2.  **Prepara tu entorno Python** (Recomendado):
    ```bash
    python -m venv .venv
    # Activar en Windows:
    .\.venv\Scripts\activate
    # Activar en Linux/Mac:
    source .venv/bin/activate
    ```

3.  **Instala las dependencias**:
    ```bash
    pip install -r requirements.txt
    ```

---

## ▶️ Cómo Usar la Aplicación

1.  **Conecta tu lector** e inserta tu DNIe.
2.  Ejecuta el script principal de la interfaz:
    ```bash
    python gui_modern.py
    ```
3.  **Login Seguro**:
    * Se abrirá una ventana solicitando tu **PIN**.
    * Al introducirlo, el sistema leerá tu certificado, generará tu identidad criptográfica y te conectará a la red.
4.  **Chatear**:
    * Espera unos segundos. Cuando otro usuario (ej. tu compañero) se conecte a la misma red WiFi, aparecerá automáticamente en la barra lateral izquierda.
    * Haz clic en su nombre y ¡empieza a escribir!

---

## 📂 Estructura del Proyecto

```
message_system/
├── dnie_real.py        # <== Puente de seguridad PKCS#11 con el DNIe
├── gui_modern.py       # <== Interfaz gráfica moderna (Tkinter Dark Mode)
├── interface.py        # <== Interfaz de consola avanzada (TUI)
├── main.py             # <== Punto de entrada principal (CLI básica)
├── network.py          # <== Motor de red: Noise IK, UDP y mDNS
├── requirements.txt    # <== Dependencias del proyecto
└── README.md           # <== Documentación
```
---

## ⚠️ Solución de Problemas Comunes

* **"No veo a nadie en la lista":**
    * Asegúrate de que ambos estáis en la misma red WiFi.
    * Revisa el **Firewall de Windows**: la primera vez que ejecutes Python, debes marcar las casillas para permitir acceso a redes "Privadas" y "Públicas".
* **"Error DNIe / PIN incorrecto":**
    * Si fallas el PIN 3 veces, el DNIe se bloquea por seguridad. Tendrás que ir a una comisaría a desbloquearlo.
    * Asegúrate de que el lector tiene la luz encendida y la tarjeta está bien insertada.

---

## 📜 Licencia

Este proyecto se distribuye bajo la Licencia MIT.

Copyright (c) 2025 Iván Ciudad Cires y Víctor Carbajo Ruiz.

Consulta el archivo `LICENSE` en la raíz del repositorio para ver
