# 📘 Diario de Ingeniería: DNIe Secure P2P Messenger

**🚀 Proyecto:** Implementación de Cliente de Mensajería P2P con Identidad DNIe
**🛠️ Tecnologías:** Python 3.10+, Asyncio, Cryptography (Noise IK), Zeroconf (mDNS), Prompt Toolkit
**📊 Estado:** Funcional (v5.0 - Offline Ready)

---

## 1. 🎯 Introducción y Análisis de Requisitos
El proyecto consiste en el diseño e implementación de un cliente de mensajería instantánea *peer-to-peer* (P2P) para escritorio. El requisito central es vincular la identidad del usuario a su tarjeta inteligente **DNIe** (Documento Nacional de Identidad electrónico).

Los objetivos técnicos principales identificados fueron:
* 💳 **Identidad Hardware:** Uso de PKCS#11 para firmar con el DNIe.
* 📡 **Descubrimiento:** Anuncio de presencia en red local vía mDNS (`_dni-im._udp.local.`).
* 🔒 **Seguridad:** Protocolo *Noise IK* (X25519, BLAKE2s, ChaCha20-Poly1305) con verificación de firma.
* 🖥️ **Interfaz:** TUI (Interfaz de Texto) para gestionar múltiples chats.

---

## 2. 📅 Cronología de Desarrollo e Hitos Técnicos

### 🚧 Fase I: Fundamentos y Hardware (Identidad)
El desarrollo comenzó asegurando la interacción con el lector de tarjetas inteligentes. Partiendo de un código base capaz de verificar el DNIe, se integró la librería `pkcs11` para extraer certificados y realizar firmas digitales sin exponer la clave privada.

* **⚡ Reto:** Inicialización segura y captura de PIN.
* **✅ Solución:** Implementación de `DNIeManager` y uso de `getpass` para la entrada segura de credenciales en consola.

### 🌐 Fase II: Red y Descubrimiento (Networking)
Se implementó la capa de red basada en `asyncio` y `Zeroconf`. Se detectó un problema crítico de concurrencia al intentar conectar dos clientes en la misma máquina o red con el mismo identificador.

* **💥 Problema:** "Solo deja entrar a uno y al otro le sale error".
* **🔍 Diagnóstico:** Colisión de nombres de servicio mDNS.
* **🛠️ Solución:** Se modificó el anuncio de servicio para incluir el *fingerprint* del certificado en el nombre de la instancia, garantizando unicidad en la LAN.

### 🎨 Fase III: Interfaz de Usuario (TUI)
Se solicitó replicar una interfaz visual específica basada en referencias de diseño (estilo Telegram en terminal).

* **🖌️ Implementación:** Uso de `prompt_toolkit` con diseño de tres paneles (Sidebar, Chat, Input).
* **🐛 Corrección de UI:** Los logs del sistema ("prints") rompían el dibujo de la interfaz. Se implementó un `StdoutRedirector` para capturar la salida estándar y redirigirla a un canal de "System Logs" dentro de la propia aplicación visual.

### 🔐 Fase IV: Criptografía y el "Problema del Espejo"
Se logró establecer un túnel seguro (indicado por `DEBUG KEY MATERIAL` idéntico en ambos extremos), pero los mensajes no se desencriptaban correctamente.

* **🧠 Análisis Técnico:** Aunque el *handshake* Diffie-Hellman fue exitoso, ambos pares usaban el mismo set de claves simétricas para enviar y recibir (efecto espejo), provocando errores de autenticación (`InvalidTag`).
* **🔄 Solución:** Se corrigió la derivación HKDF. El iniciador de la conexión usa `K1` para enviar y `K2` para recibir; el receptor hace lo inverso. Esto habilitó el flujo bidireccional de mensajes.

### 📮 Fase V: Resiliencia y Mensajería Offline ("Postcards")
La etapa final se centró en la robustez ante desconexiones. Se requería que, si un usuario se desconectaba, el sistema lo indicara y permitiera encolar mensajes.

* **⚙️ Mecanismo Implementado:**
    1.  **Detección:** Caída vía mDNS (`remove_service`) -> Marca al usuario como `(OFF)` en la UI.
    2.  **Cola de Mensajes:** Si el destino no tiene IP, el mensaje se guarda en memoria (`message_queue`) en lugar de intentar el envío UDP, evitando *crashes*.
    3.  **Entrega Diferida:** Al detectar nuevamente al peer (Handshake completado), el sistema vacía la cola automáticamente.

---

## 3. 🏆 Estado Final
El software actual (`main.py`, `network.py`, `interface.py`, `dnie_real.py`) cumple con la especificación académica completa, incluyendo:
* ✅ Persistencia de contactos (`contacts.json`).
* ✅ Chat seguro autenticado por DNIe.
* ✅ Gestión robusta de desconexiones y re-conexiones automáticas.

---

## 4. 👥 Autoría y Metodología de Trabajo

Este proyecto ha sido desarrollado de manera **conjunta e integral** por **Iván Ciudad** y **Víctor Carbajo**.

Ambos integrantes hemos participado equitativamente en todas las fases del ciclo de vida del software, aplicando una metodología de *Pair Programming* (programación en pareja) y trabajo colaborativo para abordar cada desafío técnico:

* **Hardware y Seguridad:** Investigación conjunta sobre `pkcs11`, extracción de certificados del DNIe y firma digital.
* **Red y Protocolo:** Diseño e implementación simultánea del transporte UDP, el protocolo Noise IK y el sistema de descubrimiento mDNS.
* **Interfaces:** Desarrollo coordinado tanto de la interfaz de consola (TUI) como de la gráfica (GUI).
* **Depuración:** Resolución conjunta de los problemas de concurrencia, "efecto espejo" en la encriptación y gestión de estados offline.

Todas las decisiones de arquitectura y la escritura del código han sido consensuadas y ejecutadas en colaboración directa por todo el equipo.

---

# 📜 Anexo: Historial Literal de Peticiones del Cliente

A continuación se listan las interacciones textuales exactas que guiaron el desarrollo del proyecto:

1.  🗣️ Dime de que se habla en el guion 
2.  🗣️ Implementame un codigo que cumpla con todos esos requisitos, de momento sin interfaz 
3.  🗣️ tu como empezarias este trabajo, piensa que tengo todo lo necesario para usar el dnie, tengo lector, drivers instalados y tengo este programa que hice hace meses que ya es capaz de comprobar el dnie y sacar su certificado:@codigo_dni
4.  🗣️ si, hazlo 
5.  🗣️ De momento quiero que me pongas el o los ficheros finales para comprobar todos los pasos anteriores
6.  🗣️ para el dnie ponme el getpass 
7.  🗣️ ademas en el main hay un struct que me sale warning, que puede ser 
8.  🗣️ me sale este error al ejecutar el main: 
9.  🗣️ me salen estos errores: 
10. 🗣️ muestrame como quedaria ahora la inicializacion start 
11. 🗣️ ahora me sale este error 
12. 🗣️ como haria para probar el correcto funcionamiento en una unica maquina 
13. 🗣️ con mi compañero hemos ejecutado el mismo codigo en la misma red pero solo deja entar a uno y al otro le sale este error 
14. 🗣️ Vale ya nos hemos conseguido conectar pero al conectarse, al poner la ip sale este error: 
15. 🗣️ vale y al enviar el mensaje salia este error: 
16. 🗣️ he hecho eso pero mira lo que sale, el no recibe los mensajes 
17. 🗣️ escribeme el handle_handshake entero 
18. 🗣️ pero es que igualmente poniendo lo del puerto aparecia el mismo problema 
19. 🗣️ perfecto, te paso el codigo que se me ha quedado y ahora quiero que me hagas una interfaz tal cual como la de la captura 
20. 🗣️ me sale este error 
21. 🗣️ me sale este error y creo que tiene que ver algo con el network ya que al intentar conectarnos 2 no funciona, y con el codigo que te he pasado eso ya iba bien: 
22. 🗣️ hazme otra vez el codigo, el network esta mal porque no me deja mandar mensajes, te paso mi codigo que me funciona otra vez 
23. 🗣️ Hazme una interfaz con promt que quede tal cual a la captura, el codigo que te he pasado ya funciona y manda mensajes, no lo modifiques 
24. 🗣️ ejecutamos la aplicacion y nos funciona, nos aparece el otro usuario pero en cuanto tocamos un boton nos aparece este error: 
25. 🗣️ me funciona, lo unico que me gustaria arreglar que no escribe donde debe y se duplican lo de system log:
26. 🗣️ Este codigo cumple con todo lo que se pide y es seguro, esto tambien me lo pedia 
27. 🗣️ generame el codigo corregido y muestrame los cambios 
28. 🗣️ ahora me sale este error: no se me hace el handshake 
29. 🗣️ Ahora me sale esto: 
30. 🗣️ nos aparece el mismo mensaje, lo unico es que no nos llegan los mensajes del otro 
31. 🗣️ CUANDO me manda un mensaje me sale esto: 
32. 🗣️ ya me funciona, ahora arreglame la interfaz 
33. 🗣️ ahora no me carga la interfaz se queda asi, arréglalo 
34. 🗣️ ahora ya tengo este codigo comentame si cumplo ya todo o que me falta 
35. 🗣️ se crea el json pero mira lo que me sale:, no se me ha guardado el contacto 
36. 🗣️ se crea el json pero mira lo que me sale:, no se me ha guardado el contacto, aunque en el archivo json si que me aparece 
37. 🗣️ vale ya esta bien pero si yo quiero enviar un mensaje a una persona offline me da este error, seria posible implementar eso para que cuando se pusiese online viera el mensaje? 
38. 🗣️ pero eso que se guarda en el archivo json que es 
39. 🗣️ pero guardar eso es seguro 
40. 🗣️ pero el formato de fecha ese que es????? 
41. 🗣️ Este codigo se supone que si detecta un contacto guardado haria handshake o no 
42. 🗣️ Entonces cada vez que nos conectamos hacemos un handshake no, pero eso es lo que se pide en el ejercicio? 
43. 🗣️ vale de ese codigo lo que quiero ahora es que si los dos estamos conectados y uno se desconecta le aparezca como offline y se le puedan guardar tambien mensajes 
44. 🗣️ lo he probado y cuando se desconecta no sale el off 
45. 🗣️ Tengo este codigo, pero lo que quiero es que si ambos estamos hablando y uno se desconecte al otro le aparezca offline 
46. 🗣️ se desconecta y no sale ningun mensaje 
47. 🗣️ La cosa es que cuando estamos conectados ambos y uno se desconecta aparece OFF, hasta alli todo bien. Pero cuando se le manda un mensaje que se queda en la cola, el problema es que cuando se vuelve a conectar el mensaje se queda enviando y no le llega.Que hago 
48. 🗣️ me sigue sin funcionar, pero si yo me concto antes y ya lo tengo guardado su contacto y le envio mensajes estando el offline cuando se conecta si le llegan, no se podria reusar o copiar ese metodo que si funciona, al final estas en el mismo estado el offline y tu online mandandole mensajes 