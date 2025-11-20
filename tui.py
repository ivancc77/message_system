"""
tui.py - Interfaz Gráfica de Texto estilo Telegram
Implementación visual usando prompt_toolkit
"""
import asyncio
from prompt_toolkit.application import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout.containers import HSplit, VSplit, Window, WindowAlign
from prompt_toolkit.layout.controls import FormattedTextControl, BufferControl
from prompt_toolkit.layout.layout import Layout
from prompt_toolkit.layout.dimension import D
from prompt_toolkit.styles import Style
from prompt_toolkit.widgets import Frame, TextArea
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.document import Document
from prompt_toolkit.formatted_text import HTML

class TelegramStyleTUI:
    def __init__(self, messenger_app):
        self.app_logic = messenger_app
        self.network = messenger_app.network
        self.selected_peer_index = 0
        self.input_mode = True  # True = Escribiendo, False = Navegando lista contactos
        
        # --- Estilos Visuales (Colores de la imagen) ---
        self.style = Style.from_dict({
            'frame.label': '#28a745 bold',  # Títulos en verde
            'border': '#888888',            # Bordes grises
            'sidebar.selected': 'reverse',   # Selección invertida
            'msg.me': '#00afff',            # Mis mensajes (Azul)
            'msg.peer': '#ffffff',          # Mensajes peer (Blanco)
            'header': '#00ff00 bold',       # Cabecera verde
            'time': '#444444 italic',       # Hora gris
        })

        # --- Componentes ---
        
        # 1. Lista de Chats (Izquierda Arriba)
        self.chat_list_control = FormattedTextControl(
            text=self._get_chat_list_text,
            focusable=True,
            key_bindings=self._get_list_keybindings()
        )
        self.chat_window = Frame(
            Window(self.chat_list_control),
            title="Chats",
            style="class:sidebar"
        )

        # 2. Contactos / Otros (Izquierda Abajo)
        self.other_window = Frame(
            Window(FormattedTextControl(HTML("📖 Contacts\n⚙️ Settings"))),
            title="Other",
            height=D(preferred=6)
        )

        # 3. Ventana de Mensajes (Derecha Centro)
        self.msg_control = FormattedTextControl(text=self._get_messages_text)
        self.msg_window = Frame(
            Window(self.msg_control, wrap_lines=True, always_hide_cursor=True),
            title=self._get_header_title
        )

        # 4. Área de Input (Derecha Abajo)
        self.input_buffer = Buffer(accept_handler=self._handle_input)
        self.input_window = Frame(
            Window(BufferControl(buffer=self.input_buffer), height=1),
            title="Input",
            height=D(min=4, max=4)
        )

        # --- Layout General ---
        # Izquierda: Chats + Others
        left_pane = HSplit([
            self.chat_window,
            self.other_window
        ], width=D(preferred=25))

        # Derecha: Header + Mensajes + Input
        right_pane = HSplit([
            self.msg_window,
            self._get_status_bar(),
            self.input_window
        ])

        body = VSplit([
            left_pane,
            right_pane
        ])
        
        # Barra superior global
        root_container = HSplit([
            Window(FormattedTextControl(f" TelegramTUI v0.6 [{self.network.my_fingerprint[:8]}]"), height=1, style="bg:#333333 #ffffff"),
            body
        ])

        # Keybindings globales
        kb = KeyBindings()
        @kb.add('c-c')
        def _(event):
            event.app.exit()

        @kb.add('tab')
        def _(event):
            self.input_mode = not self.input_mode
            if self.input_mode:
                event.app.layout.focus(self.input_window)
            else:
                event.app.layout.focus(self.chat_window)

        self.application = Application(
            layout=Layout(root_container, focused_element=self.input_window),
            key_bindings=kb,
            style=self.style,
            full_screen=True,
            mouse_support=True,
            refresh_interval=0.5 # Refresco para nuevos mensajes
        )

    def _get_list_keybindings(self):
        kb = KeyBindings()
        @kb.add('up')
        def _(event):
            peers = self.network.get_peers()
            if self.selected_peer_index > 0:
                self.selected_peer_index -= 1
        
        @kb.add('down')
        def _(event):
            peers = self.network.get_peers()
            if self.selected_peer_index < len(peers) - 1:
                self.selected_peer_index += 1
        return kb

    def _get_header_title(self):
        peers = self.network.get_peers()
        if not peers: return "Esperando Peers..."
        if 0 <= self.selected_peer_index < len(peers):
            p = peers[self.selected_peer_index]
            return f"{p['name']} ({p['ip']})"
        return "Desconocido"

    def _get_status_bar(self):
        # Línea fina de estado estilo TelegramTUI
        return Window(
            FormattedTextControl(
                text=HTML(f"<style color='#555555' align='right'>Last seen recently</style>")
            ),
            height=1, align=WindowAlign.RIGHT
        )

    def _get_chat_list_text(self):
        peers = self.network.get_peers()
        result = []
        
        if not peers:
            return HTML("<style color='gray'> Buscando...</style>")

        for i, peer in enumerate(peers):
            name = peer['name']
            # Icono dependiendo de si es el seleccionado
            if i == self.selected_peer_index:
                result.append(HTML(f"<style class='sidebar.selected'>👤 {name}</style>\n"))
            else:
                result.append(HTML(f"👤 {name}\n"))
        return result

    def _get_messages_text(self):
        # Aquí necesitamos un historial real.
        # Como tu clase Network no tiene historial persistente "público",
        # lo simularemos o necesitas añadir un atributo 'history' a tu clase Network
        # Asumiremos que network.history es una lista de dicts: {'sender': fp, 'text': txt, 'is_me': bool}
        
        # NOTA: Debes añadir `self.history = {}` en tu clase CompleteNetwork
        peers = self.network.get_peers()
        if not peers or not (0 <= self.selected_peer_index < len(peers)):
            return ""
            
        current_peer_fp = peers[self.selected_peer_index]['fingerprint']
        
        # Obtener historial del peer seleccionado (implementar en Network)
        msgs = getattr(self.network, 'history', {}).get(current_peer_fp, [])
        
        formatted = []
        for m in msgs:
            if m['is_me']:
                formatted.append(HTML(f"<style class='msg.me'>Yo:</style> {m['text']}\n"))
            else:
                # Simular el estilo visual de la imagen
                formatted.append(HTML(f"<style class='msg.peer'>{m['name']}:</style> {m['text']}\n"))
                
        return formatted

    def _handle_input(self, buff):
        text = buff.text
        if not text: return
        
        peers = self.network.get_peers()
        if peers and 0 <= self.selected_peer_index < len(peers):
            target = peers[self.selected_peer_index]
            
            # Enviar mensaje (Esto es async, lo lanzamos al loop)
            asyncio.create_task(self.network.send_message(target['fingerprint'], text))
            
            # Hack para añadir al historial local inmediatamente
            if not hasattr(self.network, 'history'): self.network.history = {}
            if target['fingerprint'] not in self.network.history: self.network.history[target['fingerprint']] = []
            
            self.network.history[target['fingerprint']].append({
                'name': 'Yo', 'text': text, 'is_me': True
            })

        # Limpiar input
        # buff.reset() # Esto a veces da error en async, mejor usar transform
        return True # Keep text? No.