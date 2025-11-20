import flet as ft
import asyncio
from dnie_real import DNIeReal as DNIeManager
from network import CompleteNetwork
import threading

# --- ESTADO GLOBAL DE LA APLICACIÓN ---
# Guardaremos aquí la información necesaria para la interfaz
class AppState:
    def __init__(self):
        self.network = None
        self.dnie = None
        self.my_name = ""
        self.current_chat_fp = None  # Fingerprint del chat abierto
        self.messages_history = {}   # {fp_contacto: [(es_mio, texto, nombre_emisor), ...]}
        self.contacts_list_view = ft.ListView(expand=True, spacing=10, padding=10)
        self.chat_view = ft.ListView(
            expand=True, spacing=10, padding=20, auto_scroll=True
        )

state = AppState()

# --- COMPONENTES VISUALES ---

def get_message_bubble(text, is_me, sender_name):
    """Crea un globo de mensaje estilo chat"""
    return ft.Row(
        controls=[
            ft.Container(
                content=ft.Column(
                    [
                        ft.Text(sender_name, size=12, color=ft.colors.GREY_400 if is_me else ft.colors.BLUE_200, weight=ft.FontWeight.BOLD),
                        ft.Text(text, size=16, color=ft.colors.WHITE),
                    ],
                    spacing=2
                ),
                bgcolor=ft.colors.BLUE_GREY_900 if is_me else ft.colors.indigo_900,
                padding=ft.padding.all(15),
                border_radius=ft.border_radius.only(
                    top_left=15, top_right=15,
                    bottom_left=15 if is_me else 0,
                    bottom_right=0 if is_me else 15
                ),
                constraints=ft.BoxConstraints(max_width=400), # Ancho máximo del globo
            ),
        ],
        # Alinear a la derecha si es mío, izquierda si es del otro
        alignment=ft.MainAxisAlignment.END if is_me else ft.MainAxisAlignment.START,
    )

def get_contact_card(peer_info, page):
    """Crea una tarjeta para un contacto en la lista lateral"""
    fp = peer_info['fingerprint']
    name = state.network._get_clean_name(fp)
    
    def on_click(e):
        state.current_chat_fp = fp
        update_chat_view(page)
        page.update()
        
    # Color diferente si es el chat seleccionado
    bg_color = ft.colors.BLUE_GREY_800 if state.current_chat_fp == fp else ft.colors.TRANSPARENT
    
    return ft.Container(
        content=ft.Row(
            [
                ft.Icon(ft.icons.PERSON_ROUNDED, color=ft.colors.BLUE_200),
                ft.Column(
                    [
                        ft.Text(name, weight=ft.FontWeight.BOLD, size=16),
                        ft.Text("Conectado", size=12, color=ft.colors.GREEN_400),
                    ],
                    spacing=2
                )
            ],
            alignment=ft.MainAxisAlignment.START,
        ),
        padding=ft.padding.all(15),
        border_radius=10,
        bgcolor=bg_color,
        ink=True, # Efecto visual al hacer click
        on_click=on_click,
    )

# --- FUNCIONES LÓGICAS ---

def update_contacts_list(page):
    """Refresca la lista lateral de contactos"""
    state.contacts_list_view.controls.clear()
    peers = state.network.get_peers()
    if not peers:
         state.contacts_list_view.controls.append(
             ft.Container(content=ft.Text("Esperando contactos...", italic=True, color=ft.colors.GREY), padding=20)
         )
    else:
        for peer in peers:
            state.contacts_list_view.controls.append(get_contact_card(peer, page))
    page.update()

def update_chat_view(page):
    """Refresca el panel central con los mensajes del chat actual"""
    state.chat_view.controls.clear()
    if not state.current_chat_fp:
        state.chat_view.controls.append(
             ft.Container(
                 content=ft.Text("Selecciona un contacto para chatear", size=20, color=ft.colors.GREY),
                 alignment=ft.alignment.center, expand=True
             )
        )
        return

    history = state.messages_history.get(state.current_chat_fp, [])
    for is_me, text, sender_name in history:
        state.chat_view.controls.append(get_message_bubble(text, is_me, sender_name))
    page.update()

# --- CALLBACKS PARA LA RED ---
# Estas funciones son llamadas por network.py cuando pasan cosas

def on_message_received_callback(page, remote_fp, text, sender_name):
    """Se llama cuando llega un mensaje nuevo"""
    # Añadir al historial
    if remote_fp not in state.messages_history:
        state.messages_history[remote_fp] = []
    state.messages_history[remote_fp].append((False, text, sender_name))
    
    # Si el chat está abierto, actualizar la vista
    if state.current_chat_fp == remote_fp:
        update_chat_view(page)
        page.update()

def on_peer_discovered_callback(page, peer_info):
    """Se llama cuando se encuentra un nuevo usuario"""
    update_contacts_list(page)

# --- TAREA ASÍNCRONA PRINCIPAL ---

async def start_backend(page: ft.Page, status_text: ft.Text):
    """Inicia el DNI y la red en segundo plano"""
    state.dnie = DNIeManager()
    try:
        # 1. Leer DNI
        status_text.value = "🔍 Leyendo DNIe... (Introduce el PIN si se pide)"
        page.update()
        cert, _ = state.dnie.get_certificate()
        state.my_name = cert.subject.get_attributes_for_oid(
            state.dnie.x509.NameOID.COMMON_NAME)[0].value
        # Limpiar nombre propio también
        state.my_name = state.my_name.replace("(AUTENTICACIÓN)", "").replace("(FIRMA)", "").strip()
        
        status_text.value = f"✅ Identificado como: {state.my_name}"
        status_text.color = ft.colors.GREEN_400
        page.update()
        await asyncio.sleep(1)

        # 2. Iniciar Red
        state.network = CompleteNetwork(state.dnie)
        
        # --- MONKEY PATCHING ---
        # Inyectamos nuestras funciones de la GUI en la clase de red existente
        # para que nos avise en lugar de hacer print()
        original_handle_text = state.network._handle_text
        original_add_peer = state.network.add_discovered_peer

        def new_handle_text(payload, remote_fp):
            # Llamamos al original para que haga la desencriptación
            # ¡Esto es un truco avanzado para no tocar network.py!
            try:
                decrypted = state.network.noise.decrypt_message(payload, remote_fp)
                import msgpack
                data = msgpack.unpackb(decrypted, raw=False)
                clean_name = state.network._get_clean_name(remote_fp)
                text = data.get('text')
                # Avisar a la GUI
                on_message_received_callback(page, remote_fp, text, clean_name)
            except:
                print("Error en hook de mensaje")

        def new_add_peer(info):
            original_add_peer(info)
            on_peer_discovered_callback(page, info)

        state.network._handle_text = new_handle_text
        state.network.add_discovered_peer = new_add_peer
        # -----------------------

        status_text.value = "🚀 Iniciando red P2P..."
        page.update()
        await state.network.start(state.my_name)
        status_text.value = f"🌐 Red lista. Eres: {state.my_name}"
        page.update()

        # Bucle infinito para mantener la red viva
        while True: await asyncio.sleep(1)

    except Exception as e:
        status_text.value = f"❌ Error: {e}"
        status_text.color = ft.colors.RED
        page.update()

# --- PUNTO DE ENTRADA DE LA APLICACIÓN ---

def main(page: ft.Page):
    page.title = "DNIe Secure Chat"
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 0
    page.bgcolor = ft.colors.BLACK

    # --- Controles de la UI principal ---
    status_text = ft.Text("Iniciando...", color=ft.colors.BLUE_200)
    
    message_input = ft.TextField(
        hint_text="Escribe un mensaje...",
        border_radius=30,
        filled=True,
        bgcolor=ft.colors.GREY_900,
        expand=True,
        on_submit=lambda e: send_btn.on_click(e) # Enviar al pulsar Enter
    )

    async def send_message_click(e):
        if not state.current_chat_fp or not message_input.value: return
        
        text = message_input.value
        target_fp = state.current_chat_fp
        message_input.value = "" # Limpiar input
        page.update()

        # Enviar por red (esto es async, así que lo lanzamos como tarea)
        async def send_task():
            ok = await state.network.send_message(target_fp, text)
            if ok:
                # Añadir a mi historial y actualizar vista
                if target_fp not in state.messages_history:
                    state.messages_history[target_fp] = []
                state.messages_history[target_fp].append((True, text, "Yo"))
                update_chat_view(page)
            
        asyncio.create_task(send_task())

    send_btn = ft.IconButton(
        icon=ft.icons.SEND_ROUNDED,
        icon_color=ft.colors.BLUE_400,
        bgcolor=ft.colors.BLUE_GREY_900,
        on_click=send_message_click
    )
    
    # --- Layout Principal ---
    
    # Panel Izquierdo (Contactos)
    left_panel = ft.Container(
        width=350,
        bgcolor=ft.colors.GREY_900,
        padding=20,
        content=ft.Column(
            [
                ft.Text("Chats", size=28, weight=ft.FontWeight.BOLD),
                ft.Divider(color=ft.colors.GREY_800),
                state.contacts_list_view, # La lista que se actualiza
                ft.Divider(color=ft.colors.GREY_800),
                ft.Row([
                    ft.Icon(ft.icons.VERIFIED_USER_ROUNDED, color=ft.colors.GREEN),
                    status_text # Barra de estado inferior
                ], alignment=ft.MainAxisAlignment.CENTER)
            ]
        )
    )

    # Panel Derecho (Chat)
    right_panel = ft.Container(
        expand=True,
        bgcolor=ft.colors.BLACK,
        padding=ft.padding.only(left=20, right=20, bottom=20, top=10),
        content=ft.Column(
            [
                # Área de mensajes (scrollable)
                ft.Container(
                    content=state.chat_view,
                    expand=True,
                ),
                # Barra de entrada
                ft.Row(
                    [message_input, send_btn],
                    alignment=ft.MainAxisAlignment.CENTER,
                )
            ]
        )
    )

    # Ensamblar todo
    layout = ft.Row(
        [left_panel, ft.VerticalDivider(width=1, color=ft.colors.GREY_800), right_panel],
        expand=True,
        spacing=0
    )
    
    page.add(layout)
    
    # Iniciar la vista del chat vacía
    update_chat_view(page)

    # Lanzar la tarea en segundo plano que arranca el backend
    page.run_task(start_backend, page, status_text)

if __name__ == "__main__":
    # Ejecutar la aplicación de escritorio
    ft.app(target=main)