import flet as ft
import asyncio
from dnie_real import DNIeReal as DNIeManager
from network import CompleteNetwork

# --- ESTADO GLOBAL ---
class AppState:
    def __init__(self):
        self.network = None
        self.dnie = None
        self.my_name = ""
        self.current_chat_fp = None
        self.messages_history = {}
        self.contacts_list_view = ft.ListView(expand=True, spacing=5, padding=10)
        self.chat_view = ft.ListView(
            expand=True, spacing=10, padding=20, auto_scroll=True
        )

state = AppState()

# --- COMPONENTES VISUALES ---

def get_message_bubble(text, is_me, sender_name):
    return ft.Row(
        controls=[
            ft.Container(
                content=ft.Column(
                    [
                        ft.Text(sender_name, size=11, color="grey" if is_me else "blue", weight=ft.FontWeight.BOLD),
                        ft.Text(text, size=15, color="white"),
                    ],
                    spacing=2
                ),
                bgcolor="#263238" if is_me else "#1a237e",
                padding=12,
                border_radius=ft.border_radius.only(
                    top_left=12, top_right=12,
                    bottom_left=12 if is_me else 0,
                    bottom_right=0 if is_me else 12
                ),
                constraints=ft.BoxConstraints(max_width=350),
            ),
        ],
        alignment=ft.MainAxisAlignment.END if is_me else ft.MainAxisAlignment.START,
    )

def get_contact_card(peer_info, page):
    fp = peer_info['fingerprint']
    name = state.network._get_clean_name(fp)
    
    def on_click(e):
        state.current_chat_fp = fp
        # Resetear colores
        for control in state.contacts_list_view.controls:
            control.bgcolor = "transparent"
        e.control.bgcolor = "#37474f"
        e.control.update()
        state.contacts_list_view.update()
        update_chat_view(page)
        
    return ft.Container(
        content=ft.Row(
            [
                ft.Icon(name="person", color="blue"), # FIX: String directo
                ft.Column(
                    [
                        ft.Text(name, weight=ft.FontWeight.BOLD, size=14, overflow=ft.TextOverflow.ELLIPSIS),
                        ft.Text("En línea", size=10, color="green"),
                    ],
                    spacing=0
                )
            ],
        ),
        padding=10,
        border_radius=8,
        ink=True,
        on_click=on_click,
    )

def update_chat_view(page):
    state.chat_view.controls.clear()
    if state.current_chat_fp:
        history = state.messages_history.get(state.current_chat_fp, [])
        for is_me, text, sender_name in history:
            state.chat_view.controls.append(get_message_bubble(text, is_me, sender_name))
    else:
        state.chat_view.controls.append(
             ft.Container(
                 content=ft.Text("Selecciona un contacto a la izquierda", color="grey"),
                 alignment=ft.alignment.center, padding=50
             )
        )
    page.update()

# --- CORE LOGIC ---

def on_message_received(page, remote_fp, text, sender_name):
    if remote_fp not in state.messages_history:
        state.messages_history[remote_fp] = []
    state.messages_history[remote_fp].append((False, text, sender_name))
    if state.current_chat_fp == remote_fp:
        update_chat_view(page)

def on_peer_found(page, info):
    state.contacts_list_view.controls.clear()
    for peer in state.network.get_peers():
        state.contacts_list_view.controls.append(get_contact_card(peer, page))
    page.update()

async def init_system(page, pin, status_lbl):
    try:
        status_lbl.value = "🔌 Conectando con el lector..."
        page.update()
        
        state.dnie = DNIeManager()
        ok = await state.dnie.initialize(pin=pin, interactive=False)
        
        if not ok:
            status_lbl.value = "❌ Error: PIN incorrecto o DNIe no detectado"
            status_lbl.color = "red"
            page.update()
            return False

        status_lbl.value = "✅ DNIe verificado. Iniciando red..."
        status_lbl.color = "green"
        page.update()
        
        state.my_name = state.dnie.get_user_name().replace("(AUTENTICACIÓN)","").strip()
        
        state.network = CompleteNetwork(state.dnie)
        
        # Monkey Patching
        orig_peer = state.network.add_discovered_peer

        def gui_handle_text(payload, fp):
            try:
                decrypted = state.network.noise.decrypt_message(payload, fp)
                import msgpack
                data = msgpack.unpackb(decrypted, raw=False)
                name = state.network._get_clean_name(fp)
                on_message_received(page, fp, data.get('text'), name)
            except: pass

        def gui_add_peer(info):
            orig_peer(info)
            on_peer_found(page, info)

        state.network._handle_text = gui_handle_text
        state.network.add_discovered_peer = gui_add_peer
        
        await state.network.start(state.my_name)
        return True

    except Exception as e:
        status_lbl.value = f"Error crítico: {e}"
        page.update()
        return False

# --- MAIN ---

def main(page: ft.Page):
    page.title = "DNIe Messenger"
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 0
    page.window_width = 1000
    page.window_height = 700
    page.bgcolor = "black"

    # --- UI ELEMENTOS ---
    status_bar = ft.Text("Esperando inicio de sesión...", size=12, color="grey")
    
    txt_msg = ft.TextField(hint_text="Escribe algo...", expand=True, border_radius=20, bgcolor="#212121", border_width=0)
    
    async def send_click(e):
        if not state.current_chat_fp or not txt_msg.value: return
        txt = txt_msg.value
        target = state.current_chat_fp
        txt_msg.value = ""
        page.update()
        
        if await state.network.send_message(target, txt):
            if target not in state.messages_history: state.messages_history[target] = []
            state.messages_history[target].append((True, txt, "Yo"))
            update_chat_view(page)

    # FIX: Iconos como strings
    btn_send = ft.IconButton(icon="send_rounded", icon_color="blue", on_click=lambda e: asyncio.create_task(send_click(e)))

    # --- DIALOGO DE LOGIN (PIN) ---
    pin_input = ft.TextField(label="PIN del DNIe", password=True, text_align=ft.TextAlign.CENTER)
    login_status = ft.Text("", size=12)
    
    async def login_click(e):
        if not pin_input.value:
            login_status.value = "Introduce el PIN"
            login_status.update()
            return
            
        login_dialog.open = False
        page.update()
        
        success = await init_system(page, pin_input.value, status_bar)
        if not success:
            login_status.value = "Fallo de autenticación. Reinicia."
            login_dialog.open = True
            page.update()
        else:
            status_bar.value = f"🟢 Conectado como {state.my_name}"
            page.update()

    login_dialog = ft.AlertDialog(
        modal=True,
        title=ft.Text("Autenticación DNIe"),
        content=ft.Column([
            ft.Icon(name="smart_button", size=50, color="blue"), # FIX: Icono string
            ft.Text("Introduce tu PIN para firmar tu identidad en la red."),
            pin_input,
            login_status
        ], height=200, alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER),
        actions=[
            ft.TextButton("Acceder", on_click=lambda e: asyncio.create_task(login_click(e)))
        ],
        actions_alignment=ft.MainAxisAlignment.CENTER,
    )

    # --- LAYOUT ---
    layout = ft.Row(
        [
            # Panel Izquierdo
            ft.Container(
                width=300, bgcolor="#212121", padding=10,
                content=ft.Column([
                    ft.Text("Contactos", size=20, weight="bold"),
                    ft.Divider(),
                    state.contacts_list_view,
                    ft.Divider(),
                    status_bar
                ])
            ),
            # Panel Derecho
            ft.Container(
                expand=True, bgcolor="black", padding=10,
                content=ft.Column([
                    ft.Container(content=state.chat_view, expand=True),
                    ft.Row([txt_msg, btn_send])
                ])
            )
        ],
        expand=True, spacing=0
    )

    page.add(layout)
    page.dialog = login_dialog
    login_dialog.open = True
    page.update()

if __name__ == "__main__":
    ft.app(target=main)