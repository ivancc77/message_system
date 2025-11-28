import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
import asyncio
import threading
from datetime import datetime
import queue
import msgpack # Necesario para desempaquetar mensajes en la GUI

# Backend (Tus archivos originales)
from dnie_real import DNIeReal as DNIeManager
from network import CompleteNetwork

# --- TEMA OSCURO PROFESIONAL (Estilo Discord/Telegram) ---
COL_BG_MAIN = "#0f0f0f"      # Fondo negro casi puro
COL_SIDEBAR = "#1b1b1b"      # Gris muy oscuro
COL_HEADER = "#202020"       # Cabecera
COL_INPUT_AREA = "#202020"   # Área de escribir
COL_INPUT_BOX = "#2b2b2b"    # Caja de texto
COL_ACCENT = "#0088cc"       # Azul Telegram
COL_TEXT_WHITE = "#ffffff"
COL_TEXT_GREY = "#aaaaaa"
COL_UNREAD = "#ff9800"       # Naranja para no leídos
COL_OFFLINE = "#555555"      # Gris para usuarios desconectados
COL_ONLINE = "#4caf50"       # Verde para online

# Colores de Burbujas
BUBBLE_ME = "#2b5278"        # Azul oscuro
BUBBLE_THEM = "#182533"      # Gris oscuro

# --- CLASE ADAPTADORA DE RED ---
class GuiNetwork(CompleteNetwork):
    """
    Extiende la red para comunicarse con la GUI mediante una Cola (Queue)
    en lugar de hacer prints a consola.
    """
    def __init__(self, dnie, gui_queue):
        super().__init__(dnie)
        self.gui_queue = gui_queue

    def add_discovered_peer(self, info):
        # Lógica original (añadir a diccionarios)
        super().add_discovered_peer(info)
        # Notificar a la GUI
        self.gui_queue.put(("peer_update", None))

    def remove_discovered_peer(self, instance_name):
        # Lógica original (borrar de diccionarios)
        super().remove_discovered_peer(instance_name)
        # Notificar a la GUI
        self.gui_queue.put(("peer_update", None))

    def _handle_text(self, payload, remote_fp):
        """
        Sobrescribe el manejo de texto para enviarlo a la ventana Tkinter
        en lugar de imprimirlo.
        """
        try:
            # 1. Desencriptar (usando la lógica de NoiseIKProtocol)
            decrypted = self.noise.decrypt_message(payload, remote_fp)
            
            # 2. Desempaquetar msgpack
            try:
                data = msgpack.unpackb(decrypted, raw=False)
            except:
                return # Error de formato

            text = data.get('text')
            
            # 3. Enviar a la GUI
            # Necesitamos el nombre para mostrarlo bonito
            name = self._get_clean_name(remote_fp)
            self.gui_queue.put(("msg", (remote_fp, name, text)))
            
        except Exception as e:
            # Si falla la desencriptación, lo ignoramos o notificamos error silencioso
            pass

# --- INTERFAZ GRÁFICA ---
class ModernDNIeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DNIe Messenger P2P (Secure)")
        self.root.geometry("1100x800")
        self.root.configure(bg=COL_BG_MAIN)

        # Estado
        self.network = None
        self.dnie = None
        self.my_name = ""
        self.loop = None 
        self.current_chat_fp = None
        self.messages_history = {} 
        self.gui_queue = queue.Queue()
        self.stop_event = threading.Event()

        # Fuentes
        self.f_msg = ("Segoe UI Emoji", 11)
        self.f_time = ("Arial", 8)
        self.f_bold = ("Segoe UI", 11, "bold")

        self.setup_ui()
        
        # Protocolo de cierre
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Iniciar bucles
        self.root.after(100, self.process_queue)
        self.root.after(500, self.show_login)

    def setup_ui(self):
        # ==================== SIDEBAR (IZQUIERDA) ====================
        self.sidebar = tk.Frame(self.root, bg=COL_SIDEBAR, width=320)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y)
        self.sidebar.pack_propagate(False)

        # Perfil Propio
        self.profile_frame = tk.Frame(self.sidebar, bg=COL_HEADER, height=70)
        self.profile_frame.pack(fill=tk.X)
        self.profile_lbl = tk.Label(self.profile_frame, text="Conectando...", bg=COL_HEADER, fg=COL_TEXT_WHITE, font=("Segoe UI", 13, "bold"))
        self.profile_lbl.place(relx=0.5, rely=0.5, anchor="center")

        # Lista de Contactos (Scrollable)
        self.contacts_canvas = tk.Canvas(self.sidebar, bg=COL_SIDEBAR, highlightthickness=0)
        self.contacts_frame = tk.Frame(self.contacts_canvas, bg=COL_SIDEBAR)
        self.contacts_scroll = ttk.Scrollbar(self.sidebar, orient="vertical", command=self.contacts_canvas.yview)
        
        self.contacts_canvas.configure(yscrollcommand=self.contacts_scroll.set)
        self.contacts_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.contacts_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.contacts_window = self.contacts_canvas.create_window((0,0), window=self.contacts_frame, anchor="nw")
        self.contacts_frame.bind("<Configure>", self.on_contacts_configure)
        self.contacts_canvas.bind("<Configure>", self.on_contacts_canvas_resize)

        # ==================== CHAT AREA (DERECHA) ====================
        self.chat_panel = tk.Frame(self.root, bg=COL_BG_MAIN)
        self.chat_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Cabecera Chat
        self.header = tk.Frame(self.chat_panel, bg=COL_HEADER, height=60)
        self.header.pack(fill=tk.X)
        self.header_name = tk.Label(self.header, text="Bienvenido", bg=COL_HEADER, fg=COL_TEXT_WHITE, font=("Segoe UI", 16, "bold"))
        self.header_name.pack(side=tk.LEFT, padx=20, pady=10)
        
        self.header_status = tk.Label(self.header, text="", bg=COL_HEADER, fg=COL_TEXT_GREY, font=("Segoe UI", 10))
        self.header_status.pack(side=tk.LEFT, pady=15)

        # --- ZONA DE MENSAJES ---
        self.msg_canvas = tk.Canvas(self.chat_panel, bg=COL_BG_MAIN, highlightthickness=0)
        self.msg_frame = tk.Frame(self.msg_canvas, bg=COL_BG_MAIN)
        self.msg_scroll = ttk.Scrollbar(self.chat_panel, orient="vertical", command=self.msg_canvas.yview)
        
        self.msg_canvas.configure(yscrollcommand=self.msg_scroll.set)
        self.msg_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.msg_canvas.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        
        self.msg_window = self.msg_canvas.create_window((0,0), window=self.msg_frame, anchor="nw")
        
        # Bindings scroll
        self.msg_frame.bind("<Configure>", self.on_msg_frame_configure)
        self.msg_canvas.bind("<Configure>", self.on_msg_canvas_resize)
        self.root.bind_all("<MouseWheel>", self._on_mousewheel)

        # ==================== INPUT AREA (ABAJO) ====================
        self.input_area = tk.Frame(self.chat_panel, bg=COL_INPUT_AREA, height=80)
        self.input_area.pack(fill=tk.X, side=tk.BOTTOM)

        self.input_box = tk.Frame(self.input_area, bg=COL_INPUT_BOX, padx=10, pady=10)
        self.input_box.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        self.entry = tk.Entry(self.input_box, bg=COL_INPUT_BOX, fg="white", font=("Segoe UI", 12), 
                              insertbackground="white", relief=tk.FLAT)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.entry.bind("<Return>", self.send_message)

        self.send_btn = tk.Button(self.input_box, text="➤", bg=COL_ACCENT, fg="white", 
                                  font=("Arial", 12, "bold"), command=self.send_message, 
                                  relief=tk.FLAT, cursor="hand2")
        self.send_btn.pack(side=tk.RIGHT, padx=5)

    # --- SCROLLING MAGIC ---
    def on_contacts_configure(self, event):
        self.contacts_canvas.configure(scrollregion=self.contacts_canvas.bbox("all"))
    
    def on_contacts_canvas_resize(self, event):
        self.contacts_canvas.itemconfigure(self.contacts_window, width=event.width)

    def on_msg_frame_configure(self, event):
        self.msg_canvas.configure(scrollregion=self.msg_canvas.bbox("all"))
    
    def on_msg_canvas_resize(self, event):
        self.msg_canvas.itemconfigure(self.msg_window, width=event.width)
        
    def _on_mousewheel(self, event):
        self.msg_canvas.yview_scroll(int(-1*(event.delta/120)), "units")

    def scroll_to_bottom(self):
        self.msg_canvas.update_idletasks()
        self.msg_canvas.yview_moveto(1.0)

    # --- DIBUJAR MENSAJES ---
    def draw_bubble(self, text, is_me, name, time_str):
        row = tk.Frame(self.msg_frame, bg=COL_BG_MAIN)
        row.pack(fill=tk.X, pady=5, padx=20)

        bg_color = BUBBLE_ME if is_me else BUBBLE_THEM
        side = tk.RIGHT if is_me else tk.LEFT
        
        bubble = tk.Frame(row, bg=bg_color)
        bubble.pack(side=side)

        content = tk.Frame(bubble, bg=bg_color, padx=15, pady=10)
        content.pack()

        if not is_me:
            lbl_name = tk.Label(content, text=name, bg=bg_color, fg=COL_ACCENT, font=self.f_bold, anchor="w")
            lbl_name.pack(fill=tk.X, pady=(0, 2))

        lbl_text = tk.Label(content, text=text, bg=bg_color, fg=COL_TEXT_WHITE, 
                            font=self.f_msg, justify=tk.LEFT, wraplength=400)
        lbl_text.pack(anchor="w")

        lbl_time = tk.Label(content, text=time_str, bg=bg_color, fg=COL_TEXT_GREY, font=self.f_time)
        lbl_time.pack(anchor="e", pady=(2,0))

        self.scroll_to_bottom()

    # --- LOGICA CONTACTOS MEJORADA ---
    def refresh_contact_list(self):
        if not self.network: return

        # Limpiar lista anterior
        for widget in self.contacts_frame.winfo_children():
            widget.destroy()
            
        # Obtener peers (Online + Offline) desde la lógica de network.py
        peers = self.network.get_peers()
        
        for peer in peers:
            fp = peer['fingerprint']
            # network.py ya gestiona el nombre, pero limpiamos el (OFF) para el display
            raw_name = peer.get('name', 'Unknown')
            name = raw_name.replace("(AUTENTICACIÓN)", "").replace("(FIRMA)", "").replace("(OFF)", "").strip()
            
            # Determinar estado
            is_offline = "(OFF)" in raw_name or peer.get('ip') == 'Offline'
            
            # Verificar mensajes no leídos
            has_unread = False
            if fp in self.messages_history and fp != self.current_chat_fp:
                # Comprobamos si el último msg fue de ellos
                last_msg = self.messages_history[fp][-1]
                if not last_msg[0]: # is_me es False
                     has_unread = True # (Simplificación, idealmente llevar cuenta)
                
            self.create_contact_item(name, fp, has_unread, is_offline)

    def create_contact_item(self, name, fp, unread=False, is_offline=False):
        # Color de fondo según estado
        bg_color = "#2c2c2c" if unread else COL_SIDEBAR
        
        card = tk.Frame(self.contacts_frame, bg=bg_color, height=70, cursor="hand2")
        card.pack(fill=tk.X, pady=1)
        
        # Estado Visual (Online/Offline) en el nombre
        fg_color = COL_OFFLINE if is_offline else (COL_TEXT_WHITE if unread else "#e0e0e0")
        
        def on_enter(e): 
            if fp != self.current_chat_fp: card.config(bg="#2b2b2b")
        def on_leave(e): 
            if fp == self.current_chat_fp: card.config(bg="#2b5278") 
            elif unread: card.config(bg="#2c2c2c")
            else: card.config(bg=COL_SIDEBAR)
        
        card.bind("<Enter>", on_enter)
        card.bind("<Leave>", on_leave)

        # Avatar
        initial = name[0].upper() if name else "?"
        # Color del avatar: Naranja (Unread), Verde (Online), Gris (Offline)
        if unread: av_bg = COL_UNREAD
        elif is_offline: av_bg = "#333333"
        else: av_bg = COL_ONLINE
        
        avatar = tk.Label(card, text=initial, bg=av_bg, fg="white", width=3, height=1, font=("Arial", 16, "bold"))
        avatar.pack(side=tk.LEFT, padx=15, pady=15)
        
        # Nombre
        font_style = self.f_bold if unread else ("Segoe UI", 11)
        lbl = tk.Label(card, text=name, bg=bg_color, fg=fg_color, font=font_style)
        lbl.pack(side=tk.LEFT, pady=20)
        
        # Indicador visual Offline
        if is_offline:
            status = tk.Label(card, text="💤", bg=bg_color, fg=COL_OFFLINE, font=("Segoe UI", 10))
            status.pack(side=tk.RIGHT, padx=10)
        elif unread:
             dot = tk.Label(card, text="●", bg=bg_color, fg=COL_UNREAD, font=("Arial", 12))
             dot.pack(side=tk.RIGHT, padx=10)

        # Click events
        for widget in [card, avatar, lbl]:
            widget.bind("<Button-1>", lambda e, f=fp, n=name, off=is_offline: self.select_chat(f, n, off))

    def select_chat(self, fp, name, is_offline):
        self.current_chat_fp = fp
        self.header_name.config(text=name)
        
        if is_offline:
            self.header_status.config(text="Desconectado (Mensajes se encolarán)", fg="#ff5555")
        else:
            self.header_status.config(text="En línea y Seguro", fg="#55ff55")
        
        # Refrescar lista para quitar alertas
        self.refresh_contact_list()
        
        # Limpiar chat visual
        for widget in self.msg_frame.winfo_children():
            widget.destroy()
            
        # Cargar historial
        history = self.messages_history.get(fp, [])
        for is_me, text, t in history:
            sender = "Yo" if is_me else name
            self.draw_bubble(text, is_me, sender, t)

    # --- CORE LOGIC & THREADING ---
    def show_login(self):
        # Pedir PIN de forma segura
        pin = simpledialog.askstring("DNIe", "Introduce tu PIN del DNIe:", show='*')
        if pin: 
            threading.Thread(target=self.backend_thread, args=(pin,), daemon=True).start()
        else: 
            self.root.quit()

    def backend_thread(self, pin):
        """Hilo secundario donde vive asyncio y la red"""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        
        self.dnie = DNIeManager()
        
        try:
            # 1. Inicializar DNIe
            if not self.loop.run_until_complete(self.dnie.initialize(pin, interactive=False)):
                self.gui_queue.put(("error", "Fallo al leer DNIe o PIN incorrecto."))
                return
            
            # 2. Configurar Red con la clase adaptada
            self.my_name = self.dnie.get_user_name().replace("(AUTENTICACIÓN)","").strip()
            self.gui_queue.put(("login_ok", self.my_name))
            
            self.network = GuiNetwork(self.dnie, self.gui_queue)
            
            # 3. Arrancar Servidor
            self.loop.run_until_complete(self.network.start(self.my_name))
            
            # 4. Mantener vivo hasta cierre
            # Usamos un bucle ligero revisando el evento de parada
            while not self.stop_event.is_set():
                self.loop.run_until_complete(asyncio.sleep(0.5))
                
            # 5. Parada limpia
            self.loop.run_until_complete(self.network.stop())
            
        except Exception as e:
            print(f"CRASH BACKEND: {e}")
            self.gui_queue.put(("error", f"Error backend: {e}"))
        finally:
            self.loop.close()

    def process_queue(self):
        """Hilo principal (GUI) consumiendo eventos del backend"""
        try:
            while True:
                type_, data = self.gui_queue.get_nowait()
                
                if type_ == "login_ok": 
                    self.profile_lbl.config(text=data)
                    
                elif type_ == "peer_update": 
                    self.refresh_contact_list()
                    
                elif type_ == "msg":
                    fp, name, txt = data
                    # Si recibimos mensaje, actualizamos historial
                    self.add_msg(fp, txt, False, name)
                    # Si no es el chat actual, la lista se refresca para mostrar alerta
                    if fp != self.current_chat_fp:
                        self.refresh_contact_list()
                        
                elif type_ == "error": 
                    messagebox.showerror("Error", data)
                    self.root.quit()
                    
        except queue.Empty: pass
        
        if not self.stop_event.is_set():
            self.root.after(100, self.process_queue)

    def add_msg(self, fp, text, is_me, name=""):
        t = datetime.now().strftime("%H:%M")
        if fp not in self.messages_history: self.messages_history[fp] = []
        self.messages_history[fp].append((is_me, text, t))
        
        # Solo dibujar si es el chat activo
        if self.current_chat_fp == fp:
            self.draw_bubble(text, is_me, name, t)

    def send_message(self, event=None):
        text = self.entry.get().strip()
        if not text or not self.current_chat_fp: return
        self.entry.delete(0, tk.END)
        
        # Enviar asíncronamente desde el hilo GUI al hilo asyncio
        if self.network and self.loop:
            asyncio.run_coroutine_threadsafe(
                self.network.send_message(self.current_chat_fp, text), self.loop
            )
        
        # Añadir visualmente (optimista)
        self.add_msg(self.current_chat_fp, text, True, "Yo")

    def on_close(self):
        """Manejador de cierre de ventana"""
        if messagebox.askokcancel("Salir", "¿Cerrar DNIe Messenger?"):
            self.stop_event.set() # Avisar al hilo backend
            # Dar un momento para que limpie conexiones mDNS
            self.root.destroy()

if __name__ == "__main__":
    # Soporte Windows High DPI
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except: pass

    root = tk.Tk()
    app = ModernDNIeApp(root)
    root.mainloop()