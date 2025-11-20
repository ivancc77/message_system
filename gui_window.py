import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
import asyncio
import threading
from datetime import datetime
import queue

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

# Colores de Burbujas
BUBBLE_ME = "#2b5278"        # Azul oscuro
BUBBLE_THEM = "#182533"      # Gris oscuro

class ModernDNIeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DNIe Messenger P2P")
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

        # Fuentes
        self.f_msg = ("Segoe UI Emoji", 11)
        self.f_time = ("Arial", 8)
        self.f_bold = ("Segoe UI", 11, "bold")

        self.setup_ui()
        
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

    # --- LOGICA CONTACTOS MEJORADA (Con notificaciones) ---
    def refresh_contact_list(self):
        for widget in self.contacts_frame.winfo_children():
            widget.destroy()
            
        for peer in self.network.get_peers():
            fp = peer['fingerprint']
            name = self.network._get_clean_name(fp)
            
            # Verificar mensajes no leídos
            has_unread = False
            if fp in self.messages_history and fp != self.current_chat_fp:
                has_unread = True
                
            self.create_contact_item(name, fp, has_unread)

    def create_contact_item(self, name, fp, unread=False):
        # Color de fondo según estado
        bg_color = "#2c2c2c" if unread else COL_SIDEBAR
        
        card = tk.Frame(self.contacts_frame, bg=bg_color, height=70, cursor="hand2")
        card.pack(fill=tk.X, pady=1)
        
        # Efectos visuales
        def on_enter(e): 
            if fp != self.current_chat_fp: card.config(bg="#2b2b2b")
        def on_leave(e): 
            if fp == self.current_chat_fp: card.config(bg="#2b5278") # Seleccionado
            elif unread: card.config(bg="#2c2c2c") # No leído
            else: card.config(bg=COL_SIDEBAR) # Normal
        
        card.bind("<Enter>", on_enter)
        card.bind("<Leave>", on_leave)

        # Avatar con color de alerta
        initial = name[0].upper() if name else "?"
        avatar_bg = COL_UNREAD if unread else "#555"
        avatar = tk.Label(card, text=initial, bg=avatar_bg, fg="white", width=3, height=1, font=("Arial", 16, "bold"))
        avatar.pack(side=tk.LEFT, padx=15, pady=15)
        
        # Nombre destacado
        fg_color = "white" if unread else "#b0b0b0"
        font_style = self.f_bold if unread else ("Segoe UI", 11)
        
        lbl = tk.Label(card, text=name, bg=bg_color, fg=fg_color, font=font_style)
        lbl.pack(side=tk.LEFT, pady=20)
        
        # Punto de notificación
        if unread:
             dot = tk.Label(card, text="●", bg=bg_color, fg=COL_UNREAD, font=("Arial", 12))
             dot.pack(side=tk.RIGHT, padx=10)
             dot.bind("<Button-1>", lambda e, f=fp, n=name: self.select_chat(f, n))

        # Click events
        for widget in [card, avatar, lbl]:
            widget.bind("<Button-1>", lambda e, f=fp, n=name: self.select_chat(f, n))

    def select_chat(self, fp, name):
        self.current_chat_fp = fp
        self.header_name.config(text=name)
        
        # Al entrar, refrescamos la lista para quitar la marca de "no leído"
        self.refresh_contact_list()
        
        # Limpiar chat visual
        for widget in self.msg_frame.winfo_children():
            widget.destroy()
            
        # Cargar historial
        history = self.messages_history.get(fp, [])
        for is_me, text, t in history:
            # Determinar nombre
            sender = "Yo" if is_me else name
            self.draw_bubble(text, is_me, sender, t)

    # --- CORE LOGIC ---
    def show_login(self):
        pin = simpledialog.askstring("DNIe", "Introduce tu PIN del DNIe:", show='*')
        if pin: threading.Thread(target=self.backend_thread, args=(pin,), daemon=True).start()
        else: self.root.quit()

    def backend_thread(self, pin):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.dnie = DNIeManager()
        
        try:
            if not self.loop.run_until_complete(self.dnie.initialize(pin, interactive=False)):
                self.gui_queue.put(("error", "Fallo DNIe"))
                return
            
            self.my_name = self.dnie.get_user_name().replace("(AUTENTICACIÓN)","").strip()
            self.gui_queue.put(("login_ok", self.my_name))
            
            self.network = CompleteNetwork(self.dnie)
            
            # Monkey Patching
            orig_peer = self.network.add_discovered_peer
            def gui_msg(payload, fp):
                try:
                    dec = self.network.noise.decrypt_message(payload, fp)
                    import msgpack
                    data = msgpack.unpackb(dec, raw=False)
                    name = self.network._get_clean_name(fp)
                    self.gui_queue.put(("msg", (fp, name, data.get('text'))))
                except: pass
            
            def gui_peer(info):
                orig_peer(info)
                self.gui_queue.put(("peer", None))

            self.network._handle_text = gui_msg
            self.network.add_discovered_peer = gui_peer
            
            self.loop.run_until_complete(self.network.start(self.my_name))
            self.loop.run_forever()
        except Exception as e: print(e)

    def process_queue(self):
        try:
            while True:
                type_, data = self.gui_queue.get_nowait()
                if type_ == "login_ok": 
                    self.profile_lbl.config(text=data)
                elif type_ == "peer": 
                    # Refrescamos lista (que ya gestiona los estados de no leído)
                    self.refresh_contact_list()
                elif type_ == "msg":
                    fp, name, txt = data
                    self.add_msg(fp, txt, False, name)
                    # IMPORTANTE: Refrescar lista para mostrar alerta si es chat no activo
                    if fp != self.current_chat_fp:
                        self.refresh_contact_list()
                elif type_ == "error": 
                    messagebox.showerror("Error", data)
        except queue.Empty: pass
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
        
        asyncio.run_coroutine_threadsafe(
            self.network.send_message(self.current_chat_fp, text), self.loop
        )
        self.add_msg(self.current_chat_fp, text, True, "Yo")

if __name__ == "__main__":
    root = tk.Tk()
    app = ModernDNIeApp(root)
    root.mainloop()