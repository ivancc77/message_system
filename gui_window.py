import tkinter as tk
from tkinter import ttk, simpledialog, messagebox, scrolledtext
import asyncio
import threading
from datetime import datetime
import queue

# Importamos tu backend
from dnie_real import DNIeReal as DNIeManager
from network import CompleteNetwork

# --- COLORES TEMA OSCURO ---
BG_COLOR = "#121212"
SIDEBAR_COLOR = "#1e1e1e"
CHAT_BG = "#000000"
TEXT_COLOR = "#e0e0e0"
INPUT_BG = "#2c2c2c"
ACCENT_COLOR = "#00e676"   # Verde brillante para estado

class DNIeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DNIe Messenger P2P")
        self.root.geometry("1000x700")
        self.root.configure(bg=BG_COLOR)

        # Estado
        self.network = None
        self.dnie = None
        self.my_name = ""
        self.loop = None # Loop de asyncio
        self.current_chat_fp = None
        self.messages_history = {} # {fp: ["Yo: hola", "El: adios"]}
        
        # Cola para comunicar hilos
        self.gui_queue = queue.Queue()

        # --- ESTILOS ---
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Treeview", 
                        background=SIDEBAR_COLOR, 
                        foreground=TEXT_COLOR, 
                        fieldbackground=SIDEBAR_COLOR,
                        font=('Segoe UI', 10))
        style.map('Treeview', background=[('selected', '#3d3d3d')])

        # --- LAYOUT ---
        
        # 1. Panel Izquierdo (Contactos)
        self.left_frame = tk.Frame(root, bg=SIDEBAR_COLOR, width=250)
        self.left_frame.pack(side=tk.LEFT, fill=tk.Y)
        self.left_frame.pack_propagate(False)

        tk.Label(self.left_frame, text="CONTACTOS", bg=SIDEBAR_COLOR, fg="grey", font=("Arial", 8, "bold")).pack(pady=10)
        
        # Lista de contactos
        self.contacts_list = ttk.Treeview(self.left_frame, columns=("status"), show="tree", selectmode="browse")
        self.contacts_list.pack(fill=tk.BOTH, expand=True, padx=5)
        self.contacts_list.bind("<<TreeviewSelect>>", self.on_contact_select)
        
        # Barra estado inferior
        self.status_lbl = tk.Label(self.left_frame, text="Iniciando...", bg=SIDEBAR_COLOR, fg="orange", font=("Arial", 9))
        self.status_lbl.pack(side=tk.BOTTOM, fill=tk.X, pady=5)

        # 2. Panel Derecho (Chat)
        self.right_frame = tk.Frame(root, bg=CHAT_BG)
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Cabecera del chat
        self.chat_header = tk.Label(self.right_frame, text="Selecciona un chat", bg="#252525", fg="white", font=("Segoe UI", 14), pady=10)
        self.chat_header.pack(fill=tk.X)

        # Área de mensajes (Scrollable)
        self.chat_area = scrolledtext.ScrolledText(self.right_frame, bg=CHAT_BG, fg=TEXT_COLOR, font=("Consolas", 11), state='disabled', borderwidth=0)
        self.chat_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # --- CORRECCIÓN DE ESTILOS AQUÍ ---
        # Usamos lmargin1 (primera linea) y lmargin2 (resto) en lugar de lmargin
        self.chat_area.tag_config("me", foreground="#64b5f6", justify='right', rmargin=10)
        self.chat_area.tag_config("them", foreground="#81c784", justify='left', lmargin1=10, lmargin2=10)
        self.chat_area.tag_config("system", foreground="grey", justify='center')

        # Área de escritura
        self.input_frame = tk.Frame(self.right_frame, bg=SIDEBAR_COLOR, height=60)
        self.input_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.msg_entry = tk.Entry(self.input_frame, bg=INPUT_BG, fg="white", font=("Segoe UI", 12), insertbackground="white", borderwidth=0)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=15, pady=15, ipady=5)
        self.msg_entry.bind("<Return>", self.send_message)

        send_btn = tk.Button(self.input_frame, text="Enviar", bg="#0d47a1", fg="white", command=self.send_message, borderwidth=0, padx=20)
        send_btn.pack(side=tk.RIGHT, padx=10)

        # Iniciar revisión de cola de eventos
        self.root.after(100, self.process_queue)
        
        # Lanzar Login
        self.root.after(500, self.show_login)

    def show_login(self):
        pin = simpledialog.askstring("Acceso DNIe", "Introduce el PIN del DNIe:", show='*')
        if pin:
            # Arrancar hilo de red
            threading.Thread(target=self.start_backend_thread, args=(pin,), daemon=True).start()
        else:
            self.root.quit()

    # --- HILO DE RED (ASYNCIO) ---
    def start_backend_thread(self, pin):
        # Crear nuevo bucle para este hilo
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        
        self.gui_queue.put(("status", ("⏳ Conectando DNIe...", "orange")))
        
        self.dnie = DNIeManager()
        
        # Ejecutar inicialización
        try:
            ok = self.loop.run_until_complete(self.dnie.initialize(pin, interactive=False))
            if not ok:
                self.gui_queue.put(("error", "PIN incorrecto o DNIe no detectado"))
                return
            
            # Limpiar nombre
            raw_name = self.dnie.get_user_name()
            self.my_name = raw_name.replace("(AUTENTICACIÓN)", "").replace("(FIRMA)", "").strip()
            
            self.gui_queue.put(("status", (f"✅ {self.my_name}", ACCENT_COLOR)))
            
            # Iniciar red
            self.network = CompleteNetwork(self.dnie)
            
            # Monkey Patching para capturar eventos
            orig_peer = self.network.add_discovered_peer

            def gui_handle_text(payload, fp):
                try:
                    decrypted = self.network.noise.decrypt_message(payload, fp)
                    import msgpack
                    data = msgpack.unpackb(decrypted, raw=False)
                    text = data.get('text')
                    name = self.network._get_clean_name(fp)
                    # Enviar a la GUI
                    self.gui_queue.put(("msg", (fp, name, text)))
                except: pass

            def gui_add_peer(info):
                orig_peer(info)
                self.gui_queue.put(("peer", info))

            self.network._handle_text = gui_handle_text
            self.network.add_discovered_peer = gui_add_peer
            
            self.gui_queue.put(("log", "Iniciando red P2P..."))
            self.loop.run_until_complete(self.network.start(self.my_name))
            
            # Mantener vivo el loop
            self.loop.run_forever()
            
        except Exception as e:
            self.gui_queue.put(("error", str(e)))

    # --- HILO GUI (MAIN) ---
    def process_queue(self):
        """Revisa si el hilo de red ha mandado algo"""
        try:
            while True:
                type_, data = self.gui_queue.get_nowait()
                
                if type_ == "status":
                    self.status_lbl.config(text=data[0], fg=data[1])
                elif type_ == "error":
                    messagebox.showerror("Error", data)
                    self.root.quit()
                elif type_ == "peer":
                    self.update_contact_list()
                elif type_ == "msg":
                    fp, name, text = data
                    self.add_message_to_history(fp, text, is_me=False, name=name)
                elif type_ == "log":
                    print(data) # Solo consola debug
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.process_queue)

    def update_contact_list(self):
        # Limpiar y recargar
        for item in self.contacts_list.get_children():
            self.contacts_list.delete(item)
            
        for peer in self.network.get_peers():
            fp = peer['fingerprint']
            name = self.network._get_clean_name(fp)
            # Icono unicode para estado
            self.contacts_list.insert("", "end", iid=fp, text=f"👤 {name}")

    def on_contact_select(self, event):
        selection = self.contacts_list.selection()
        if selection:
            fp = selection[0]
            self.current_chat_fp = fp
            
            name = self.network._get_clean_name(fp)
            self.chat_header.config(text=name)
            self.refresh_chat_window()

    def refresh_chat_window(self):
        self.chat_area.config(state='normal')
        self.chat_area.delete(1.0, tk.END)
        
        history = self.messages_history.get(self.current_chat_fp, [])
        for is_me, text, time_str in history:
            tag = "me" if is_me else "them"
            # Formato bonito
            sender = "Tú" if is_me else self.chat_header.cget("text")
            self.chat_area.insert(tk.END, f"{sender} [{time_str}]\n", "system")
            self.chat_area.insert(tk.END, f"{text}\n\n", tag)
            
        self.chat_area.config(state='disabled')
        self.chat_area.see(tk.END)

    def add_message_to_history(self, fp, text, is_me, name=""):
        if fp not in self.messages_history:
            self.messages_history[fp] = []
        
        t = datetime.now().strftime("%H:%M")
        self.messages_history[fp].append((is_me, text, t))
        
        if self.current_chat_fp == fp:
            self.refresh_chat_window()

    def send_message(self, event=None):
        text = self.msg_entry.get().strip()
        if not text or not self.current_chat_fp: return
        
        target = self.current_chat_fp
        self.msg_entry.delete(0, tk.END)
        
        # Enviar en el hilo de asyncio de forma segura
        asyncio.run_coroutine_threadsafe(
            self.network.send_message(target, text), 
            self.loop
        )
        
        # Actualizar mi vista inmediatamente
        self.add_message_to_history(target, text, is_me=True)

if __name__ == "__main__":
    root = tk.Tk()
    app = DNIeApp(root)
    root.mainloop()