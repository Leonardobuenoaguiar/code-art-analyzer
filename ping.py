import csv
import platform
import queue
import re
import socket
import subprocess
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from collections import deque
from datetime import datetime
from urllib.request import Request, urlopen
import json
import ipaddress
import base64
import io
from PIL import Image, ImageTk

import customtkinter as ctk

try:
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    MATPLOTLIB_OK = True
except ImportError:
    MATPLOTLIB_OK = False

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

BG = "#080808"
PANEL = "#121216"
PANEL_ALT = "#1D1D25"
GREEN = "#42F5B3"
GREEN_DARK = "#16A879"
TEXT = "#F0F5FC"
MUTED = "#9BAEC4"
RED = "#FF5D6C"
AMBER = "#FFC857"
BLUE = "#6268FF"
PURPLE = "#C47DFF"
BORDER = "#30303A"

PING_INTERVAL_MS = 2000
HISTORY_SIZE = 100
PING_TIMEOUT = 2
PORTS = (("RDP 3389", 3389), ("HTTP 80", 80), ("HTTPS 443", 443))


def run_command(command, timeout=5):
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, errors="replace",
            timeout=timeout, shell=False
        )
        return (result.stdout or "") + "\n" + (result.stderr or ""), result.returncode
    except Exception as exc:
        return str(exc), 1


def ping_host(host, timeout=PING_TIMEOUT):
    """Executa um ping e retorna status, latência, TTL e detalhe."""
    system = platform.system().lower()
    if system == "windows":
        command = ["ping", "-n", "1", "-w", str(timeout * 1000), host]
    elif system == "darwin":
        command = ["ping", "-c", "1", "-W", str(timeout * 1000), host]
    else:
        command = ["ping", "-c", "1", "-W", str(timeout), host]

    output, code = run_command(command, timeout + 2)
    if code != 0 or re.search(r"(timed out|esgotado|inacessível|unreachable|100% packet loss)", output, re.I):
        return {"online": False, "latency": None, "ttl": None, "detail": "Sem resposta ICMP"}

    # Windows, Linux e macOS variam entre "time=", "tempo<1ms" e "time<1ms".
    latency_match = re.search(r"(?:time|tempo)\s*[=<]\s*(\d+(?:[.,]\d+)?)\s*ms", output, re.I)
    if not latency_match:
        latency_match = re.search(r"(?:time|tempo)\s*=\s*(\d+(?:[.,]\d+)?)", output, re.I)
    ttl_match = re.search(r"\bttl\s*[=:\s]+(\d+)", output, re.I)
    # Código de saída 0 normalmente indica resposta; se a latência for arredondada,
    # registra 0 ms em vez de deixar o host eternamente aguardando.
    latency = float(latency_match.group(1).replace(",", ".")) if latency_match else 0.0
    ttl = int(ttl_match.group(1)) if ttl_match else None
    return {"online": True, "latency": latency, "ttl": ttl, "detail": "Resposta ICMP recebida"}


def resolve_dns(host):
    try:
        return socket.gethostbyaddr(host)[0]
    except (socket.herror, socket.gaierror, OSError):
        try:
            return socket.getfqdn(host) if socket.getfqdn(host) != host else "Não resolvido"
        except Exception:
            return "Não resolvido"


def resolve_ipv4(host):
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, OSError):
        return host


def get_mac(ip):
    """Consulta a tabela ARP local; o host precisa ter sido alcançado na rede local."""
    system = platform.system().lower()
    if system == "windows":
        output, _ = run_command(["arp", "-a", ip], 3)
    else:
        output, _ = run_command(["arp", "-n", ip], 3)
        if "?" in output or not re.search(r"(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}", output, re.I):
            output2, _ = run_command(["ip", " neigh", "show", ip], 3)
            output += "\n" + output2
    match = re.search(r"(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}", output, re.I)
    return match.group(0).replace("-", ":").upper() if match else "Não disponível na tabela ARP"


def get_default_gateway():
    system = platform.system().lower()
    if system == "windows":
        output, _ = run_command(["ipconfig"], 4)
        match = re.search(r"(?:Gateway Padrão|Default Gateway)[ .:]*\s*(\d{1,3}(?:\.\d{1,3}){3})", output, re.I)
        if match:
            return match.group(1)
    elif system == "darwin":
        output, _ = run_command(["route", "-n", "get", "default"], 3)
        match = re.search(r"gateway:\s*(\S+)", output, re.I)
        if match:
            return match.group(1)
    else:
        output, _ = run_command(["ip", "route", "show", "default"], 3)
        match = re.search(r"default via (\S+)", output)
        if match:
            return match.group(1)
    return "Não identificado"


def traceroute_host(host, timeout=12):
    system = platform.system().lower()
    if system == "windows":
        command = ["tracert", "-d", "-h", "8", "-w", "700", host]
    else:
        command = ["traceroute", "-n", "-m", "8", "-w", "1", host]
    output, code = run_command(command, timeout)
    if code != 0 and not output.strip():
        return "Traceroute indisponível (verifique se o comando está instalado)"
    lines = [line.strip() for line in output.splitlines() if re.search(r"^\s*\d+\s+", line)]
    return "\n".join(lines[:8]) if lines else output.strip()[:1200] or "Sem dados de rota"


def public_ip_info():
    """Consulta serviço externo para IP público, cidade, país e ASN."""
    try:
        req = Request("https://ipapi.co/json/", headers={"User-Agent": "NetworkMonitor/1.0"})
        with urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode("utf-8", "replace"))
        if data.get("error"):
            raise ValueError(data.get("reason", "Consulta indisponível"))
        return {
            "ip": data.get("ip", "Não disponível"),
            "city": data.get("city", "Não disponível"),
            "country": data.get("country_name", "Não disponível"),
            "asn": data.get("asn", "Não disponível"),
            "org": data.get("org", "Não disponível"),
        }
    except Exception as exc:
        return {"ip": "Não disponível", "city": "Não disponível",
                "country": "Não disponível", "asn": "Não disponível",
                "org": f"Consulta externa indisponível: {exc}"}


class NetworkMonitor(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("CODE ART ANALYZER")
        self.geometry("1720x1050")
        self.minsize(1320, 850)
        self.configure(fg_color=BG)

        self.events = queue.Queue()
        self.running = False
        self.monitoring = False
        self.monitor_generation = 0
        self.stop_event = threading.Event()
        self.host_data = {}
        self.selected_host = None
        self.gateway = "Carregando..."
        self.public_info = {"ip": "Consultando...", "city": "—", "country": "—", "asn": "—", "org": "—"}
        self.last_alerts = {}
        self.alert_popup = None
        self.alert_popup_after_id = None
        self.alert_history = deque(maxlen=100)
        self.active_alerts = {}
        self.alert_center = None
        self.alert_listing = None
        self.alert_dropdown = None
        self.alert_dropdown_open = False
        self.alert_dropdown_items = None
        self.latency_history = deque(maxlen=HISTORY_SIZE)
        self.history_times = deque(maxlen=HISTORY_SIZE)
        self.last_ping_at = None
        self.csv_rows = []
        self.after(100, self.process_events)

        self.configure_table_style()
        self.build_ui()
        threading.Thread(target=self.load_network_info, daemon=True).start()

    def configure_table_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Dark.Treeview", background=PANEL, foreground=TEXT,
                        fieldbackground=PANEL, borderwidth=0, rowheight=36,
                        font=("Segoe UI", 10))
        style.configure("Dark.Treeview.Heading", background=PANEL_ALT,
                        foreground=GREEN, borderwidth=0, relief="flat",
                        font=("Segoe UI", 9, "bold"), padding=(7, 8))
        style.map("Dark.Treeview", background=[("selected", "#1D5035")],
                  foreground=[("selected", "#FFFFFF")])

    def card(self, parent, title=None):
        frame = ctk.CTkFrame(parent, fg_color=PANEL, corner_radius=12,
                             border_width=1, border_color=BORDER)
        if title:
            ctk.CTkLabel(frame, text=title.upper(), text_color=MUTED,
                         font=("Segoe UI", 10, "bold")).pack(
                anchor="w", padx=13, pady=(11, 4))
        return frame

    def build_ui(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(16, 12))
        titlebox = ctk.CTkFrame(header, fg_color="transparent")
        titlebox.pack(side="left", fill="x", expand=True)
        logo_data = base64.b64decode("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")
        logo_image = Image.open(io.BytesIO(logo_data)).convert("RGBA")
        self.logo_photo = ImageTk.PhotoImage(logo_image)
        ctk.CTkLabel(titlebox, image=self.logo_photo, text="").pack(side="left", padx=(0, 12))
        title_text = ctk.CTkFrame(titlebox, fg_color="transparent")
        title_text.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(title_text, text="CODE ART ANALYZER",
                     text_color=TEXT, font=("Segoe UI", 24, "bold")).pack(anchor="w")
        ctk.CTkLabel(title_text, text="ICMP  •  DNS  •  ARP  •  TRACEROUTE",
                     text_color=BLUE, font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(2, 0))
        self.badge = ctk.CTkLabel(header, text="●  PRONTO", text_color=GREEN,
                                  fg_color="#132B1D", corner_radius=18,
                                  font=("Segoe UI", 10, "bold"))
        self.badge.pack(side="right", padx=(10, 0), ipadx=12, ipady=7)
        self.clock = ctk.CTkLabel(header, text="--:--:--", text_color=MUTED,
                                  font=("Cascadia Code", 11))
        self.clock.pack(side="right", padx=12)
        self.btn_alerts = ctk.CTkButton(
            header, text="⚑ Alertas (0) ▾", command=self.toggle_alert_dropdown,
            width=118, height=34, fg_color="#3A2730", hover_color="#56313C",
            text_color=TEXT, font=("Segoe UI", 10, "bold")
        )
        self.btn_alerts.pack(side="right", padx=(8, 0))

        self.filter_var = tk.StringVar(value="Todos os IPs")
        self.ip_filter = ctk.CTkOptionMenu(
            header, variable=self.filter_var, values=["Todos os IPs"],
            command=self.change_ip_filter, width=210, height=36,
            fg_color=PANEL_ALT, button_color="#4549B8",
            button_hover_color="#5B60E8", text_color=TEXT,
            font=("Segoe UI", 11, "bold"), dropdown_fg_color=PANEL,
            dropdown_text_color=TEXT, dropdown_hover_color="#292B66"
        )
        self.ip_filter.pack(side="right", padx=(12, 8))
        self.bind_all("<Control-Shift-C>", self.copy_entire_interface_shortcut)
        self.bind_all("<Control-Shift-c>", self.copy_entire_interface_shortcut)
        self.bind_all("<Control-Shift-V>", self.paste_targets_shortcut)
        self.bind_all("<Control-Shift-v>", self.paste_targets_shortcut)
        self.update_clock()

        stats = ctk.CTkFrame(self, fg_color="transparent")
        stats.pack(fill="x", padx=20, pady=(0, 12))
        for col in range(5):
            stats.grid_columnconfigure(col, weight=1, uniform="stats")
        self.stat_total = self.stat_card(stats, 0, "HOSTS MONITORADOS", "0", BLUE)
        self.stat_online = self.stat_card(stats, 1, "ONLINE", "0", GREEN)
        self.stat_offline = self.stat_card(stats, 2, "OFFLINE", "0", RED)
        self.stat_latency = self.stat_card(stats, 3, "LATÊNCIA MÉDIA", "—", AMBER)
        self.stat_loss = self.stat_card(stats, 4, "PERDA DE PACOTES", "—", PURPLE)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=20, pady=(0, 12))
        body.grid_columnconfigure(0, weight=0, minsize=370)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        left = ctk.CTkFrame(body, fg_color="transparent")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        right = ctk.CTkFrame(body, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew")

        targets = self.card(left, "Alvos de rede")
        targets.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(targets, text="Um IP ou hostname por linha",
                     text_color=TEXT, font=("Segoe UI", 11)).pack(anchor="w", padx=13, pady=(6, 6))
        self.txt_hosts = ctk.CTkTextbox(targets, height=115, fg_color="#0D0D11",
                                        text_color=TEXT, border_color=BORDER,
                                        border_width=1, corner_radius=8,
                                        font=("Cascadia Code", 10))
        self.txt_hosts.pack(fill="x", padx=11)
        self.txt_hosts.insert("1.0", "8.8.8.8\n1.1.1.1\n192.168.0.1")
        self.enable_text_copy_paste(self.txt_hosts)
        self.btn_start = ctk.CTkButton(targets, text="▶  Iniciar monitoramento",
                                       command=self.toggle_monitoring, height=38,
                                       fg_color=GREEN_DARK, hover_color="#12864A",
                                       text_color="#06130B", font=("Segoe UI", 11, "bold"))
        self.btn_start.pack(fill="x", padx=11, pady=(10, 6))
        paste_actions = ctk.CTkFrame(targets, fg_color="transparent")
        paste_actions.pack(fill="x", padx=11, pady=(0, 6))
        ctk.CTkButton(paste_actions, text="Colar IPs da área de transferência",
                      command=self.paste_targets, height=30,
                      fg_color="#292B66", hover_color="#4B50C9",
                      text_color=TEXT).pack(side="left", fill="x", expand=True, padx=(0, 4))
        ctk.CTkButton(paste_actions, text="Copiar interface",
                      command=self.copy_entire_interface, height=30,
                      fg_color=PANEL_ALT, hover_color="#34366F",
                      text_color=TEXT).pack(side="left", fill="x", expand=True, padx=(4, 0))
        actions = ctk.CTkFrame(targets, fg_color="transparent")
        actions.pack(fill="x", padx=11, pady=(0, 11))
        ctk.CTkButton(actions, text="Exportar CSV", command=self.export_csv,
                      fg_color=PANEL_ALT, hover_color="#26392D", text_color=TEXT,
                      border_width=1, border_color=BORDER).pack(side="left", fill="x", expand=True, padx=(0, 4))
        ctk.CTkButton(actions, text="Limpar", command=self.clear_data,
                      fg_color="#3A1C22", hover_color="#5B252F",
                      text_color="#FFB7BF").pack(side="left", fill="x", expand=True, padx=(4, 0))

        details = self.card(left, "Detalhes do host selecionado")
        details.pack(fill="both", expand=True, pady=(0, 2))
        # Conteúdo rolável: mantém o cabeçalho do card visível e permite acessar
        # todos os detalhes e o traceroute mesmo em telas menores.
        self.details_scroll = ctk.CTkScrollableFrame(
            details, fg_color="transparent", corner_radius=8,
            scrollbar_button_color=BLUE, scrollbar_button_hover_color="#8589FF"
        )
        self.details_scroll.pack(fill="both", expand=True, padx=5, pady=(0, 6))
        self.detail_labels = {}
        for key, label in [
            ("host", "Host monitorado"), ("status", "Estado atual"),
            ("hostname", "Hostname / resolução DNS"), ("mac", "Endereço MAC (ARP)"),
            ("ttl", "TTL retornado"), ("last", "Horário da última resposta"),
            ("last_latency", "Latência da última resposta"),
            ("minmax", "Latência mínima / máxima"), ("avg", "Latência média"),
            ("jitter", "Jitter médio"), ("moving", "Média móvel (10 últimas respostas)"),
            ("loss", "Perda de pacotes"), ("samples", "Amostras no histórico"),
            ("uptime", "Disponibilidade observada"),
        ]:
            self.detail_labels[key] = self.info_line(self.details_scroll, label, "—")
        ctk.CTkButton(self.details_scroll, text="Executar traceroute", command=self.run_traceroute,
                      height=32, fg_color=BLUE, hover_color="#4B50C9",
                      text_color="#FFFFFF", font=("Segoe UI", 10, "bold")).pack(
                          fill="x", padx=11, pady=(10, 6))
        self.traceroute_text = ctk.CTkTextbox(self.details_scroll, height=120, fg_color="#0D0D11",
                                               text_color=MUTED, font=("Cascadia Code", 9),
                                               corner_radius=7)
        self.traceroute_text.pack(fill="x", padx=11, pady=(0, 10))
        self.traceroute_text.insert("1.0", "Selecione um host e execute o traceroute.")
        self.enable_text_copy_paste(self.traceroute_text)

        # Main dashboard, with panels inspired by the supplied traffic analyzer screenshot.
        right.grid_columnconfigure(0, weight=1)
        right.grid_columnconfigure(1, weight=1)
        right.grid_rowconfigure(0, weight=3)
        right.grid_rowconfigure(1, weight=4)

        table_card = self.card(right, "Hosts e estado de conectividade")
        table_card.grid(row=0, column=0, columnspan=2, sticky="nsew", pady=(0, 10))
        columns = ("host", "hostname", "status", "latency", "loss", "ttl", "last")
        self.tree = ttk.Treeview(table_card, columns=columns, show="headings",
                                 style="Dark.Treeview", selectmode="browse")
        headings = {"host": "IP / HOST", "hostname": "DNS / HOSTNAME", "status": "STATUS",
                    "latency": "PING", "loss": "PERDA", "ttl": "TTL", "last": "ÚLTIMA RESPOSTA"}
        widths = {"host": 125, "hostname": 155, "status": 78, "latency": 85,
                  "loss": 75, "ttl": 55, "last": 125}
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], minwidth=55, anchor="center")
        self.tree.tag_configure("online", foreground=GREEN)
        self.tree.tag_configure("offline", foreground=RED)
        self.tree.tag_configure("warning", foreground=AMBER)
        self.tree.pack(fill="both", expand=True, padx=10, pady=(6, 10))
        self.tree.bind("<<TreeviewSelect>>", self.select_host)
        self.tree.bind("<Control-c>", self.copy_tree_selection)
        self.tree.bind("<Control-C>", self.copy_tree_selection)
        self.tree.bind("<Button-3>", self.show_tree_context_menu)

        chart_card = self.card(right, "Latência ICMP em tempo real — últimas 100 amostras")
        chart_card.grid(row=1, column=0, sticky="nsew", padx=(0, 5))
        self.chart_area = ctk.CTkFrame(chart_card, fg_color="#0D0D11", corner_radius=8)
        self.chart_area.pack(fill="both", expand=True, padx=10, pady=(5, 10))
        self.create_latency_chart()

        distribution = self.card(right, "Visão geral do monitoramento")
        distribution.grid(row=1, column=1, sticky="nsew", padx=(5, 0))
        self.donut_area = ctk.CTkFrame(distribution, fg_color="#0D0D11", corner_radius=8)
        self.donut_area.pack(fill="both", expand=True, padx=10, pady=(5, 8))
        self.create_donut_chart()
        self.alert_box = ctk.CTkTextbox(distribution, height=74, fg_color="#0D0D11",
                                        text_color=AMBER, font=("Segoe UI", 10),
                                        corner_radius=8)
        self.alert_box.pack(fill="x", padx=10, pady=(0, 10))
        self.alert_box.insert("1.0", "Alertas: ping > 100 ms • perda > 5% • host offline")
        self.enable_text_copy_paste(self.alert_box)
        self.alert_box.configure(state="disabled")

        footer = ctk.CTkFrame(self, fg_color="#0D0D13", corner_radius=8, height=30)
        footer.pack(fill="x", padx=20, pady=(0, 8))
        footer.pack_propagate(False)
        ctk.CTkLabel(footer, text="DESENVOLVIDO POR  •  LEONARDO AGUIAR",
                     text_color=TEXT, font=("Segoe UI", 10, "bold")).pack(
                         side="left", padx=12, pady=5)
        ctk.CTkLabel(footer, text="CODE ART ANALYZER  /  NETWORK INTELLIGENCE",
                     text_color=BLUE, font=("Segoe UI", 9, "bold")).pack(
                         side="right", padx=12, pady=5)

    def enable_text_copy_paste(self, widget):
        widget.bind("<Control-a>", lambda event, w=widget: self.select_all_text(w))
        widget.bind("<Control-A>", lambda event, w=widget: self.select_all_text(w))
        widget.bind("<Control-c>", lambda event, w=widget: self.copy_text_selection(w))
        widget.bind("<Control-C>", lambda event, w=widget: self.copy_text_selection(w))
        widget.bind("<Control-v>", lambda event, w=widget: self.paste_into_text(w))
        widget.bind("<Control-V>", lambda event, w=widget: self.paste_into_text(w))
        widget.bind("<Control-x>", lambda event, w=widget: self.cut_text_selection(w))
        widget.bind("<Button-3>", lambda event, w=widget: self.show_text_context_menu(event, w))

    def select_all_text(self, widget):
        widget.tag_add("sel", "1.0", "end-1c")
        widget.mark_set("insert", "end-1c")
        widget.focus_set()
        return "break"

    def copy_text_selection(self, widget):
        try:
            selected = widget.get("sel.first", "sel.last")
        except Exception:
            selected = ""
        if selected:
            self.clipboard_clear()
            self.clipboard_append(selected)
            self.badge.configure(text="●  TEXTO COPIADO", text_color=GREEN, fg_color="#132B1D")
        return "break"

    def paste_into_text(self, widget):
        try:
            widget.insert("insert", self.clipboard_get())
        except Exception:
            pass
        widget.focus_set()
        return "break"

    def cut_text_selection(self, widget):
        self.copy_text_selection(widget)
        try:
            widget.delete("sel.first", "sel.last")
        except Exception:
            pass
        return "break"

    def show_text_context_menu(self, event, widget):
        menu = tk.Menu(self, tearoff=0, bg=PANEL, fg=TEXT,
                       activebackground="#292B66", activeforeground=TEXT)
        menu.add_command(label="Copiar", command=lambda: self.copy_text_selection(widget))
        menu.add_command(label="Colar", command=lambda: self.paste_into_text(widget))
        menu.add_command(label="Selecionar tudo", command=lambda: self.select_all_text(widget))
        menu.add_command(label="Recortar", command=lambda: self.cut_text_selection(widget))
        menu.tk_popup(event.x_root, event.y_root)
        return "break"

    def copy_widget_text(self, event, widget):
        try:
            self.clipboard_clear()
            self.clipboard_append(str(widget.cget("text")))
            self.badge.configure(text="●  TEXTO COPIADO", text_color=GREEN, fg_color="#132B1D")
        except Exception:
            pass
        return "break"

    def copy_tree_selection(self, _event=None):
        selection = self.tree.selection()
        if not selection:
            return "break"
        headings = [self.tree.heading(col, "text") for col in self.tree["columns"]]
        rows = ["\\t".join(headings)]
        for item in selection:
            rows.append("\\t".join(str(v) for v in self.tree.item(item, "values")))
        self.clipboard_clear()
        self.clipboard_append("\\n".join(rows))
        self.badge.configure(text="●  LINHA COPIADA", text_color=GREEN, fg_color="#132B1D")
        return "break"

    def show_tree_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
        menu = tk.Menu(self, tearoff=0, bg=PANEL, fg=TEXT,
                       activebackground="#292B66", activeforeground=TEXT)
        menu.add_command(label="Copiar linha selecionada", command=self.copy_tree_selection)
        menu.add_command(label="Filtrar este host", command=self.filter_selected_tree_host)
        menu.tk_popup(event.x_root, event.y_root)

    def filter_selected_tree_host(self):
        selection = self.tree.selection()
        if not selection:
            return
        item = selection[0]
        host = next((h for h, d in self.host_data.items() if d.get("iid") == item), None)
        if host:
            data = self.host_data[host]
            label = host if not data.get("ip") or data["ip"] == host else f'{host} ({data["ip"]})'
            self.filter_var.set(label)
            self.change_ip_filter(label)

    def paste_targets(self):
        try:
            pasted = self.clipboard_get()
        except Exception:
            messagebox.showwarning("Code Art Network Analyzer", "A área de transferência está vazia ou indisponível.")
            return
        new_lines = [line.strip() for line in pasted.splitlines() if line.strip()]
        if not new_lines:
            return
        current = [line.strip() for line in self.txt_hosts.get("1.0", "end-1c").splitlines() if line.strip()]
        combined = list(dict.fromkeys(current + new_lines))
        self.txt_hosts.delete("1.0", "end")
        self.txt_hosts.insert("1.0", "\n".join(combined))
        self.txt_hosts.focus_set()
        self.badge.configure(text=f"●  {len(combined)} ALVOS NA LISTA", text_color=GREEN, fg_color="#132B1D")

    def copy_entire_interface(self):
        lines = [
            "CODE ART ANALYZER",
            f"Data/hora da captura: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "", "RESUMO GERAL",
            f"Hosts monitorados: {self.stat_total.cget('text')}",
            f"Online: {self.stat_online.cget('text')}",
            f"Offline: {self.stat_offline.cget('text')}",
            f"Latência média do filtro: {self.stat_latency.cget('text')}",
            f"Perda de pacotes do filtro: {self.stat_loss.cget('text')}",
            f"Filtro atual: {self.filter_var.get()}",
            "", "HOSTS MONITORADOS",
            "\\t".join(self.tree.heading(col, "text") for col in self.tree["columns"]),
        ]
        for item in self.tree.get_children():
            lines.append("\\t".join(str(value) for value in self.tree.item(item, "values")))
        lines.extend(["", "DETALHES DO HOST SELECIONADO"])
        for key, widget in self.detail_labels.items():
            lines.append(f"{key}: {widget.cget('text')}")
        lines.extend(["", "TRACEROUTE", self.traceroute_text.get("1.0", "end-1c")])
        try:
            lines.extend(["", "ALERTAS", self.alert_box.get("1.0", "end-1c")])
        except Exception:
            pass
        self.clipboard_clear()
        self.clipboard_append("\\n".join(lines))
        self.badge.configure(text="●  INTERFACE COPIADA", text_color=GREEN, fg_color="#132B1D")

    def copy_entire_interface_shortcut(self, _event=None):
        self.copy_entire_interface()
        return "break"

    def paste_targets_shortcut(self, _event=None):
        self.paste_targets()
        return "break"

    def info_line(self, parent, label, value):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=11, pady=2)
        ctk.CTkLabel(row, text=label, text_color=MUTED, font=("Segoe UI", 9),
                     anchor="w").pack(anchor="w")
        value_label = ctk.CTkLabel(row, text=value, text_color=TEXT,
                                   font=("Segoe UI", 10, "bold"), anchor="w",
                                   wraplength=320, justify="left")
        value_label.pack(anchor="w")
        value_label.bind("<Button-3>", lambda event, widget=value_label: self.copy_widget_text(event, widget))
        value_label.bind("<Control-c>", lambda event, widget=value_label: self.copy_widget_text(event, widget))
        value_label.bind("<Control-C>", lambda event, widget=value_label: self.copy_widget_text(event, widget))
        value_label.configure(cursor="hand2")
        return value_label

    def stat_card(self, parent, column, title, value, color):
        frame = self.card(parent)
        frame.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 5, 5))
        ctk.CTkLabel(frame, text=title, text_color=MUTED,
                     font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=12, pady=(12, 2))
        label = ctk.CTkLabel(frame, text=value, text_color=color,
                             font=("Segoe UI", 26, "bold"))
        label.pack(anchor="w", padx=12, pady=(0, 12))
        return label

    def create_latency_chart(self):
        if not MATPLOTLIB_OK:
            ctk.CTkLabel(self.chart_area, text="Instale matplotlib para ver os gráficos.",
                         text_color=AMBER).pack(padx=10, pady=20)
            self.fig = self.ax = self.canvas = None
            return
        self.fig = Figure(figsize=(7.0, 3.5), dpi=110, facecolor="#0D0D11")
        self.ax = self.fig.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.chart_area)
        self.canvas.get_tk_widget().configure(highlightthickness=0, background="#0D0D11")
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        self.draw_latency_chart()

    def draw_latency_chart(self):
        if not MATPLOTLIB_OK or self.ax is None:
            return
        self.ax.clear()
        self.ax.set_facecolor("#0D0D11")
        self.ax.tick_params(colors=MUTED, labelsize=9)
        for spine in self.ax.spines.values():
            spine.set_color(BORDER)
        self.ax.grid(True, color="#30303A", alpha=0.8, linewidth=0.6)
        self.ax.set_ylabel("Latência (ms)", color=MUTED, fontsize=9)
        self.ax.set_xlabel("Últimas amostras", color=MUTED, fontsize=9)
        host = self.selected_host or "visão geral — selecione um IP para filtrar"
        self.ax.set_title(f"Histórico ICMP — {host}", color=TEXT, loc="left", fontsize=10, pad=7)
        vals = list(self.latency_history)
        if vals:
            xs = list(range(1, len(vals) + 1))
            ys = [v if v is not None else float("nan") for v in vals]
            self.ax.plot(xs, ys, color=GREEN, linewidth=1.8, marker="o", markersize=2.5)
            self.ax.fill_between(xs, ys, 0, color=GREEN, alpha=0.10)
            moving = []
            for i in range(len(vals)):
                sample = [v for v in vals[max(0, i - 9):i + 1] if v is not None]
                moving.append(sum(sample) / len(sample) if sample else float("nan"))
            self.ax.plot(xs, moving, color=BLUE, linewidth=1.2, linestyle="--", label="Média móvel (10)")
            self.ax.legend(facecolor=PANEL, labelcolor=TEXT, fontsize=7, loc="upper left")
            self.ax.set_xlim(1, max(2, len(xs)))
            finite = [v for v in vals if v is not None]
            if finite:
                self.ax.set_ylim(bottom=0, top=max(10, max(finite) * 1.25))
        else:
            self.ax.text(0.5, 0.5, "Inicie o monitoramento para visualizar medições",
                         transform=self.ax.transAxes, ha="center", va="center",
                         color=MUTED, fontsize=9)
        self.fig.tight_layout(pad=1.5)
        self.canvas.draw_idle()

    def create_donut_chart(self):
        if not MATPLOTLIB_OK:
            ctk.CTkLabel(self.donut_area, text="Gráfico indisponível sem matplotlib",
                         text_color=AMBER).pack(padx=10, pady=20)
            self.donut_fig = self.donut_ax = self.donut_canvas = None
            return
        self.donut_fig = Figure(figsize=(6.2, 3.0), dpi=110, facecolor="#0D0D11")
        self.donut_ax = self.donut_fig.add_subplot(111)
        self.donut_canvas = FigureCanvasTkAgg(self.donut_fig, master=self.donut_area)
        self.donut_canvas.get_tk_widget().configure(highlightthickness=0, background="#0D0D11")
        self.donut_canvas.get_tk_widget().pack(fill="both", expand=True)
        self.draw_donut_chart()

    def draw_donut_chart(self):
        if not MATPLOTLIB_OK or self.donut_ax is None:
            return
        self.donut_ax.clear()
        self.donut_ax.set_facecolor("#0D0D11")
        if self.selected_host and self.selected_host in self.host_data:
            selected_data = self.host_data[self.selected_host]
            online = int(bool(selected_data["samples"] and selected_data["samples"][-1]["online"]))
            offline = int(bool(selected_data["samples"] and not selected_data["samples"][-1]["online"]))
            unknown = int(not selected_data["samples"])
            center_label = self.selected_host
        else:
            online = sum(1 for d in self.host_data.values() if d["samples"] and d["samples"][-1]["online"])
            offline = sum(1 for d in self.host_data.values() if d["samples"] and not d["samples"][-1]["online"])
            unknown = max(0, len(self.host_data) - online - offline)
            center_label = str(len(self.host_data))
        values = [online, offline, unknown]
        colors = [GREEN, RED, "#46544B"]
        if sum(values) == 0:
            values = [1]
            colors = ["#30303A"]
        self.donut_ax.pie(values, colors=colors, startangle=90,
                          wedgeprops={"width": 0.28, "edgecolor": "#0D0D11"})
        self.donut_ax.text(0, 0.08, center_label[:10], color=TEXT,
                           ha="center", va="center", fontsize=13 if len(center_label) > 4 else 20,
                           fontweight="bold")
        self.donut_ax.text(0, -0.18, "IP SELECIONADO" if self.selected_host else "HOSTS",
                           color=MUTED, ha="center", va="center", fontsize=8)
        self.donut_ax.legend(["Online", "Offline", "Sem dados"], loc="center left",
                             bbox_to_anchor=(0.85, 0.5), frameon=False,
                             labelcolor=TEXT, fontsize=8)
        self.donut_ax.set_title("Estado dos alvos", color=TEXT, fontsize=9, loc="left")
        self.donut_fig.tight_layout(pad=1.1)
        self.donut_canvas.draw_idle()

    def update_clock(self):
        self.clock.configure(text=datetime.now().strftime("%H:%M:%S"))
        self.after(1000, self.update_clock)

    def load_network_info(self):
        gateway = get_default_gateway()
        public = public_ip_info()
        self.events.put(("network_info", gateway, public))

    def refresh_network_info(self):
        self.lbl_gateway.configure(text="Consultando...")
        self.lbl_public_ip.configure(text="Consultando...")
        self.lbl_geo.configure(text="Consultando...")
        threading.Thread(target=self.load_network_info, daemon=True).start()

    def toggle_monitoring(self):
        if self.monitoring:
            self.monitoring = False
            self.monitor_generation += 1
            self.stop_event.set()
            self.btn_start.configure(text="▶  Iniciar monitoramento")
            self.badge.configure(text="●  PAUSADO", text_color=AMBER, fg_color="#302817")
            return
        hosts = [line.strip() for line in self.txt_hosts.get("1.0", "end").splitlines() if line.strip()]
        if not hosts:
            messagebox.showwarning("CODE ART ANALYZER", "Informe pelo menos um IP ou hostname.")
            return
        # Deduplicate targets while preserving order.
        hosts = list(dict.fromkeys(hosts))
        self.host_data.clear()
        self.csv_rows.clear()
        self.active_alerts.clear()
        self.tree.delete(*self.tree.get_children())
        self.latency_history.clear()
        self.history_times.clear()
        for host in hosts:
            # Não resolva DNS na thread da interface: um DNS lento pode travar a tela.
            self.host_data[host] = {
                "hostname": "Resolvendo DNS...", "ip": host,
                "samples": deque(maxlen=HISTORY_SIZE), "iid": None,
                "mac": "Consultando...", "traceroute": ""
            }
        # Exibe todos os alvos imediatamente, mesmo antes da primeira resposta ICMP.
        for host in hosts:
            self.refresh_tree_row(host)
        self.monitoring = True
        self.monitor_generation += 1
        run_id = self.monitor_generation
        self.stop_event.clear()
        self.btn_start.configure(text="■  Parar monitoramento")
        self.badge.configure(text="●  MONITORANDO", text_color=GREEN, fg_color="#132B1D")
        self.selected_host = None
        self.filter_var.set("Todos os IPs")
        self.refresh_filter_options()
        self.refresh_details_all()
        threading.Thread(target=self.monitor_worker, args=(hosts, run_id), daemon=True).start()
        threading.Thread(target=self.resolve_hosts_worker, args=(hosts, run_id), daemon=True).start()
        self.update_dashboard()

    def resolve_hosts_worker(self, hosts, run_id=None):
        for host in hosts:
            if self.stop_event.is_set() or (run_id is not None and run_id != self.monitor_generation):
                return
            try:
                ip = resolve_ipv4(host)
                hostname = resolve_dns(ip if ip != host else host)
                mac = get_mac(ip) if ip != host or re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip) else "Não disponível para hostname não resolvido"
            except Exception as exc:
                ip, hostname, mac = host, f"Falha na resolução: {exc}", "Não disponível"
            self.events.put(("dns", host, hostname, ip, mac))

    def monitor_worker(self, hosts, run_id=None):
        """Monitora continuamente até o usuário clicar em Parar."""
        while not self.stop_event.is_set() and (run_id is None or run_id == self.monitor_generation):
            cycle_start = time.monotonic()
            for host in hosts:
                if self.stop_event.is_set() or (run_id is not None and run_id != self.monitor_generation):
                    break
                try:
                    result = ping_host(host, timeout=PING_TIMEOUT)
                    if not isinstance(result, dict):
                        raise RuntimeError("Resposta de ping inválida")
                except Exception as exc:
                    result = {"online": False, "latency": None, "ttl": None,
                              "detail": f"Erro ao executar ping: {exc}"}
                result["time"] = datetime.now()
                self.events.put(("ping", host, result))
            elapsed = time.monotonic() - cycle_start
            # Aguarda o intervalo sem bloquear o botão Parar.
            self.stop_event.wait(max(0.05, PING_INTERVAL_MS / 1000 - elapsed))

    def process_events(self):
        try:
            while True:
                event = self.events.get_nowait()
                if event[0] == "network_info":
                    _, gateway, public = event
                    self.gateway, self.public_info = gateway, public
                    self.lbl_gateway.configure(text=gateway)
                    self.lbl_public_ip.configure(text=public["ip"])
                    self.lbl_geo.configure(text=f'{public["city"]}, {public["country"]} • {public["asn"]}')
                elif event[0] == "dns":
                    _, host, hostname, ip, mac = event
                    if host in self.host_data:
                        self.host_data[host]["hostname"] = hostname
                        self.host_data[host]["ip"] = ip
                        self.host_data[host]["mac"] = mac
                        self.refresh_tree_row(host)
                        if host == self.selected_host:
                            self.refresh_details()
                elif event[0] == "ping":
                    _, host, result = event
                    if host in self.host_data:
                        self.host_data[host]["samples"].append(result)
                        if host == self.selected_host:
                            self.latency_history.append(result["latency"] if result["online"] else None)
                            self.history_times.append(result["time"])
                            self.refresh_details()
                            self.draw_latency_chart()
                        elif self.selected_host is None:
                            self.draw_latency_chart()
                        self.refresh_tree_row(host)
                        self.check_alerts(host)
                        self.update_dashboard()
                elif event[0] == "traceroute":
                    _, host, output = event
                    self.traceroute_text.delete("1.0", "end")
                    self.traceroute_text.insert("1.0", output)
        except queue.Empty:
            pass
        except Exception as exc:
            # Um evento com dados inesperados não pode parar o loop da interface;
            # caso contrário, a tabela fica presa em "Resolvendo/Aguardando".
            print(f"[Code Art Network Analyzer] Erro ao atualizar a interface: {exc}")
        finally:
            if self.winfo_exists():
                self.after(100, self.process_events)

    def host_metrics(self, host):
        data = self.host_data[host]
        samples = list(data["samples"])
        latencies = [s["latency"] for s in samples if s["online"] and s["latency"] is not None]
        last = samples[-1] if samples else None
        loss = (sum(1 for s in samples if not s["online"]) / len(samples) * 100) if samples else 0
        jitter_values = [abs(latencies[i] - latencies[i-1]) for i in range(1, len(latencies))]
        jitter = sum(jitter_values) / len(jitter_values) if jitter_values else None
        moving_values = latencies[-10:]
        moving = sum(moving_values) / len(moving_values) if moving_values else None
        return {"samples": samples, "latencies": latencies, "last": last, "loss": loss,
                "min": min(latencies) if latencies else None,
                "max": max(latencies) if latencies else None,
                "avg": sum(latencies) / len(latencies) if latencies else None,
                "jitter": jitter, "moving": moving}

    def refresh_tree_row(self, host):
        if host not in self.host_data:
            return
        data = self.host_data[host]
        m = self.host_metrics(host)
        last = m["last"]
        status = "AGUARDANDO" if not last else ("ONLINE" if last["online"] else "OFFLINE")
        latency = f'{last["latency"]:.1f} ms' if last and last["online"] else "—"
        ttl = str(last["ttl"]) if last and last["ttl"] is not None else "—"
        last_time = last["time"].strftime("%H:%M:%S") if last else "—"
        values = (data["ip"], data["hostname"], status, latency,
                  f'{m["loss"]:.1f}%', ttl, last_time)
        tag = "online" if status == "ONLINE" else ("offline" if status == "OFFLINE" else "warning")
        iid = data.get("iid")
        if iid and self.tree.exists(iid):
            self.tree.item(iid, values=values, tags=(tag,))
        else:
            iid = self.tree.insert("", "end", values=values, tags=(tag,))
            data["iid"] = iid
        self.csv_rows = []
        for target, d in self.host_data.items():
            mm = self.host_metrics(target)
            last_sample = mm["last"]
            self.csv_rows.append([
                target, d["ip"], d["hostname"],
                "ONLINE" if last_sample and last_sample["online"] else ("OFFLINE" if last_sample else "AGUARDANDO"),
                f'{last_sample["latency"]:.2f}' if last_sample and last_sample["latency"] is not None else "",
                f'{mm["min"]:.2f}' if mm["min"] is not None else "",
                f'{mm["max"]:.2f}' if mm["max"] is not None else "",
                f'{mm["avg"]:.2f}' if mm["avg"] is not None else "",
                f'{mm["loss"]:.2f}', str(last_sample["ttl"]) if last_sample and last_sample["ttl"] is not None else "",
                f'{mm["jitter"]:.2f}' if mm["jitter"] is not None else "",
                last_sample["time"].isoformat(timespec="seconds") if last_sample else "",
                d["mac"], self.gateway
            ])

    def change_ip_filter(self, value):
        if value == "Todos os IPs":
            self.selected_host = None
            self.latency_history.clear()
            self.history_times.clear()
            self.refresh_details_all()
            self.draw_latency_chart()
            self.update_dashboard()
            return

        host = next((h for h, d in self.host_data.items()
                     if value == h or value == d.get("ip", "")
                     or value == d.get("hostname", "")
                     or value.startswith(h + " (")), None)
        if not host:
            return
        self.selected_host = host
        self.latency_history.clear()
        self.history_times.clear()
        for sample in list(self.host_data[host]["samples"]):
            self.latency_history.append(sample["latency"] if sample["online"] else None)
            self.history_times.append(sample["time"])
        data = self.host_data[host]
        if data.get("iid") and self.tree.exists(data["iid"]):
            self.tree.selection_set(data["iid"])
            self.tree.focus(data["iid"])
        self.refresh_details()
        self.draw_latency_chart()
        self.update_dashboard()

    def refresh_filter_options(self):
        options = ["Todos os IPs"]
        for host, data in self.host_data.items():
            label = host
            if data.get("ip") and data["ip"] != host:
                label = f'{host} ({data["ip"]})'
            options.append(label)
        current = self.filter_var.get()
        self.ip_filter.configure(values=options)
        if current not in options:
            if self.selected_host and self.selected_host in self.host_data:
                selected_data = self.host_data[self.selected_host]
                selected_label = self.selected_host
                if selected_data.get("ip") and selected_data["ip"] != self.selected_host:
                    selected_label = f'{self.selected_host} ({selected_data["ip"]})'
                self.filter_var.set(selected_label if selected_label in options else "Todos os IPs")
            else:
                self.filter_var.set("Todos os IPs")

    def refresh_details_all(self):
        for key, label in [
            ("host", "Host / IP"), ("hostname", "Hostname DNS"), ("mac", "MAC (ARP)"),
            ("ttl", "TTL retornado"), ("last", "Última resposta"),
            ("minmax", "Latência mín. / máx."), ("jitter", "Jitter"),
            ("moving", "Média móvel"), ("loss", "Perda de pacotes"),
        ]:
            if key in self.detail_labels:
                self.detail_labels[key].configure(text="Selecione um IP na tabela ou no filtro")

    def update_dashboard(self):
        self.refresh_filter_options()
        all_hosts = list(self.host_data)
        chosen = self.selected_host if self.selected_host in self.host_data else None
        self.stat_total.configure(text=str(len(all_hosts)))

        online = sum(1 for host in all_hosts
                     if self.host_metrics(host)["last"] and self.host_metrics(host)["last"]["online"])
        offline = sum(1 for host in all_hosts
                      if self.host_metrics(host)["last"] and not self.host_metrics(host)["last"]["online"])
        self.stat_online.configure(text=str(online))
        self.stat_offline.configure(text=str(offline))

        # These two cards alone follow the selected IP filter.
        if chosen:
            metric = self.host_metrics(chosen)
            self.stat_latency.configure(text=f'{metric["avg"]:.1f} ms' if metric["avg"] is not None else "—")
            self.stat_loss.configure(text=f'{metric["loss"]:.1f}%' if metric["samples"] else "—")
        else:
            self.stat_latency.configure(text="—")
            self.stat_loss.configure(text="—")
        self.draw_donut_chart()

    def refresh_details(self):
        host = self.selected_host
        if not host or host not in self.host_data:
            return
        data = self.host_data[host]
        m = self.host_metrics(host)
        last = m["last"]
        self.detail_labels["host"].configure(text=f'{host}  ({data["ip"]})')
        self.detail_labels["status"].configure(
            text=("ONLINE" if last and last["online"] else "OFFLINE" if last else "AGUARDANDO"),
            text_color=GREEN if last and last["online"] else RED if last else AMBER)
        self.detail_labels["hostname"].configure(text=data["hostname"])
        self.detail_labels["mac"].configure(text=data["mac"])
        self.detail_labels["ttl"].configure(text=str(last["ttl"]) if last and last["ttl"] is not None else "—")
        self.detail_labels["last"].configure(text=last["time"].strftime("%Y-%m-%d %H:%M:%S") if last else "Aguardando primeira resposta")
        self.detail_labels["last_latency"].configure(text=f'{last["latency"]:.1f} ms' if last and last["online"] and last["latency"] is not None else "Sem resposta")
        self.detail_labels["minmax"].configure(text=f'{m["min"]:.1f} / {m["max"]:.1f} ms' if m["min"] is not None else "—")
        self.detail_labels["avg"].configure(text=f'{m["avg"]:.1f} ms' if m["avg"] is not None else "—")
        self.detail_labels["jitter"].configure(text=f'{m["jitter"]:.1f} ms' if m["jitter"] is not None else "—")
        self.detail_labels["moving"].configure(text=f'{m["moving"]:.1f} ms' if m["moving"] is not None else "—")
        self.detail_labels["loss"].configure(text=f'{m["loss"]:.1f}% ({sum(1 for sample in m["samples"] if not sample["online"])}/{len(m["samples"])} falhas)' if m["samples"] else "—")
        self.detail_labels["samples"].configure(text=f'{len(m["samples"])} / {HISTORY_SIZE}')
        total = len(m["samples"])
        received = sum(1 for sample in m["samples"] if sample["online"])
        self.detail_labels["uptime"].configure(text=f'{received / total * 100:.1f}%' if total else "—")

    def select_host(self, _event=None):
        selection = self.tree.selection()
        if not selection:
            return
        vals = self.tree.item(selection[0], "values")
        if not vals:
            return
        host = next((h for h, d in self.host_data.items() if d.get("iid") == selection[0]), vals[0])
        if host != self.selected_host:
            self.selected_host = host
            self.latency_history.clear()
            self.history_times.clear()
            for sample in list(self.host_data[host]["samples"]):
                self.latency_history.append(sample["latency"] if sample["online"] else None)
                self.history_times.append(sample["time"])
            self.refresh_details()
            self.draw_latency_chart()
            self.update_dashboard()

    def show_alert_popup(self, host, alerts):
        """Notificação compacta incorporada à janela principal, estilo toast."""
        if not alerts:
            return
        self.dismiss_alert_popup()
        is_offline = any("OFFLINE" in message.upper() for message in alerts)
        is_zero = any("ZERADO" in message.upper() for message in alerts)
        accent = RED if is_offline else (BLUE if is_zero else AMBER)
        heading = "HOST OFFLINE" if is_offline else ("PING ZERADO" if is_zero else "ALERTA DE REDE")

        popup = ctk.CTkFrame(self, fg_color="#111923", corner_radius=10,
                             border_width=1, border_color=accent, width=330, height=88)
        self.alert_popup = popup
        popup.place(relx=1.0, x=-18, y=62, anchor="ne")
        popup.lift()
        popup.grid_propagate(False)
        popup.grid_columnconfigure(0, weight=1)
        popup.grid_rowconfigure(1, weight=1)

        top = ctk.CTkFrame(popup, fg_color="transparent", height=27)
        top.grid(row=0, column=0, sticky="ew", padx=(10, 5), pady=(5, 0))
        top.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(top, text=f"●  {heading}", text_color=accent,
                     font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w")
        ctk.CTkButton(top, text="×", width=19, height=19, corner_radius=5,
                      fg_color="transparent", hover_color="#263449", text_color="#AAB5C4",
                      font=("Segoe UI", 13), command=self.dismiss_alert_popup
                      ).grid(row=0, column=1, sticky="e")
        message = f"{host}  ·  " + " | ".join(alerts)
        ctk.CTkLabel(popup, text=message, text_color=TEXT,
                     font=("Segoe UI", 10), anchor="w", justify="left",
                     wraplength=295).grid(row=1, column=0, sticky="ew", padx=11, pady=(0, 8))
        self.alert_popup_after_id = self.after(5500, self.dismiss_alert_popup)

    def dismiss_alert_popup(self, popup=None):
        target = popup or self.alert_popup
        if self.alert_popup_after_id is not None:
            try:
                self.after_cancel(self.alert_popup_after_id)
            except Exception:
                pass
            self.alert_popup_after_id = None
        try:
            if target is not None and target.winfo_exists():
                target.destroy()
        except Exception:
            pass
        if target is self.alert_popup or popup is None:
            self.alert_popup = None

    def record_alert(self, host, alerts):
        timestamp = datetime.now().strftime("%H:%M:%S")
        entry = f"[{timestamp}] {host} — " + " | ".join(alerts)
        self.alert_history.appendleft(entry)
        self.btn_alerts.configure(text=f"⚑ Alertas ({len(self.alert_history)}) {'▴' if self.alert_dropdown_open else '▾'}")
        if self.alert_dropdown_open:
            self.refresh_alert_dropdown()
        self.alert_box.configure(state="normal")
        self.alert_box.delete("1.0", "end")
        self.alert_box.insert("1.0", "\n".join(list(self.alert_history)[:6]) or "Sem alertas registrados.")
        self.alert_box.configure(state="disabled")

    def toggle_alert_dropdown(self):
        if self.alert_dropdown_open:
            self.close_alert_dropdown()
            return
        if self.alert_dropdown is None or not self.alert_dropdown.winfo_exists():
            panel = ctk.CTkFrame(self, fg_color="#111923", corner_radius=10,
                                 border_width=1, border_color=BORDER, width=390, height=330)
            self.alert_dropdown = panel
            panel.place(relx=1.0, x=-18, y=104, anchor="ne")
            panel.lift()
            panel.grid_propagate(False)
            panel.grid_rowconfigure(1, weight=1)
            panel.grid_columnconfigure(0, weight=1)
            top = ctk.CTkFrame(panel, fg_color="transparent")
            top.grid(row=0, column=0, sticky="ew", padx=12, pady=(10, 6))
            top.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(top, text="HISTÓRICO DE ALERTAS", text_color=TEXT,
                         font=("Segoe UI", 12, "bold")).grid(row=0, column=0, sticky="w")
            ctk.CTkButton(top, text="×", width=24, height=23, corner_radius=6,
                          fg_color="transparent", hover_color="#263449", text_color=MUTED,
                          command=self.close_alert_dropdown).grid(row=0, column=1, sticky="e")
            self.alert_dropdown_items = ctk.CTkScrollableFrame(
                panel, fg_color=PANEL, corner_radius=8,
                scrollbar_button_color="#40546A", scrollbar_button_hover_color="#58718D")
            self.alert_dropdown_items.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        # close_alert_dropdown usa place_forget; ao reabrir, é necessário
        # posicionar novamente o mesmo painel (não basta chamar lift()).
        self.alert_dropdown.place(relx=1.0, x=-18, y=104, anchor="ne")
        self.alert_dropdown_open = True
        self.btn_alerts.configure(text=f"⚑ Alertas ({len(self.alert_history)}) ▴")
        self.refresh_alert_dropdown()
        self.alert_dropdown.lift()

    def refresh_alert_dropdown(self):
        if self.alert_dropdown_items is None:
            return
        try:
            for child in self.alert_dropdown_items.winfo_children():
                child.destroy()
            if not self.alert_history:
                ctk.CTkLabel(self.alert_dropdown_items, text="Nenhum alerta registrado ainda.",
                             text_color=MUTED, font=("Segoe UI", 10)).pack(anchor="w", padx=8, pady=10)
                return
            for entry in self.alert_history:
                item = ctk.CTkFrame(self.alert_dropdown_items, fg_color="#1A2430", corner_radius=7)
                item.pack(fill="x", padx=3, pady=3)
                ctk.CTkLabel(item, text=entry, text_color=TEXT, font=("Segoe UI", 10),
                             anchor="w", justify="left", wraplength=330).pack(fill="x", padx=9, pady=8)
        except Exception:
            pass

    def close_alert_dropdown(self):
        self.alert_dropdown_open = False
        if self.alert_dropdown is not None:
            try:
                self.alert_dropdown.place_forget()
            except Exception:
                pass
        self.btn_alerts.configure(text=f"⚑ Alertas ({len(self.alert_history)}) ▾")

    def open_alert_center(self):
        # Compatibilidade com chamadas antigas: abre o painel incorporado.
        self.toggle_alert_dropdown()

    def filter_host_from_alert(self, host, popup=None):
        if host in self.host_data:
            data = self.host_data[host]
            label = host if not data.get("ip") or data["ip"] == host else f'{host} ({data["ip"]})'
            self.filter_var.set(label)
            self.change_ip_filter(label)
        if popup is not None:
            self.dismiss_alert_popup(popup)

    def check_alerts(self, host):
        metrics = self.host_metrics(host)
        last = metrics["last"]
        current = {}
        if last and not last["online"]:
            current["offline"] = f"{host}: HOST OFFLINE (sem resposta ICMP)"
        if last and last["online"] and last["latency"] is not None:
            if last["latency"] > 100:
                current["high_ping"] = f"{host}: ping alto ({last['latency']:.1f} ms)"
            if last["latency"] <= 0:
                current["zero_ping"] = f"{host}: PING ZERADO (0 ms)"
        if len(metrics["samples"]) >= 5 and metrics["loss"] > 5:
            current["packet_loss"] = f"{host}: perda de pacotes {metrics['loss']:.1f}%"

        previous = self.active_alerts.get(host, set())
        newly_triggered = [message for key, message in current.items() if key not in previous]
        self.active_alerts[host] = set(current)
        # Notifica apenas na entrada em um estado de alerta; não repete a cada ping.
        if newly_triggered:
            self.events.put(("alert_display", host, newly_triggered))

    def run_traceroute(self):
        host = self.selected_host
        if not host:
            messagebox.showinfo("Traceroute", "Selecione um host na tabela primeiro.")
            return
        self.traceroute_text.delete("1.0", "end")
        self.traceroute_text.insert("1.0", f"Executando traceroute para {host}...")
        threading.Thread(target=lambda: self.events.put(("traceroute", host, traceroute_host(host))), daemon=True).start()

    def export_csv(self):
        if not self.host_data:
            messagebox.showinfo("Exportar CSV", "Inicie o monitoramento antes de exportar.")
            return
        path = filedialog.asksaveasfilename(title="Exportar resultados", defaultextension=".csv",
                                            filetypes=[("Arquivo CSV", "*.csv")],
                                            initialfile="opmon_monitoramento.csv")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f, delimiter=";")
                writer.writerow(["ALVO", "IP", "HOSTNAME", "STATUS", "PING_ATUAL_MS",
                                 "PING_MIN_MS", "PING_MAX_MS", "PING_MEDIO_MS", "PERDA_PCT",
                                 "TTL", "JITTER_MS", "ULTIMA_RESPOSTA", "MAC_ARP", "GATEWAY"])
                writer.writerows(self.csv_rows)
            messagebox.showinfo("Exportação concluída", f"Arquivo salvo em:\n{path}")
        except OSError as exc:
            messagebox.showerror("Erro ao exportar", str(exc))

    def clear_data(self):
        if self.monitoring:
            messagebox.showwarning("OPMON", "Pare o monitoramento antes de limpar os dados.")
            return
        self.host_data.clear()
        self.csv_rows.clear()
        self.tree.delete(*self.tree.get_children())
        self.latency_history.clear()
        self.history_times.clear()
        self.selected_host = None
        self.filter_var.set("Todos os IPs")
        self.refresh_filter_options()
        for label in [self.stat_total, self.stat_online, self.stat_offline]:
            label.configure(text="0")
        self.stat_latency.configure(text="—")
        self.stat_loss.configure(text="—")
        for label in self.detail_labels.values():
            label.configure(text="—")
        self.draw_latency_chart()
        self.draw_donut_chart()

    def process_events(self):
        try:
            while True:
                try:
                    event = self.events.get_nowait()
                except queue.Empty:
                    break
                try:
                    if event[0] == "network_info":
                        _, gateway, public = event
                        self.gateway, self.public_info = gateway, public
                        self.lbl_gateway.configure(text=gateway)
                        self.lbl_public_ip.configure(text=public["ip"])
                        self.lbl_geo.configure(text=f'{public["city"]}, {public["country"]} • {public["asn"]} • {public["org"]}')
                    elif event[0] == "dns":
                        _, host, hostname, ip, mac = event
                        if host in self.host_data:
                            self.host_data[host].update({"hostname": hostname, "ip": ip, "mac": mac})
                            self.refresh_tree_row(host)
                            if host == self.selected_host:
                                self.refresh_details()
                            self.refresh_filter_options()
                    elif event[0] == "ping":
                        _, host, result = event
                        if host in self.host_data:
                            self.host_data[host]["samples"].append(result)
                            if host == self.selected_host:
                                self.latency_history.append(result["latency"] if result["online"] else None)
                                self.history_times.append(result["time"])
                                self.refresh_details()
                                self.draw_latency_chart()
                            self.refresh_tree_row(host)
                            self.check_alerts(host)
                            self.update_dashboard()
                    elif event[0] == "traceroute":
                        _, host, output = event
                        if host == self.selected_host:
                            self.traceroute_text.delete("1.0", "end")
                            self.traceroute_text.insert("1.0", output)
                    elif event[0] == "alert_display":
                        _, host, alerts = event
                        self.record_alert(host, alerts)
                        self.show_alert_popup(host, alerts)
                except Exception as exc:
                    # Um evento defeituoso não pode interromper a atualização contínua da interface.
                    try:
                        print(f"Erro ao atualizar evento do monitoramento: {exc}")
                    except Exception:
                        pass
        finally:
            # Sempre reagenda o consumidor de eventos, mesmo se um widget falhar.
            try:
                self.after(100, self.process_events)
            except tk.TclError:
                pass


if __name__ == "__main__":
    app = NetworkMonitor()
    app.mainloop()
