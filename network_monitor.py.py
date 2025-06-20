import sys
import socket
import threading
import time
import psutil
import platform
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from collections import defaultdict, deque

class PortMonitor:
    def __init__(self):
        self.monitored_ports = {80, 443}  # Domyślnie monitorowane porty HTTP i HTTPS
        self.running = False
        self.data_lock = threading.Lock()
        self.reset_stats()
        self.history = deque(maxlen=1000)  # Historia ostatnich 1000 pomiarów
        self.alarms = []
        self.local_ip = self.get_local_ip()
        
    def get_local_ip(self):
        """Pobiera lokalny adres IP komputera"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    def reset_stats(self):
        """Resetuje statystyki monitorowania"""
        with self.data_lock:
            self.stats = {
                'total_recv': 0,
                'total_sent': 0,
                'connections': defaultdict(lambda: {
                    'recv': 0,
                    'sent': 0,
                    'start_time': time.time(),
                    'last_update': time.time()
                }),
                'port_stats': defaultdict(lambda: {
                    'recv': 0,
                    'sent': 0,
                    'connections': set()
                })
            }
    
    def add_port(self, port):
        """Dodaje port do monitorowania"""
        with self.data_lock:
            self.monitored_ports.add(int(port))
    
    def remove_port(self, port):
        """Usuwa port z monitorowania"""
        with self.data_lock:
            port = int(port)
            if port in self.monitored_ports:
                self.monitored_ports.remove(port)
    
    def add_alarm(self, port, direction, limit):
        """Dodaje alarm dla określonego portu i kierunku transferu"""
        with self.data_lock:
            self.alarms.append({
                'port': int(port),
                'direction': direction,
                'limit': limit,
                'triggered': False
            })
    
    def remove_alarm(self, index):
        """Usuwa alarm o podanym indeksie"""
        with self.data_lock:
            if 0 <= index < len(self.alarms):
                del self.alarms[index]
    
    def get_stats(self):
        """Zwraca aktualne statystyki"""
        with self.data_lock:
            return {
                'total_recv': self.stats['total_recv'],
                'total_sent': self.stats['total_sent'],
                'connections': dict(self.stats['connections']),
                'port_stats': dict(self.stats['port_stats']),
                'monitored_ports': list(self.monitored_ports),
                'alarms': list(self.alarms)
            }
    
    def get_history(self):
        """Zwraca historię pomiarów"""
        with self.data_lock:
            return list(self.history)
    
    def start(self):
        """Uruchamia monitorowanie"""
        if self.running:
            return
            
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_connections)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def stop(self):
        """Zatrzymuje monitorowanie"""
        self.running = False
    
    def _monitor_connections(self):
        """Główna pętla monitorująca połączenia sieciowe"""
        last_connections = set()
        
        while self.running:
            try:
                # Pobierz aktualne połączenia sieciowe
                current_connections = set()
                for conn in psutil.net_connections(kind='inet'):
                    if conn.status == 'ESTABLISHED' and conn.laddr and conn.raddr:
                        # Sprawdź, czy port lokalny jest w monitorowanych portach
                        local_port = conn.laddr.port
                        if local_port in self.monitored_ports:
                            key = (conn.laddr.ip, conn.laddr.port, conn.raddr.ip, conn.raddr.port)
                            current_connections.add(key)
                            
                            # Dodaj nowe połączenie do statystyk
                            if key not in self.stats['connections']:
                                with self.data_lock:
                                    self.stats['connections'][key] = {
                                        'recv': 0,
                                        'sent': 0,
                                        'start_time': time.time(),
                                        'last_update': time.time()
                                    }
                                    self.stats['port_stats'][local_port]['connections'].add(key)
                
                # Usuń zakończone połączenia
                for key in list(self.stats['connections'].keys()):
                    if key not in current_connections:
                        with self.data_lock:
                            del self.stats['connections'][key]
                            for port_stat in self.stats['port_stats'].values():
                                if key in port_stat['connections']:
                                    port_stat['connections'].remove(key)
                
                # Aktualizuj statystyki transferu danych
                net_io = psutil.net_io_counters(pernic=False)
                with self.data_lock:
                    # Aktualizuj statystyki dla każdego połączenia
                    for key in current_connections:
                        # Pobierz statystyki dla procesu (uproszczone)
                        # W rzeczywistości potrzebowalibyśmy bardziej zaawansowanego śledzenia
                        # Dla uproszczenia używamy ogólnych statystyk
                        conn = self.stats['connections'][key]
                        elapsed = time.time() - conn['last_update']
                        conn['recv'] += net_io.bytes_recv - self.stats.get('last_recv', 0)
                        conn['sent'] += net_io.bytes_sent - self.stats.get('last_sent', 0)
                        conn['last_update'] = time.time()
                        
                        # Aktualizuj statystyki portu
                        port = key[1]
                        self.stats['port_stats'][port]['recv'] += net_io.bytes_recv - self.stats.get('last_recv', 0)
                        self.stats['port_stats'][port]['sent'] += net_io.bytes_sent - self.stats.get('last_sent', 0)
                    
                    # Aktualizuj statystyki ogólne
                    self.stats['total_recv'] += net_io.bytes_recv - self.stats.get('last_recv', 0)
                    self.stats['total_sent'] += net_io.bytes_sent - self.stats.get('last_sent', 0)
                    self.stats['last_recv'] = net_io.bytes_recv
                    self.stats['last_sent'] = net_io.bytes_sent
                    
                    # Dodaj aktualny stan do historii
                    self.history.append({
                        'timestamp': datetime.now(),
                        'total_recv': self.stats['total_recv'],
                        'total_sent': self.stats['total_sent'],
                        'port_stats': dict(self.stats['port_stats'])
                    })
                
                # Sprawdź alarmy
                self._check_alarms()
                
                time.sleep(1)
            except Exception as e:
                print(f"Błąd monitorowania: {e}")
                time.sleep(5)
    
    def _check_alarms(self):
        """Sprawdza, czy którykolwiek alarm został przekroczony"""
        with self.data_lock:
            for alarm in self.alarms:
                port = alarm['port']
                if port in self.stats['port_stats']:
                    value = self.stats['port_stats'][port]['recv' if alarm['direction'] == 'download' else 'sent']
                    if value >= alarm['limit'] and not alarm['triggered']:
                        alarm['triggered'] = True
                        # Zwróć informację o alarmie
                        return {
                            'port': port,
                            'direction': alarm['direction'],
                            'value': value,
                            'limit': alarm['limit']
                        }
        return None

class NetworkMonitorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Monitor Transferu Danych przez Porty")
        self.geometry("1200x800")
        self.monitor = PortMonitor()
        
        # Utwórz interfejs
        self.create_widgets()
        
        # Uruchom aktualizację UI
        self.update_ui()
        
        # Uruchom monitorowanie
        self.monitor.start()
        
        # Ustaw obsługę zamknięcia okna
        self.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def create_widgets(self):
        # Tworzenie zakładek
        tab_control = ttk.Notebook(self)
        
        # Zakładka monitorowania w czasie rzeczywistym
        realtime_tab = ttk.Frame(tab_control)
        tab_control.add(realtime_tab, text='Monitor w czasie rzeczywistym')
        self.create_realtime_tab(realtime_tab)
        
        # Zakładka zarządzania portami
        ports_tab = ttk.Frame(tab_control)
        tab_control.add(ports_tab, text='Zarządzanie portami')
        self.create_ports_tab(ports_tab)
        
        # Zakładka alarmów
        alarms_tab = ttk.Frame(tab_control)
        tab_control.add(alarms_tab, text='Zarządzanie alarmami')
        self.create_alarms_tab(alarms_tab)
        
        # Zakładka raportów
        reports_tab = ttk.Frame(tab_control)
        tab_control.add(reports_tab, text='Raporty historyczne')
        self.create_reports_tab(reports_tab)
        
        tab_control.pack(expand=1, fill="both")
        
        # Panel statusu
        self.status_var = tk.StringVar(value="Gotowy do monitorowania")
        status_bar = ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def create_realtime_tab(self, parent):
        # Ramka z ogólnymi statystykami
        stats_frame = ttk.LabelFrame(parent, text="Ogólne statystyki")
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Pole lokalnego adresu IP
        ttk.Label(stats_frame, text="Lokalny adres IP:").grid(row=0, column=0, padx=5, pady=2, sticky=tk.W)
        self.local_ip_var = tk.StringVar(value=self.monitor.local_ip)
        ttk.Label(stats_frame, textvariable=self.local_ip_var).grid(row=0, column=1, padx=5, pady=2, sticky=tk.W)
        
        # Pole pobranych danych
        ttk.Label(stats_frame, text="Pobrane dane:").grid(row=1, column=0, padx=5, pady=2, sticky=tk.W)
        self.total_recv_var = tk.StringVar(value="0 B")
        ttk.Label(stats_frame, textvariable=self.total_recv_var).grid(row=1, column=1, padx=5, pady=2, sticky=tk.W)
        
        # Pole wysłanych danych
        ttk.Label(stats_frame, text="Wysłane dane:").grid(row=2, column=0, padx=5, pady=2, sticky=tk.W)
        self.total_sent_var = tk.StringVar(value="0 B")
        ttk.Label(stats_frame, textvariable=self.total_sent_var).grid(row=2, column=1, padx=5, pady=2, sticky=tk.W)
        
        # Statystyki per port
        port_stats_frame = ttk.LabelFrame(parent, text="Statystyki per port")
        port_stats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Tabela z portami
        columns = ("port", "recv", "sent", "connections")
        self.port_tree = ttk.Treeview(port_stats_frame, columns=columns, show="headings")
        
        # Konfiguracja kolumn
        self.port_tree.heading("port", text="Port")
        self.port_tree.heading("recv", text="Pobrane (B)")
        self.port_tree.heading("sent", text="Wysłane (B)")
        self.port_tree.heading("connections", text="Aktywne połączenia")
        
        self.port_tree.column("port", width=100)
        self.port_tree.column("recv", width=150)
        self.port_tree.column("sent", width=150)
        self.port_tree.column("connections", width=150)
        
        # Pasek przewijania
        scrollbar = ttk.Scrollbar(port_stats_frame, orient=tk.VERTICAL, command=self.port_tree.yview)
        self.port_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.port_tree.pack(fill=tk.BOTH, expand=True)
        
        # Aktywne połączenia
        connections_frame = ttk.LabelFrame(parent, text="Aktywne połączenia")
        connections_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        columns = ("local", "remote", "recv", "sent", "duration")
        self.conn_tree = ttk.Treeview(connections_frame, columns=columns, show="headings")
        
        # Konfiguracja kolumn
        self.conn_tree.heading("local", text="Lokalny adres")
        self.conn_tree.heading("remote", text="Zdalny adres")
        self.conn_tree.heading("recv", text="Pobrane (B)")
        self.conn_tree.heading("sent", text="Wysłane (B)")
        self.conn_tree.heading("duration", text="Czas trwania")
        
        self.conn_tree.column("local", width=150)
        self.conn_tree.column("remote", width=150)
        self.conn_tree.column("recv", width=100)
        self.conn_tree.column("sent", width=100)
        self.conn_tree.column("duration", width=100)
        
        # Pasek przewijania
        scrollbar = ttk.Scrollbar(connections_frame, orient=tk.VERTICAL, command=self.conn_tree.yview)
        self.conn_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.conn_tree.pack(fill=tk.BOTH, expand=True)
    
    def create_ports_tab(self, parent):
        # Dodawanie portu
        add_frame = ttk.LabelFrame(parent, text="Dodaj port do monitorowania")
        add_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(add_frame, text="Numer portu:").grid(row=0, column=0, padx=5, pady=5)
        self.port_entry = ttk.Entry(add_frame, width=10)
        self.port_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(add_frame, text="Dodaj port", command=self.add_port).grid(row=0, column=2, padx=5, pady=5)
        
        # Usuwanie portu
        remove_frame = ttk.LabelFrame(parent, text="Usuń port z monitorowania")
        remove_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(remove_frame, text="Wybierz port:").grid(row=0, column=0, padx=5, pady=5)
        self.port_remove_var = tk.StringVar()
        port_remove_combo = ttk.Combobox(remove_frame, textvariable=self.port_remove_var)
        port_remove_combo.grid(row=0, column=1, padx=5, pady=5)
        self.port_remove_combo = port_remove_combo
        
        ttk.Button(remove_frame, text="Usuń port", command=self.remove_port).grid(row=0, column=2, padx=5, pady=5)
        
        # Lista monitorowanych portów
        ports_frame = ttk.LabelFrame(parent, text="Monitorowane porty")
        ports_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        columns = ("port", "status")
        self.ports_tree = ttk.Treeview(ports_frame, columns=columns, show="headings")
        
        self.ports_tree.heading("port", text="Port")
        self.ports_tree.heading("status", text="Status")
        
        self.ports_tree.column("port", width=100)
        self.ports_tree.column("status", width=100)
        
        scrollbar = ttk.Scrollbar(ports_frame, orient=tk.VERTICAL, command=self.ports_tree.yview)
        self.ports_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.ports_tree.pack(fill=tk.BOTH, expand=True)
    
    def create_alarms_tab(self, parent):
        # Dodawanie alarmu
        add_frame = ttk.LabelFrame(parent, text="Dodaj nowy alarm")
        add_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Wybór portu
        ttk.Label(add_frame, text="Port:").grid(row=0, column=0, padx=5, pady=5)
        self.alarm_port_var = tk.StringVar()
        alarm_port_combo = ttk.Combobox(add_frame, textvariable=self.alarm_port_var)
        alarm_port_combo.grid(row=0, column=1, padx=5, pady=5)
        self.alarm_port_combo = alarm_port_combo
        
        # Kierunek transferu
        ttk.Label(add_frame, text="Kierunek:").grid(row=0, column=2, padx=5, pady=5)
        self.alarm_direction_var = tk.StringVar(value="download")
        ttk.Combobox(add_frame, textvariable=self.alarm_direction_var, 
                    values=["download", "upload"], state="readonly").grid(row=0, column=3, padx=5, pady=5)
        
        # Limit
        ttk.Label(add_frame, text="Limit (bajty):").grid(row=0, column=4, padx=5, pady=5)
        self.alarm_limit_entry = ttk.Entry(add_frame, width=15)
        self.alarm_limit_entry.grid(row=0, column=5, padx=5, pady=5)
        
        ttk.Button(add_frame, text="Dodaj alarm", command=self.add_alarm).grid(row=0, column=6, padx=5, pady=5)
        
        # Lista alarmów
        alarms_frame = ttk.LabelFrame(parent, text="Aktywne alarmy")
        alarms_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        columns = ("port", "direction", "limit", "status")
        self.alarms_tree = ttk.Treeview(alarms_frame, columns=columns, show="headings")
        
        self.alarms_tree.heading("port", text="Port")
        self.alarms_tree.heading("direction", text="Kierunek")
        self.alarms_tree.heading("limit", text="Limit (B)")
        self.alarms_tree.heading("status", text="Status")
        
        self.alarms_tree.column("port", width=100)
        self.alarms_tree.column("direction", width=100)
        self.alarms_tree.column("limit", width=150)
        self.alarms_tree.column("status", width=100)
        
        scrollbar = ttk.Scrollbar(alarms_frame, orient=tk.VERTICAL, command=self.alarms_tree.yview)
        self.alarms_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.alarms_tree.pack(fill=tk.BOTH, expand=True)
        
        # Przycisk usuwania alarmu
        ttk.Button(alarms_frame, text="Usuń zaznaczony alarm", command=self.remove_selected_alarm).pack(pady=5)
    
    def create_reports_tab(self, parent):
        # Kontrolki raportów
        controls_frame = ttk.Frame(parent)
        controls_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Wybór portu
        ttk.Label(controls_frame, text="Port:").pack(side=tk.LEFT, padx=5)
        self.report_port_var = tk.StringVar()
        report_port_combo = ttk.Combobox(controls_frame, textvariable=self.report_port_var, width=10)
        report_port_combo.pack(side=tk.LEFT, padx=5)
        self.report_port_combo = report_port_combo
        
        # Zakres czasowy
        ttk.Label(controls_frame, text="Zakres czasowy:").pack(side=tk.LEFT, padx=5)
        self.report_range_var = tk.StringVar(value="10")
        ttk.Combobox(controls_frame, textvariable=self.report_range_var, 
                    values=["5", "10", "30", "60"], width=5, state="readonly").pack(side=tk.LEFT, padx=5)
        
        # Przycisk generowania raportu
        ttk.Button(controls_frame, text="Generuj raport", command=self.generate_report).pack(side=tk.LEFT, padx=10)
        
        # Wykres
        fig, self.ax = plt.subplots(figsize=(10, 6))
        self.canvas = FigureCanvasTkAgg(fig, master=parent)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Dziennik zdarzeń
        log_frame = ttk.LabelFrame(parent, text="Dziennik zdarzeń")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text.config(state=tk.DISABLED)
    
    def add_port(self):
        port = self.port_entry.get()
        if port and port.isdigit():
            self.monitor.add_port(int(port))
            self.port_entry.delete(0, tk.END)
            self.log_event(f"Dodano port {port} do monitorowania")
        else:
            messagebox.showerror("Błąd", "Proszę podać poprawny numer portu")
    
    def remove_port(self):
        port = self.port_remove_var.get()
        if port:
            self.monitor.remove_port(port)
            self.log_event(f"Usunięto port {port} z monitorowania")
    
    def add_alarm(self):
        port = self.alarm_port_var.get()
        direction = self.alarm_direction_var.get()
        limit = self.alarm_limit_entry.get()
        
        if not port or not direction or not limit:
            messagebox.showerror("Błąd", "Wszystkie pola są wymagane")
            return
            
        if not limit.isdigit():
            messagebox.showerror("Błąd", "Limit musi być liczbą całkowitą")
            return
            
        self.monitor.add_alarm(port, direction, int(limit))
        self.alarm_limit_entry.delete(0, tk.END)
        self.log_event(f"Dodano alarm dla portu {port}: {direction} > {limit} bajtów")
    
    def remove_selected_alarm(self):
        selected = self.alarms_tree.selection()
        if selected:
            index = self.alarms_tree.index(selected[0])
            self.monitor.remove_alarm(index)
            self.log_event(f"Usunięto alarm {index}")
    
    def generate_report(self):
        # Ta metoda generowałaby raport na podstawie historii
        # W tej wersji demonstracyjnej po prostu logujemy akcję
        port = self.report_port_var.get()
        time_range = self.report_range_var.get()
        self.log_event(f"Wygenerowano raport dla portu {port}, zakres: {time_range} minut")
        
        # Tutaj dodano by kod do generowania wykresu na podstawie historii
        
    def log_event(self, message):
        """Dodaje wpis do dziennika zdarzeń"""
        self.log_text.config(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.config(state=tk.DISABLED)
        self.log_text.see(tk.END)
    
    def update_ui(self):
        """Aktualizuje interfejs użytkownika na podstawie danych z monitora"""
        try:
            stats = self.monitor.get_stats()
            
            # Aktualizuj ogólne statystyki
            self.total_recv_var.set(self.format_bytes(stats['total_recv']))
            self.total_sent_var.set(self.format_bytes(stats['total_sent']))
            
            # Aktualizuj listę portów
            self.update_port_list(stats['monitored_ports'])
            
            # Aktualizuj statystyki per port
            self.update_port_stats(stats['port_stats'])
            
            # Aktualizuj aktywne połączenia
            self.update_connections(stats['connections'])
            
            # Aktualizuj alarmy
            self.update_alarms(stats['alarms'])
            
            # Sprawdź, czy nie ma nowych alarmów
            alarm = self.monitor._check_alarms()
            if alarm:
                message = (f"ALARM! Przekroczono limit dla portu {alarm['port']} "
                          f"({alarm['direction']}): {alarm['value']} > {alarm['limit']} bajtów")
                self.log_event(message)
                messagebox.showwarning("Alarm", message)
            
        except Exception as e:
            print(f"Błąd aktualizacji UI: {e}")
        
        # Ponownie zaplanuj aktualizację
        self.after(1000, self.update_ui)
    
    def update_port_list(self, ports):
        """Aktualizuje listę monitorowanych portów"""
        # Aktualizuj comboboxy
        if ports:
            self.port_remove_combo['values'] = ports
            self.alarm_port_combo['values'] = ports
            self.report_port_combo['values'] = ports
            
            if not self.port_remove_var.get() and ports:
                self.port_remove_var.set(str(ports[0]))
            if not self.alarm_port_var.get() and ports:
                self.alarm_port_var.set(str(ports[0]))
            if not self.report_port_var.get() and ports:
                self.report_port_var.set(str(ports[0]))
        
        # Aktualizuj drzewo portów
        for item in self.ports_tree.get_children():
            self.ports_tree.delete(item)
        
        for port in ports:
            self.ports_tree.insert("", tk.END, values=(port, "Aktywny"))
    
    def update_port_stats(self, port_stats):
        """Aktualizuje statystyki per port"""
        for item in self.port_tree.get_children():
            self.port_tree.delete(item)
        
        for port, stats in port_stats.items():
            self.port_tree.insert("", tk.END, values=(
                port,
                self.format_bytes(stats['recv']),
                self.format_bytes(stats['sent']),
                len(stats['connections'])
            ))
    
    def update_connections(self, connections):
        """Aktualizuje listę aktywnych połączeń"""
        for item in self.conn_tree.get_children():
            self.conn_tree.delete(item)
        
        for key, stats in connections.items():
            local_addr = f"{key[0]}:{key[1]}"
            remote_addr = f"{key[2]}:{key[3]}"
            duration = time.strftime("%H:%M:%S", time.gmtime(time.time() - stats['start_time']))
            
            self.conn_tree.insert("", tk.END, values=(
                local_addr,
                remote_addr,
                self.format_bytes(stats['recv']),
                self.format_bytes(stats['sent']),
                duration
            ))
    
    def update_alarms(self, alarms):
        """Aktualizuje listę alarmów"""
        for item in self.alarms_tree.get_children():
            self.alarms_tree.delete(item)
        
        for i, alarm in enumerate(alarms):
            status = "Aktywny" if not alarm['triggered'] else "TRIGGERED"
            self.alarms_tree.insert("", tk.END, values=(
                alarm['port'],
                alarm['direction'],
                alarm['limit'],
                status
            ))
    
    def format_bytes(self, size):
        """Formatuje bajty do czytelnej postaci"""
        power = 2**10
        n = 0
        power_labels = {0: 'B', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
        while size > power and n < len(power_labels) - 1:
            size /= power
            n += 1
        return f"{size:.2f} {power_labels[n]}"
    
    def on_close(self):
        """Obsługa zamknięcia aplikacji"""
        self.monitor.stop()
        self.destroy()

if __name__ == "__main__":
    # Sprawdź, czy użytkownik ma odpowiednie uprawnienia
    if platform.system() != "Windows" and os.geteuid() != 0:
        print("Aplikacja wymaga uprawnień administratora (root).")
        sys.exit(1)
    
    app = NetworkMonitorApp()
    app.mainloop()