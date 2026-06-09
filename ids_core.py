import time
import threading
import socket
import os
import sys
import select
import tty
import termios
import smtplib
import bcrypt
from datetime import datetime, timedelta
from email.message import EmailMessage
from scapy.all import sniff, Ether, IP, TCP, UDP, DNSQR, Raw
from sqlalchemy.exc import IntegrityError
from ipwhois import IPWhois
from dotenv import load_dotenv
# Al inicio del archivo, agrega este import
from concurrent.futures import ThreadPoolExecutor
from actualizar_threats import descargar_lista_inteligencia
# Pool de hilos persistente (no daemon, no muere solo)
EMAIL_POOL = ThreadPoolExecutor(max_workers=3)
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.align import Align
from rich.text import Text
from rich.console import Console
from zoneinfo import ZoneInfo
from datetime import datetime, timedelta

from utils import es_ip_valida, es_mac_valida, actualizar_env
load_dotenv()
from modelos_db import Session, EquipoAutorizado, BitacoraTrafico, RegistroAmenazas, UsuarioIAM, ListaNegraIP

# ==========================================
# VARIABLES GLOBALES
# ==========================================
CACHE_EQUIPOS_AUTORIZADOS = {}
BLACKLIST_IPS = set()
RATE_LIMIT_CACHE = {}
RED_LOCAL_PREFIJO = ""


def hora_local():
    """Obtiene la hora de México y la limpia para que SQLite la entienda."""
    return datetime.now(ZoneInfo("America/Mexico_City")).replace(tzinfo=None)

TIEMPO_INICIO = hora_local()
SISTEMA_ACTIVO = True
OFFSET_PANTALLA = 0
PAUSA_INTERFAZ = False

# NUEVAS VARIABLES PARA EL FILTRO INFALIBLE
ULTIMO_ID_AMENAZA = 0
ULTIMO_ID_TRAFICO = 0

console = Console()

from utils import obtener_password_seguro

# ==========================================
# 1. AUTENTICACIÓN Y GESTIÓN IAM
# ==========================================
def autenticar_admin():
    print("\n--- INICIO DE SESIÓN ---")
    username = input("Usuario: ")
    password = obtener_password_seguro("Contraseña: ")

    local_session = Session()
    try:
        usuario = local_session.query(UsuarioIAM).filter_by(username=username).first()
        if usuario and bcrypt.checkpw(password.encode('utf-8'), usuario.password_hash.encode('utf-8')):
            print(f"[+] Acceso concedido. Bienvenido, {usuario.username} (Rol: {usuario.rol})")
            time.sleep(1)
            return usuario
        print("[-] Credenciales incorrectas.")
        time.sleep(1)
        return None
    finally:
        local_session.close()  # siempre se cierra


def gestionar_lista_blanca():
    local_session = Session()
    try:
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print("\n--- GESTIÓN DE LISTA BLANCA ---")
            print("1. Autorizar nuevo equipo")
            print("2. Revocar autorización")
            print("3. Ver equipos autorizados")
            print("4. Volver")
            opc = input("Seleccione: ").strip()

            if opc == "1":
                mac = input("MAC (ej. 08:00:27:63:b0:05): ").strip()
                ip = input("IP (ej. 192.168.1.1): ").strip()
                propietario = input("Propietario: ").strip()

                if not es_mac_valida(mac):
                    print("[-] Error: Dirección MAC inválida.")
                    time.sleep(2)
                    continue
                if not es_ip_valida(ip):
                    print("[-] Error: Dirección IP inválida.")
                    time.sleep(2)
                    continue
                if not propietario:
                    print("[-] Error: El nombre del propietario no puede estar vacío.")
                    time.sleep(2)
                    continue

                nuevo_equipo = EquipoAutorizado(
                    mac_address=mac, ip_address=ip,
                    propietario=propietario, activo=True
                )
                try:
                    local_session.add(nuevo_equipo)
                    local_session.commit()
                    print("[+] Equipo agregado correctamente.")
                except IntegrityError:
                    local_session.rollback()
                    print("[-] Error: Esta MAC ya existe en la base de datos.")
                time.sleep(2)

            elif opc == "2":
                mac = input("Ingrese la MAC del equipo a revocar: ").strip()
                equipo = local_session.query(EquipoAutorizado).filter_by(mac_address=mac).first()
                if equipo:
                    equipo.activo = False
                    local_session.commit()
                    print(f"[+] Autorización revocada para: {equipo.propietario}")
                else:
                    print("[-] Equipo no encontrado.")
                time.sleep(2)

            elif opc == "3":
                equipos = local_session.query(EquipoAutorizado).all()
                print(f"\n{'Estado':<8} {'MAC':<20} {'IP':<16} {'Propietario'}")
                print("-" * 60)
                for e in equipos:
                    estado = "ACTIVO" if e.activo else "REVOCADO"
                    print(f"{estado:<8} {e.mac_address:<20} {e.ip_address:<16} {e.propietario}")
                input("\nPresiona Enter para continuar...")

            elif opc == "4":
                break
    finally:
        local_session.close()


def gestionar_lista_negra():
    local_session = Session()
    try:
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print("\n--- GESTIÓN DE LISTA NEGRA ---")
            print("1. Registrar IP peligrosa")
            print("2. Remover IP")
            print("3. Ver lista negra")
            print("4. Cargar blacklist de base de datos externa (feodotracker)")
            print("5. Volver")
            opc = input("Seleccione: ").strip()

            if opc == "1":
                ip = input("Ingrese la IP externa maliciosa: ").strip()
                if not es_ip_valida(ip):
                    print("[-] Error: La IP ingresada no es válida.")
                    time.sleep(2)
                    continue
                desc = input("Tipo de riesgo (ej. Botnet, Ransomware): ").strip()
                nueva_ip = ListaNegraIP(ip_maliciosa=ip, descripcion=desc)
                try:
                    local_session.add(nueva_ip)
                    local_session.commit()
                    print("[+] IP bloqueada y registrada.")
                except IntegrityError:
                    local_session.rollback()
                    print("[-] La IP ya estaba en la lista negra.")
                time.sleep(2)

            elif opc == "2":
                ip = input("Ingrese la IP a remover: ").strip()
                registro = local_session.query(ListaNegraIP).filter_by(ip_maliciosa=ip).first()
                if registro:
                    local_session.delete(registro)
                    local_session.commit()
                    print("[+] IP removida de la lista negra.")
                else:
                    print("[-] IP no encontrada en la lista.")
                time.sleep(2)
            elif opc == "3":
                        ips = local_session.query(ListaNegraIP).all()
                        print(f"\n{'IP Maliciosa':<20} {'Descripción'}")
                        print("-" * 50)
                        if not ips:
                            print("La lista negra está vacía.")
                        else:
                            for entry in ips:
                                print(f"{entry.ip_maliciosa:<20} {entry.descripcion or 'Sin descripción'}")
                        input("\nPresiona Enter para continuar...")
            elif opc == "4":
                            # Aquí se ejecuta la función importada
                print("\n[*] Iniciando módulo de inteligencia de amenazas...")
                descargar_lista_inteligencia()
                input("\nPresiona Enter para continuar...")

            elif opc == "5":
                break
                
            else:
                print("[-] Opción no válida.")
                time.sleep(1)
                break
    finally:
        local_session.close()


def gestionar_configuracion_email():
    """Permite al ADMIN cambiar el correo remitente y la contraseña SMTP."""
    os.system('cls' if os.name == 'nt' else 'clear')
    print("\n--- CONFIGURACIÓN DE ALERTAS POR CORREO ---")
    print("Se actualizará el archivo .env con las nuevas credenciales.")
    print("IMPORTANTE: Usa una contraseña de aplicación de Gmail, no tu contraseña normal.\n")

    nuevo_email = input("Nuevo correo remitente (Enter para no cambiar): ").strip()
    nueva_pass = obtener_password_seguro("Nueva contraseña de aplicación (Enter para no cambiar): ")

    if nuevo_email:
        if "@" not in nuevo_email:
            print("[-] Correo inválido.")
            time.sleep(2)
            return
        actualizar_env("REMITENTE_EMAIL", nuevo_email)
        print("[+] Correo actualizado.")

    if nueva_pass:
        actualizar_env("REMITENTE_PASSWORD", nueva_pass)
        print("[+] Contraseña actualizada.")

    # Actualizar también el email del admin en la BD
    local_session = Session()
    try:
        admin = local_session.query(UsuarioIAM).filter_by(rol='ADMIN').first()
        if admin and nuevo_email:
            nuevo_dest = input("¿Correo DESTINO de alertas? (Enter para usar el mismo): ").strip()
            admin.email = nuevo_dest if nuevo_dest else nuevo_email
            local_session.commit()
            print("[+] Correo de destino de alertas actualizado.")
    finally:
        local_session.close()

    time.sleep(2)


def mostrar_listas():
    """Vista de solo lectura de ambas listas."""
    local_session = Session()
    try:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("\n===== LISTA BLANCA (Equipos Autorizados) =====")
        equipos = local_session.query(EquipoAutorizado).filter_by(activo=True).all()
        if equipos:
            print(f"{'MAC':<20} {'IP':<16} {'Propietario'}")
            print("-" * 55)
            for e in equipos:
                print(f"{e.mac_address:<20} {e.ip_address:<16} {e.propietario}")
        else:
            print("  (Sin equipos autorizados)")

        print("\n===== LISTA NEGRA (IPs Bloqueadas) =====")
        ips = local_session.query(ListaNegraIP).all()
        if ips:
            print(f"{'IP':<20} {'Descripción'}")
            print("-" * 45)
            for ip in ips:
                print(f"{ip.ip_maliciosa:<20} {ip.descripcion or 'Sin descripción'}")
        else:
            print("  (Lista negra vacía)")

        input("\nPresiona Enter para volver...")
    finally:
        local_session.close()


def menu_configuracion_iam(usuario_logueado):
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"=== PANEL IAM  |  Usuario: {usuario_logueado.username}  |  Rol: {usuario_logueado.rol} ===")
        print("1. Ver Listas (White/Black)")
        print("2. Modificar Lista Blanca       [Solo ADMIN]")
        print("3. Modificar Lista Negra        [Solo ADMIN]")
        print("4. Configuración de Email       [Solo ADMIN]")
        print("0. Volver al menú principal")

        opc = input("\nSelección: ").strip()

        if opc == "1":
            mostrar_listas()
        elif opc in ["2", "3", "4"]:
            if usuario_logueado.rol != 'ADMIN':
                print("[!] Acceso denegado: Se requiere rol ADMIN.")
                time.sleep(2)
                continue
            if opc == "2":
                gestionar_lista_blanca()
            elif opc == "3":
                gestionar_lista_negra()
            elif opc == "4":
                gestionar_configuracion_email()
        elif opc == "0":
            break


# ==========================================
# 2. SINCRONIZACIÓN Y SERVICIOS DE RED
# ==========================================
def cargar_cache_listas():
    """Carga la base de datos a la memoria RAM una vez."""
    global CACHE_EQUIPOS_AUTORIZADOS, BLACKLIST_IPS
    local_session = Session()
    try:
        equipos = local_session.query(EquipoAutorizado).filter_by(activo=True).all()
        # Guardamos la MAC en minúsculas para evitar errores de mayúsculas/minúsculas
        CACHE_EQUIPOS_AUTORIZADOS = {e.mac_address.lower(): e.ip_address for e in equipos}
        ips_malas = local_session.query(ListaNegraIP).all()
        BLACKLIST_IPS = {ip.ip_maliciosa for ip in ips_malas}
    except Exception:
        pass
    finally:
        local_session.close()

def sincronizar_bd():
    """Hilo en segundo plano que actualiza la caché cada 30 segundos."""
    while SISTEMA_ACTIVO:
        cargar_cache_listas()
        time.sleep(30)


def obtener_nombre_equipo(ip):
    try:
        nombre, _, _ = socket.gethostbyaddr(ip)
        return nombre
    except (socket.herror, socket.gaierror):
        return "Host_No_Resuelto"


def analizar_whois_abuso(ip):
    try:
        obj = IPWhois(ip)
        resultados = obj.lookup_rdap()
        emails_abuso = resultados['network'].get('emails', 'No asignado')
        if isinstance(emails_abuso, list):
            return ", ".join(emails_abuso)
        return emails_abuso
    except Exception as e:
        return f"Error Whois: {e}"


def enviar_alerta_estructurada(asunto, cuerpo):
    local_session = Session()
    try:
        admin = local_session.query(UsuarioIAM).filter_by(rol='ADMIN').first()
    finally:
        local_session.close()

    if not admin or not admin.email:
        print("[!] No hay admin con email configurado para recibir alertas.")
        return

    REMITENTE = os.getenv("REMITENTE_EMAIL")
    PASSWORD = os.getenv("REMITENTE_PASSWORD")
    if not REMITENTE or not PASSWORD:
        print("[!] Credenciales SMTP no configuradas en .env")
        return

    msg = EmailMessage()
    msg['Subject'] = asunto
    msg['From'] = REMITENTE
    msg['To'] = admin.email
    msg.set_content(cuerpo)

    # Intento 1: SSL directo (puerto 465)
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=10) as server:
            server.login(REMITENTE, PASSWORD)
            server.send_message(msg)
        return  # éxito, salimos
    except Exception as e:
        print(f"[!] SSL puerto 465 falló: {e}. Intentando STARTTLS...")

    # Intento 2: STARTTLS (puerto 587) — fallback
    try:
        with smtplib.SMTP('smtp.gmail.com', 587, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(REMITENTE, PASSWORD)
            server.send_message(msg)
    except Exception as e:
        print(f"[-] Correo no enviado por ningún método: {e}")


# ==========================================
# 3. MOTOR DE ANÁLISIS DE PAQUETES
# ==========================================

def procesar_paquete(paquete):
    if not SISTEMA_ACTIVO:
        return
    local_session = Session()
    try:
        # ── Filtro SMTP — evitar bucles con nuestros propios correos ──
        if paquete.haslayer(IP) and paquete.haslayer(TCP):
            if paquete[TCP].dport in [465, 587] or paquete[TCP].sport in [465, 587]:
                return

        # ── MÓDULO 1: Control de acceso perimetral (Capa 2 y 3) ──────
        # Solo analiza IPs del segmento local (evita alertas por tráfico
        # de IPs externas que son ruteadas por el gateway)
        if paquete.haslayer(Ether) and paquete.haslayer(IP):
            mac_src = paquete[Ether].src.lower()
            ip_src  = paquete[IP].src

            es_local = (
                RED_LOCAL_PREFIJO
                and ip_src.startswith(RED_LOCAL_PREFIJO)
                and not ip_src.startswith("127.")
                and ip_src != "0.0.0.0"
            )

            if es_local:
                ip_autorizada = CACHE_EQUIPOS_AUTORIZADOS.get(mac_src)

                if ip_autorizada != ip_src:
                    tiempo_actual = time.time()
                    ultimo_aviso  = RATE_LIMIT_CACHE.get(ip_src, 0)

                    if tiempo_actual - ultimo_aviso > 600:
                        RATE_LIMIT_CACHE[ip_src] = tiempo_actual

                        nombre_host  = obtener_nombre_equipo(ip_src)
                        tipo_trafico = "IP Genérica"
                        if paquete.haslayer(TCP):
                            tipo_trafico = f"TCP/{paquete[TCP].dport}"
                        elif paquete.haslayer(UDP):
                            tipo_trafico = f"UDP/{paquete[UDP].dport}"
                        elif paquete.haslayer('ICMP'):
                            tipo_trafico = "ICMP (Ping)"

                        nueva_amenaza = RegistroAmenazas(
                            ip_implicada=ip_src,
                            tipo_amenaza="DISPOSITIVO_NO_AUTORIZADO",
                            alerta_enviada=True,
                            timestamp=hora_local()
                        )
                        local_session.add(nueva_amenaza)
                        local_session.commit()

                        cuerpo = (
                            f"{'='*58}\n"
                            f" EXCEPCIÓN FORENSE: DISPOSITIVO NO AUTORIZADO\n"
                            f"{'='*58}\n\n"
                            f"  IP Local    : {ip_src}\n"
                            f"  MAC Física  : {mac_src}\n"
                            f"  Nombre Host : {nombre_host}\n"
                            f"  Protocolo   : {tipo_trafico}\n"
                            f"  Timestamp   : {hora_local().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                            f"Requiere autorización en el panel IAM."
                        )
                        EMAIL_POOL.submit(
                            enviar_alerta_estructurada,
                            "IDS Alerta: Intruso en la Red", cuerpo
                        )

        # ── MÓDULO 2: Bitácora de tráfico global ─────────────────────
        if paquete.haslayer(IP):
            ip_src = paquete[IP].src
            ip_dst = paquete[IP].dst
            nuevo_log = None

            # DNS — nombre de dominio consultado
            if paquete.haslayer(DNSQR):
                dominio = paquete[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                if (dominio
                        and not dominio.endswith("arpa")
                        and "in-addr" not in dominio
                        and "gmail.com" not in dominio):
                    nuevo_log = BitacoraTrafico(
                        ip_origen=ip_src, dominio_visitado=dominio,
                        protocolo="DNS", timestamp=hora_local()
                    )

            # HTTP — host visible en el payload
            elif (paquete.haslayer(TCP)
                  and paquete[TCP].dport == 80
                  and paquete.haslayer(Raw)):
                payload = paquete[Raw].load.decode('utf-8', errors='ignore')
                for linea in payload.split('\r\n'):
                    if linea.startswith("Host: "):
                        dominio = linea.split(" ", 1)[1].strip()
                        nuevo_log = BitacoraTrafico(
                            ip_origen=ip_src, dominio_visitado=dominio,
                            protocolo="HTTP", timestamp=hora_local()
                        )
                        break

            # HTTPS — resolvemos la IP destino a nombre si es posible
            elif (paquete.haslayer(TCP)
                  and paquete[TCP].dport == 443
                  and paquete[TCP].flags == "S"):
                nombre_dst = obtener_nombre_equipo(ip_dst)
                destino    = nombre_dst if nombre_dst != "Host_No_Resuelto" else ip_dst
                nuevo_log  = BitacoraTrafico(
                    ip_origen=ip_src,
                    dominio_visitado=f"HTTPS → {destino}",
                    protocolo="HTTPS", timestamp=hora_local()
                )

            # ICMP — ping/rastreo
            elif paquete.haslayer('ICMP') and paquete['ICMP'].type == 8:
                nuevo_log = BitacoraTrafico(
                    ip_origen=ip_src,
                    dominio_visitado=f"Ping → {ip_dst}",
                    protocolo="ICMP", timestamp=hora_local()
                )

            if nuevo_log:
                local_session.add(nuevo_log)
                local_session.commit()

            # ── MÓDULO 3: Threat Intelligence — blacklist ─────────────
            if ip_dst in BLACKLIST_IPS:
                tiempo_actual = time.time()
                ultimo_aviso  = RATE_LIMIT_CACHE.get(ip_dst, 0)
                if tiempo_actual - ultimo_aviso > 600:
                    RATE_LIMIT_CACHE[ip_dst] = tiempo_actual

                    correos_abuso = analizar_whois_abuso(ip_dst)
                    nombre_origen = obtener_nombre_equipo(ip_src)
                    cuerpo_alerta = (
                        f"{'='*58}\n"
                        f" ALERTA FORENSE: CONEXIÓN A IP DE MALWARE\n"
                        f"{'='*58}\n"
                        f"  Equipo Comprometido : {ip_src} ({nombre_origen})\n"
                        f"  IP Bloqueada        : {ip_dst}\n"
                        f"  Contacto de Abuso   : {correos_abuso}\n"
                        f"{'='*58}"
                    )
                    EMAIL_POOL.submit(
                        enviar_alerta_estructurada,
                        "Emergencia IDS: Conexión a IP Maliciosa", cuerpo_alerta
                    )

                    nueva_amenaza = RegistroAmenazas(
                        ip_implicada=ip_dst,
                        tipo_amenaza="CONEXION_IP_MALICIOSA",
                        alerta_enviada=True,
                        timestamp=hora_local()
                    )
                    local_session.add(nueva_amenaza)
                    local_session.commit()

    except Exception as e:
        local_session.rollback()
    finally:
        local_session.close()
# ==========================================
# MOTOR DE ANÁLISIS DE PAQUETES — VERSIÓN LIMPIA
# ==========================================

def detectar_interfaz_y_red():
    """
    Detecta automáticamente la interfaz activa y el segmento de red.
    Funciona en clase A (10.x), B (172.16-31.x) y C (192.168.x).
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_local = s.getsockname()[0]
        s.close()

        # Detectar prefijo de red según clase
        partes = ip_local.split(".")
        if ip_local.startswith("10."):
            prefijo = "10."
        elif ip_local.startswith("172."):
            prefijo = f"172.{partes[1]}."
        else:  # 192.168.x.x
            prefijo = f"{partes[0]}.{partes[1]}.{partes[2]}."

        from scapy.all import conf
        interfaz = conf.iface
        return interfaz, ip_local, prefijo

    except Exception as e:
        print(f"[!] No se pudo detectar la red: {e}")
        return None, None, None


def arrancar_sniffer():
    """
    Arranca el sniffer en la interfaz correcta detectada automáticamente.
    Captura TODO el tráfico visible en el segmento de red.
    """
    interfaz, ip_local, prefijo = detectar_interfaz_y_red()

    if not interfaz:
        print("[-] No se pudo determinar la interfaz. Abortando sniffer.")
        return

    print(f"[*] Interfaz activa  : {interfaz}")
    print(f"[*] IP del sensor    : {ip_local}")
    print(f"[*] Segmento de red  : {prefijo}0/24")
    print(f"[*] Modo promiscuo   : ACTIVADO")

    # Guardar prefijo globalmente para usarlo en procesar_paquete
    global RED_LOCAL_PREFIJO
    RED_LOCAL_PREFIJO = prefijo

    sniff(
        iface=interfaz,
        prn=procesar_paquete,
        store=False,
        promisc=True
    )
# ==========================================
# MÓDULO EXTRA: INTERCEPCIÓN ARP (MAN-IN-THE-MIDDLE)
# ==========================================
def habilitar_ip_forwarding():
    """Evita que el equipo víctima se quede sin internet al interceptarlo."""
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def restaurar_red(ip_victima, ip_router):
    """Devuelve la red a la normalidad al cerrar el IDS."""
    send(ARP(op=2, pdst=ip_victima, psrc=ip_router, hwdst="ff:ff:ff:ff:ff:ff"), count=4, verbose=False)
    send(ARP(op=2, pdst=ip_router, psrc=ip_victima, hwdst="ff:ff:ff:ff:ff:ff"), count=4, verbose=False)
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def hilo_arp_spoofing(ip_victima, ip_router):
    """Engaña al router y a la víctima para que el tráfico pase por el IDS."""
    habilitar_ip_forwarding()
    try:
        while SISTEMA_ACTIVO:
            # Engañar a la víctima
            send(ARP(op=2, pdst=ip_victima, psrc=ip_router), verbose=False)
            # Engañar al router
            send(ARP(op=2, pdst=ip_router, psrc=ip_victima), verbose=False)
            time.sleep(2)
    except Exception:
        pass
    finally:
        restaurar_red(ip_victima, ip_router)
# ==========================================
# 4. INTERFAZ GRÁFICA MEJORADA (RICH)
# ==========================================
def generar_interfaz():
    local_session = Session()
    try:
        # FILTRO BASADO ESTRICTAMENTE EN IDs
        
        amenazas = (local_session.query(RegistroAmenazas)
                    .filter(RegistroAmenazas.id > ULTIMO_ID_AMENAZA)
                    .order_by(RegistroAmenazas.id.desc())
                    .offset(OFFSET_PANTALLA).limit(15).all())
        
        traficos = (local_session.query(BitacoraTrafico)
                    .filter(BitacoraTrafico.id > ULTIMO_ID_TRAFICO)
                    .order_by(BitacoraTrafico.id.desc())
                    .offset(OFFSET_PANTALLA).limit(15).all())
        
        total_amenazas = local_session.query(RegistroAmenazas).filter(RegistroAmenazas.id > ULTIMO_ID_AMENAZA).count()
        total_trafico = local_session.query(BitacoraTrafico).filter(BitacoraTrafico.id > ULTIMO_ID_TRAFICO).count()
        
    finally:
        local_session.close()

    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="stats", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3)
    )
    layout["body"].split_row(
        Layout(name="left"),
        Layout(name="right")
    )

    # Header con estado y uptime
    # Header con estado y uptime
    # Header con estado y uptime
    uptime = hora_local() - TIEMPO_INICIO
    horas, rem = divmod(int(uptime.total_seconds()), 3600)
    minutos, segundos = divmod(rem, 60)
    uptime_str = f"{horas:02d}:{minutos:02d}:{segundos:02d}"
    estado = "[bold white on red] 🔴 EN VIVO [/]" if OFFSET_PANTALLA == 0 else f"[bold white on blue] ⏸ HISTÓRICO (-{OFFSET_PANTALLA}) [/]"
    header_text = Text.from_markup(
        f"🛡️  SOC TERMINAL — IDS  |  {estado}  |  ⏱ Uptime: {uptime_str}"
    )
    layout["header"].update(Panel(Align.center(header_text, vertical="middle"), style="bold cyan"))

    # Barra de estadísticas de sesión
    stats_table = Table(box=None, expand=True, show_header=False, padding=(0, 4))
    stats_table.add_column(justify="center")
    stats_table.add_column(justify="center")
    stats_table.add_column(justify="center")
    stats_table.add_column(justify="center")
    equipos_activos = len(CACHE_EQUIPOS_AUTORIZADOS)
    ips_bloqueadas = len(BLACKLIST_IPS)
    stats_table.add_row(
        f"[bold cyan]Equipos Autorizados:[/] [white]{equipos_activos}[/]",
        f"[bold red]IPs en Lista Negra:[/]  [white]{ips_bloqueadas}[/]",
        f"[bold yellow]Total Amenazas:[/]     [white]{total_amenazas}[/]",
        f"[bold green]Registros Tráfico:[/]  [white]{total_trafico}[/]",
    )
    layout["stats"].update(Panel(stats_table, border_style="dim cyan"))

    # Panel izquierdo — amenazas
    tabla_amenazas = Table(box=box.SIMPLE, expand=True, show_header=True, header_style="bold red")
    tabla_amenazas.add_column("Hora", style="dim white", width=10)
    tabla_amenazas.add_column("Tipo de Amenaza", style="bold red")
    tabla_amenazas.add_column("IP Implicada", style="yellow")
    for a in amenazas:
        tabla_amenazas.add_row(
            a.timestamp.strftime('%H:%M:%S'),
            a.tipo_amenaza,
            a.ip_implicada
        )
    layout["left"].update(Panel(tabla_amenazas, title="[bold red]🚨 AMENAZAS DETECTADAS[/]", border_style="red"))

    # Panel derecho — tráfico
    tabla_trafico = Table(box=box.SIMPLE, expand=True, show_header=True, header_style="bold green")
    tabla_trafico.add_column("Hora", style="dim white", width=10)
    tabla_trafico.add_column("Origen", style="bold green", width=14)
    tabla_trafico.add_column("Proto", style="cyan", width=6)
    tabla_trafico.add_column("Destino", style="white")
    for t in traficos:
        tabla_trafico.add_row(
            t.timestamp.strftime('%H:%M:%S'),
            t.ip_origen,
            t.protocolo,
            t.dominio_visitado[:35]
        )
    layout["right"].update(Panel(tabla_trafico, title="[bold green]📡 BITÁCORA DE TRÁFICO[/]", border_style="green"))

    # Footer con controles
    controles = (
        "[b white][W][/] Subir  [b white][S][/] Bajar  [b white][R][/] Vivo  │  "
        "[b yellow]Reportes:[/] [b white][P][/] Sesión  [b white][H][/] 2h  [b white][C][/] Completo  │  "
        "[b red][Q][/] Salir"
    )
    layout["footer"].update(Panel(Align.center(Text.from_markup(controles), vertical="middle"), border_style="cyan"))

    return layout


# ==========================================
# 5. REPORTES
# ==========================================
def ejecutar_reporte_soc(tipo, horas=0):
    os.system('cls' if os.name == 'nt' else 'clear')
    print("\n\033[44m\033[97m  MÓDULO DE EXPORTACIÓN FORENSE  \033[0m\n")

    local_session = Session()
    try:
        if tipo == 1:
            trafico = (local_session.query(BitacoraTrafico)
                       .filter(BitacoraTrafico.timestamp >= TIEMPO_INICIO)
                       .order_by(BitacoraTrafico.timestamp.desc()).all())
            amenazas = (local_session.query(RegistroAmenazas)
                        .filter(RegistroAmenazas.timestamp >= TIEMPO_INICIO)
                        .order_by(RegistroAmenazas.timestamp.desc()).all())
            rango_str = "SESIÓN ACTUAL SOC"
        elif tipo == 2:
            tiempo_limite = datetime.now() - timedelta(hours=horas)
            trafico = (local_session.query(BitacoraTrafico)
                       .filter(BitacoraTrafico.timestamp >= tiempo_limite)
                       .order_by(BitacoraTrafico.timestamp.desc()).all())
            amenazas = (local_session.query(RegistroAmenazas)
                        .filter(RegistroAmenazas.timestamp >= tiempo_limite)
                        .order_by(RegistroAmenazas.timestamp.desc()).all())
            rango_str = f"ÚLTIMAS {horas} HORAS"
        else:
            trafico = local_session.query(BitacoraTrafico).order_by(BitacoraTrafico.timestamp.desc()).all()
            amenazas = local_session.query(RegistroAmenazas).order_by(RegistroAmenazas.timestamp.desc()).all()
            rango_str = "HISTÓRICO INTEGRAL"
    finally:
        local_session.close()

    nombre_personalizado = input("» Nombre del archivo (Enter para nombre automático): ").strip()
    if not nombre_personalizado:
        nombre_personalizado = f"Reporte_SOC_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    if not nombre_personalizado.endswith(".txt"):
        nombre_archivo = f"{nombre_personalizado}.txt"
    else:
        nombre_archivo = nombre_personalizado

    print(f"\n[*] Generando reporte...")
    with open(nombre_archivo, "w", encoding="utf-8") as f:
        f.write("┌" + "─" * 70 + "┐\n")
        f.write(f"│ REPORTE SOC — AUDITORÍA: {rango_str:<46}│\n")
        f.write(f"│ Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<61}│\n")
        f.write("└" + "─" * 70 + "┘\n\n")
        f.write(f" AMENAZAS ({len(amenazas)} registros):\n")
        f.write(" " + "─" * 68 + "\n")
        for a in amenazas:
            f.write(f"  • [{a.timestamp}]  {a.tipo_amenaza:<35} | {a.ip_implicada}\n")
        f.write(f"\n TRÁFICO ({len(trafico)} registros):\n")
        f.write(" " + "─" * 68 + "\n")
        for t in trafico:
            f.write(f"  • [{t.timestamp}]  {t.ip_origen:<15} → {t.protocolo:<5} | {t.dominio_visitado}\n")

    print(f"\n[✓] Reporte guardado: {nombre_archivo}")
    input("Presiona [ENTER] para regresar al monitor...")


# ==========================================
# 6. MONITOR EN VIVO
# ==========================================
def iniciar_soc_en_vivo():
    global SISTEMA_ACTIVO, PAUSA_INTERFAZ, OFFSET_PANTALLA, TIEMPO_INICIO

    # Limpiar registros de sesión anterior
    clean_session = Session()
    try:
        clean_session.query(RegistroAmenazas).delete()
        clean_session.query(BitacoraTrafico).delete()
        clean_session.commit()
    except Exception:
        clean_session.rollback()
    finally:
        clean_session.close()

    SISTEMA_ACTIVO  = True
    OFFSET_PANTALLA = 0
    PAUSA_INTERFAZ  = False
    TIEMPO_INICIO   = hora_local()

    cargar_cache_listas()
    threading.Thread(target=sincronizar_bd, daemon=True).start()
    threading.Thread(target=arrancar_sniffer, daemon=True).start()

    fd = sys.stdin.fileno()
    ajustes_originales = termios.tcgetattr(fd)

    try:
        with Live(generar_interfaz(), refresh_per_second=4, screen=True) as live:
            tty.setcbreak(fd)
            while SISTEMA_ACTIVO:
                live.update(generar_interfaz())
                rlist, _, _ = select.select([sys.stdin], [], [], 0.25)
                if rlist:
                    tecla = sys.stdin.read(1).lower()
                    if tecla == 'w':
                        OFFSET_PANTALLA += 5
                    elif tecla == 's':
                        OFFSET_PANTALLA = max(0, OFFSET_PANTALLA - 5)
                    elif tecla == 'r':
                        OFFSET_PANTALLA = 0
                    elif tecla == 'q':
                        SISTEMA_ACTIVO = False
                        break
                    elif tecla in ['p', 'h', 'c']:
                        PAUSA_INTERFAZ = True
                        live.stop()
                        termios.tcsetattr(fd, termios.TCSADRAIN, ajustes_originales)
                        if tecla == 'p':   ejecutar_reporte_soc(1)
                        elif tecla == 'h': ejecutar_reporte_soc(2, horas=2)
                        elif tecla == 'c': ejecutar_reporte_soc(3)
                        tty.setcbreak(fd)
                        live.start()
                        PAUSA_INTERFAZ = False
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, ajustes_originales)
        print("\n[*] Monitor detenido. Volviendo al menú principal.")
        time.sleep(1)
# ==========================================
# 7. AUTO-DISCOVERY Y BUCLE PRINCIPAL
# ==========================================
def auto_autorizar_maquina_actual():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_p = s.getsockname()[0]
        s.close()
        from scapy.all import get_if_hwaddr, conf
        mac_p = get_if_hwaddr(conf.iface)
    except Exception as e:
        print(f"[!] No se pudo detectar IP/MAC local: {e}")
        return

    os.system('cls' if os.name == 'nt' else 'clear')
    print("=" * 50)
    print(" AUTO-DISCOVERY — DIAGNÓSTICO DE INICIALIZACIÓN")
    print("=" * 50)
    print(f"  IP Local  : {ip_p}")
    print(f"  MAC Local : {mac_p}")
    print("-" * 50)

    local_session = Session()
    try:
        existe = local_session.query(EquipoAutorizado).filter_by(mac_address=mac_p, activo=True).first()
        if existe:
            if existe.ip_address != ip_p:
                print("[*] IP dinámica cambió. Actualizando lista blanca...")
                existe.ip_address = ip_p
                local_session.commit()
            else:
                print("[✓] Equipo ya registrado y autorizado.")
            time.sleep(1)
        else:
            print("[!] Esta máquina NO está en la lista blanca.")
            resp = input("\n¿Autorizar este equipo ahora? (s/n): ").strip().lower()
            if resp == 's':
                prop = input(" Nombre/propietario del equipo: ").strip()
                nuevo = EquipoAutorizado(
                    mac_address=mac_p, ip_address=ip_p,
                    propietario=prop or "Laptop_SOC", activo=True
                )
                local_session.add(nuevo)
                local_session.commit()
                print("[+] Equipo autorizado correctamente.")
            time.sleep(1.5)
    finally:
        local_session.close()


if __name__ == "__main__":
    auto_autorizar_maquina_actual()

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("=" * 50)
        print(" SISTEMA DE DETECCIÓN DE INTRUSOS (IDS)")
        print("=" * 50)
        print("  1. Iniciar Monitor SOC en Vivo")
        print("  2. Panel de Configuración IAM")
        print("  3. Salir")
        opc = input("\nSeleccione una opción: ").strip()

        if opc == "1":
            iniciar_soc_en_vivo()
        elif opc == "2":
            usuario = autenticar_admin()  # login obligatorio
            if usuario:
                menu_configuracion_iam(usuario)
        elif opc == "3":
            print("\n[*] Cerrando sistema. ¡Hasta pronto!")
            sys.exit(0)
