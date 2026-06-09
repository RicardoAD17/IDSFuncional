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
from scapy.all import sniff, Ether, IP, TCP, UDP, DNSQR, Raw, srp, ARP, conf, getmacbyip
from sqlalchemy.exc import IntegrityError
from ipwhois import IPWhois
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor
from actualizar_threats import descargar_lista_inteligencia
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.align import Align
from rich.text import Text
from rich.console import Console
from zoneinfo import ZoneInfo

from utils import es_ip_valida, es_mac_valida, actualizar_env, obtener_password_seguro
from modelos_db import Session, EquipoAutorizado, BitacoraTrafico, RegistroAmenazas, UsuarioIAM, ListaNegraIP

load_dotenv()


EMAIL_POOL = ThreadPoolExecutor(max_workers=3)


CACHE_EQUIPOS_AUTORIZADOS = {}
BLACKLIST_IPS = set()
RATE_LIMIT_CACHE = {}
RED_LOCAL_PREFIJO = ""

ARP_TABLE_CACHE = {}  
PORT_SCAN_CACHE = {}  

PUERTOS_COMUNES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    67: "DHCP-Server", 68: "DHCP-Client", 110: "POP3", 123: "NTP",
    137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS", 143: "IMAP",
    445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 8080: "HTTP-Alt"
}

def hora_local():
    """Obtiene la hora local limpia para SQLite."""
    return datetime.now(ZoneInfo("America/Mexico_City")).replace(tzinfo=None)

TIEMPO_INICIO = hora_local()
SISTEMA_ACTIVO = True
OFFSET_PANTALLA = 0
PAUSA_INTERFAZ = False
ULTIMO_ID_AMENAZA = 0
ULTIMO_ID_TRAFICO = 0

console = Console()

# §IC-01 
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
        local_session.close()

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

                if not es_mac_valida(mac) or not es_ip_valida(ip) or not propietario:
                    print("[-] Error: Datos inválidos.")
                    time.sleep(2)
                    continue

                nuevo_equipo = EquipoAutorizado(mac_address=mac, ip_address=ip, propietario=propietario, activo=True)
                try:
                    local_session.add(nuevo_equipo)
                    local_session.commit()
                    print("[+] Equipo agregado correctamente.")
                except IntegrityError:
                    local_session.rollback()
                    print("[-] Error: Esta MAC ya existe.")
                time.sleep(2)
            elif opc == "2":
                mac = input("MAC a revocar: ").strip()
                equipo = local_session.query(EquipoAutorizado).filter_by(mac_address=mac).first()
                if equipo:
                    equipo.activo = False
                    local_session.commit()
                    print("[+] Autorización revocada.")
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
            print("4. Actualizar Threat Intelligence (Externo)")
            print("5. Volver")
            opc = input("Seleccione: ").strip()

            if opc == "1":
                ip = input("IP externa maliciosa: ").strip()
                if not es_ip_valida(ip):
                    print("[-] Error: IP inválida.")
                    time.sleep(2)
                    continue
                desc = input("Tipo de riesgo: ").strip()
                try:
                    local_session.add(ListaNegraIP(ip_maliciosa=ip, descripcion=desc))
                    local_session.commit()
                    print("[+] IP bloqueada.")
                except IntegrityError:
                    local_session.rollback()
                    print("[-] IP ya estaba en lista negra.")
                time.sleep(2)
            elif opc == "2":
                ip = input("IP a remover: ").strip()
                registro = local_session.query(ListaNegraIP).filter_by(ip_maliciosa=ip).first()
                if registro:
                    local_session.delete(registro)
                    local_session.commit()
                    print("[+] IP removida.")
                else:
                    print("[-] No encontrada.")
                time.sleep(2)
            elif opc == "3":
                ips = local_session.query(ListaNegraIP).all()
                print(f"\n{'IP Maliciosa':<20} {'Descripción'}")
                print("-" * 50)
                for entry in ips:
                    print(f"{entry.ip_maliciosa:<20} {entry.descripcion or 'N/A'}")
                input("\nPresiona Enter para continuar...")
            elif opc == "4":
                print("\n[*] Actualizando base de datos global de malware...")
                descargar_lista_inteligencia()
                input("\nPresiona Enter para continuar...")
            elif opc == "5":
                break
    finally:
        local_session.close()

def gestionar_configuracion_email():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("\n--- CONFIGURACIÓN DE ALERTAS POR CORREO ---")
    nuevo_email = input("Nuevo correo remitente (Enter omitir): ").strip()
    nueva_pass = obtener_password_seguro("Nueva contraseña de aplicación (Enter omitir): ")

    if nuevo_email:
        actualizar_env("REMITENTE_EMAIL", nuevo_email)
        local_session = Session()
        try:
            admin = local_session.query(UsuarioIAM).filter_by(rol='ADMIN').first()
            if admin:
                nuevo_dest = input("¿Correo DESTINO de alertas? (Enter para usar el mismo): ").strip()
                admin.email = nuevo_dest if nuevo_dest else nuevo_email
                local_session.commit()
        finally:
            local_session.close()
    if nueva_pass:
        actualizar_env("REMITENTE_PASSWORD", nueva_pass)
    print("[+] Configuración procesada.")
    time.sleep(2)

def mostrar_listas():
    local_session = Session()
    try:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("\n===== LISTA BLANCA =====")
        for e in local_session.query(EquipoAutorizado).filter_by(activo=True).all():
            print(f"{e.mac_address:<20} {e.ip_address:<16} {e.propietario}")
        print("\n===== LISTA NEGRA =====")
        for ip in local_session.query(ListaNegraIP).all():
            print(f"{ip.ip_maliciosa:<20} {ip.descripcion or 'N/A'}")
        input("\nPresiona Enter para volver...")
    finally:
        local_session.close()

def menu_configuracion_iam(usuario_logueado):
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"=== PANEL IAM | Usuario: {usuario_logueado.username} | Rol: {usuario_logueado.rol} ===")
        print("1. Ver Listas\n2. Modificar Lista Blanca\n3. Modificar Lista Negra\n4. Configurar Email\n0. Volver")
        opc = input("\nSelección: ").strip()

        if opc == "1": mostrar_listas()
        elif opc in ["2", "3", "4"] and usuario_logueado.rol == 'ADMIN':
            if opc == "2": gestionar_lista_blanca()
            elif opc == "3": gestionar_lista_negra()
            elif opc == "4": gestionar_configuracion_email()
        elif opc == "0": break

# §IC-02
def cargar_cache_listas():
    global CACHE_EQUIPOS_AUTORIZADOS, BLACKLIST_IPS
    local_session = Session()
    try:
        equipos = local_session.query(EquipoAutorizado).filter_by(activo=True).all()
        CACHE_EQUIPOS_AUTORIZADOS = {e.mac_address.lower(): e.ip_address for e in equipos}
        ips_malas = local_session.query(ListaNegraIP).all()
        BLACKLIST_IPS = {ip.ip_maliciosa for ip in ips_malas}
    finally:
        local_session.close()

def sincronizar_bd():
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
    """Extrae la información WHOIS completa para formateo forense."""
    try:
        obj = IPWhois(ip)
        resultados = obj.lookup_rdap()
        
        isp = resultados.get('asn_description') or 'No disponible'
        pais = resultados.get('asn_country_code') or 'N/A'
        
        red = resultados.get('network', {}) or {}
        org = red.get('name') or 'No disponible'
        
        emails = red.get('emails', ['No asignado'])
        if isinstance(emails, list):
            emails = ", ".join(emails)
            
        return {"isp": isp, "pais": pais, "org": org, "emails": emails}
    except Exception as e:
        return {"isp": "Error de consulta", "pais": "N/A", "org": "N/A", "emails": f"Error: {str(e)}"}

def enviar_alerta_estructurada(asunto, cuerpo_html):
    """Envía un correo electrónico en formato HTML enriquecido."""
    local_session = Session()
    try:
        admin = local_session.query(UsuarioIAM).filter_by(rol='ADMIN').first()
    finally:
        local_session.close()

    if not admin or not admin.email: return
    REMITENTE = os.getenv("REMITENTE_EMAIL")
    PASSWORD = os.getenv("REMITENTE_PASSWORD")
    if not REMITENTE or not PASSWORD: return

    msg = EmailMessage()
    msg['Subject'] = asunto
    msg['From'] = REMITENTE
    msg['To'] = admin.email
    
    msg.set_content("ALERTA IDS: Por favor, visualiza este correo en un cliente que soporte HTML para ver el reporte forense completo.")
    
    msg.add_alternative(cuerpo_html, subtype='html')

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=10) as server:
            server.login(REMITENTE, PASSWORD)
            server.send_message(msg)
    except Exception:
        try:
            with smtplib.SMTP('smtp.gmail.com', 587, timeout=10) as server:
                server.ehlo()
                server.starttls()
                server.login(REMITENTE, PASSWORD)
                server.send_message(msg)
        except Exception:
            pass

# §IC-03 
def procesar_paquete(paquete):
    if not SISTEMA_ACTIVO:
        return
    local_session = Session()
    try:
        
        if paquete.haslayer(IP) and paquete.haslayer(TCP):
            if paquete[TCP].dport in [465, 587] or paquete[TCP].sport in [465, 587]:
                return
        
        
        if paquete.haslayer(IP):
            if paquete.haslayer('ICMP') and paquete[IP].dst in ["8.8.8.8", "1.1.1.1"]:
                return
            if paquete.haslayer(UDP) and paquete[UDP].dport == 5353:
                return

        
        if paquete.haslayer(ARP) and paquete[ARP].op in (1, 2):
            ip_arp, mac_arp = paquete[ARP].psrc, paquete[ARP].hwsrc.lower()
            if mac_arp not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                if ip_arp in ARP_TABLE_CACHE:
                    if ARP_TABLE_CACHE[ip_arp] != mac_arp:
                        t_actual = time.time()
                        if t_actual - RATE_LIMIT_CACHE.get(f"ARP_{ip_arp}", 0) > 60:
                            RATE_LIMIT_CACHE[f"ARP_{ip_arp}"] = t_actual
                            
                            
                            asunto = f"[IDS ALERTA - SPOOFING] Posible MITM afectando IP: {ip_arp}"
                            cuerpo_html = f"""
                            <div style="font-family: Arial, sans-serif; color: #333;">
                                <h2 style="color: #f0ad4e;">⚠️ ALERTA DE RED: ARP Spoofing Detectado</h2>
                                <p>Se ha detectado una suplantación de identidad en la capa de enlace (Posible Man-In-The-Middle).</p>
                                <table style="border-collapse: collapse; width: 100%; max-width: 600px; text-align: left;">
                                    <tr><th style="padding: 8px; border: 1px solid #ddd; background-color: #f2f2f2;">IP Afectada</th><td style="padding: 8px; border: 1px solid #ddd;">{ip_arp}</td></tr>
                                    <tr><th style="padding: 8px; border: 1px solid #ddd; background-color: #f2f2f2;">MAC Legítima</th><td style="padding: 8px; border: 1px solid #ddd;">{ARP_TABLE_CACHE[ip_arp]}</td></tr>
                                    <tr><th style="padding: 8px; border: 1px solid #ddd; background-color: #f2f2f2;">MAC Atacante</th><td style="padding: 8px; border: 1px solid #ddd; color: red;"><strong>{mac_arp}</strong></td></tr>
                                    <tr><th style="padding: 8px; border: 1px solid #ddd; background-color: #f2f2f2;">Timestamp</th><td style="padding: 8px; border: 1px solid #ddd;">{hora_local().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
                                </table>
                            </div>
                            """
                            EMAIL_POOL.submit(enviar_alerta_estructurada, asunto, cuerpo_html)
                            local_session.add(RegistroAmenazas(ip_implicada=ip_arp, tipo_amenaza="ATAQUE_ARP_SPOOFING", alerta_enviada=True, timestamp=hora_local()))
                            local_session.commit()
                else:
                    ARP_TABLE_CACHE[ip_arp] = mac_arp

        
        if paquete.haslayer(TCP) and paquete.haslayer(IP) and paquete[TCP].flags == "S":
            ip_atc, p_obj, t_act = paquete[IP].src, paquete[TCP].dport, time.time()
            if ip_atc not in PORT_SCAN_CACHE or t_act - PORT_SCAN_CACHE[ip_atc]['inicio'] > 5:
                PORT_SCAN_CACHE[ip_atc] = {'inicio': t_act, 'puertos': set()}
            PORT_SCAN_CACHE[ip_atc]['puertos'].add(p_obj)
            
            if len(PORT_SCAN_CACHE[ip_atc]['puertos']) > 15:
                if t_act - RATE_LIMIT_CACHE.get(f"SCAN_{ip_atc}", 0) > 60:
                    RATE_LIMIT_CACHE[f"SCAN_{ip_atc}"] = t_act
                    
                    asunto = f"[IDS ALERTA - NMAP] Escaneo de puertos desde IP: {ip_atc}"
                    cuerpo_html = f"""
                    <div style="font-family: Arial, sans-serif; color: #333;">
                        <h2 style="color: #f0ad4e;">⚠️ ALERTA DE COMPORTAMIENTO: Escaneo de Puertos</h2>
                        <p>Se ha detectado un barrido táctico de puertos originado desde un equipo de la red. Esto es característico de herramientas de intrusión como Nmap.</p>
                        <ul>
                            <li><strong>IP Atacante (Origen):</strong> <span style="color: red;">{ip_atc}</span></li>
                            <li><strong>Patrón Detectado:</strong> Más de 15 puertos TCP (SYN) distintos contactados en menos de 5 segundos.</li>
                            <li><strong>Hora del Evento:</strong> {hora_local().strftime('%Y-%m-%d %H:%M:%S')}</li>
                        </ul>
                        <p><em>Revise si la IP de origen corresponde a un administrador realizando auditorías autorizadas.</em></p>
                    </div>
                    """
                    EMAIL_POOL.submit(enviar_alerta_estructurada, asunto, cuerpo_html)
                    local_session.add(RegistroAmenazas(ip_implicada=ip_atc, tipo_amenaza="ESCANEO_PUERTOS_NMAP", alerta_enviada=True, timestamp=hora_local()))
                    local_session.commit()

        
        if paquete.haslayer(Ether) and paquete.haslayer(IP):
            mac_src, ip_src = paquete[Ether].src.lower(), paquete[IP].src
            if RED_LOCAL_PREFIJO and ip_src.startswith(RED_LOCAL_PREFIJO) and not ip_src.startswith("127."):
                if CACHE_EQUIPOS_AUTORIZADOS.get(mac_src) != ip_src:
                    t_actual = time.time()
                    if t_actual - RATE_LIMIT_CACHE.get(ip_src, 0) > 600:
                        RATE_LIMIT_CACHE[ip_src] = t_actual
                        tipo_tr = f"TCP/{paquete[TCP].dport}" if paquete.haslayer(TCP) else f"UDP/{paquete[UDP].dport}" if paquete.haslayer(UDP) else "IP Genérica"
                        nombre_host = obtener_nombre_equipo(ip_src)
                        
                        # Plantilla HTML para Whitelist (Intrusos)
                        asunto = f"[IDS ALERTA - INTRUSO] Dispositivo desconocido IP: {ip_src}"
                        cuerpo_html = f"""
                        <div style="font-family: Arial, sans-serif; color: #333;">
                            <h2 style="color: #d9534f;">🚨 ALERTA: Dispositivo No Autorizado</h2>
                            <p>Se ha detectado un equipo traficando en la red institucional que no se encuentra en la Lista Blanca.</p>
                            <table style="border-collapse: collapse; width: 100%; max-width: 600px; text-align: left;">
                                <tr style="background-color: #f9f9f9;"><th style="padding: 8px; border: 1px solid #ddd;">IP Local:</th><td style="padding: 8px; border: 1px solid #ddd;">{ip_src}</td></tr>
                                <tr><th style="padding: 8px; border: 1px solid #ddd;">MAC Física:</th><td style="padding: 8px; border: 1px solid #ddd;">{mac_src}</td></tr>
                                <tr style="background-color: #f9f9f9;"><th style="padding: 8px; border: 1px solid #ddd;">Hostname:</th><td style="padding: 8px; border: 1px solid #ddd;">{nombre_host}</td></tr>
                                <tr><th style="padding: 8px; border: 1px solid #ddd;">Tráfico Detectado:</th><td style="padding: 8px; border: 1px solid #ddd;">{tipo_tr}</td></tr>
                                <tr style="background-color: #f9f9f9;"><th style="padding: 8px; border: 1px solid #ddd;">Timestamp:</th><td style="padding: 8px; border: 1px solid #ddd;">{hora_local().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
                            </table>
                            <p style="margin-top: 20px;"><em>Este dispositivo requiere ser validado y autorizado mediante el panel IAM del sistema.</em></p>
                        </div>
                        """
                        EMAIL_POOL.submit(enviar_alerta_estructurada, asunto, cuerpo_html)
                        local_session.add(RegistroAmenazas(ip_implicada=ip_src, tipo_amenaza="DISPOSITIVO_NO_AUTORIZADO", alerta_enviada=True, timestamp=hora_local()))
                        local_session.commit()

       
        if paquete.haslayer(IP):
            ip_src, ip_dst, nuevo_log, registrado = paquete[IP].src, paquete[IP].dst, None, False

            if paquete.haslayer(DNSQR):
                dom = paquete[DNSQR].qname.decode('utf-8', 'ignore').rstrip('.')
                if dom and not dom.endswith("arpa") and "in-addr" not in dom:
                    nuevo_log = BitacoraTrafico(ip_origen=ip_src, dominio_visitado=dom, protocolo="DNS", timestamp=hora_local())
                    registrado = True
            elif paquete.haslayer(TCP) and paquete[TCP].dport == 80 and paquete.haslayer(Raw):
                payload = paquete[Raw].load.decode('utf-8', 'ignore')
                for lin in payload.split('\r\n'):
                    if lin.startswith("Host: "):
                        nuevo_log = BitacoraTrafico(ip_origen=ip_src, dominio_visitado=lin.split(" ", 1)[1].strip(), protocolo="HTTP", timestamp=hora_local())
                        registrado = True; break
            elif paquete.haslayer(TCP) and paquete[TCP].dport == 443 and paquete[TCP].flags == "S":
                ndst = obtener_nombre_equipo(ip_dst)
                nuevo_log = BitacoraTrafico(ip_origen=ip_src, dominio_visitado=f"HTTPS → {ndst if ndst != 'Host_No_Resuelto' else ip_dst}", protocolo="HTTPS", timestamp=hora_local())
                registrado = True
            elif paquete.haslayer('ICMP') and paquete['ICMP'].type == 8:
                nuevo_log = BitacoraTrafico(ip_origen=ip_src, dominio_visitado=f"Ping → {ip_dst}", protocolo="ICMP", timestamp=hora_local())
                registrado = True
            
            
            if not registrado and (paquete.haslayer(TCP) or paquete.haslayer(UDP)):
                p_dst = paquete[TCP if paquete.haslayer(TCP) else UDP].dport
                if p_dst in PUERTOS_COMUNES:
                    nuevo_log = BitacoraTrafico(ip_origen=ip_src, dominio_visitado=f"Conexión a {ip_dst}:{p_dst}", protocolo=PUERTOS_COMUNES[p_dst], timestamp=hora_local())

            if nuevo_log:
                local_session.add(nuevo_log)
                local_session.commit()

            if ip_dst in BLACKLIST_IPS:
                t_act = time.time()
                if t_act - RATE_LIMIT_CACHE.get(ip_dst, 0) > 600:
                    RATE_LIMIT_CACHE[ip_dst] = t_act
                    
                    whois_data = analizar_whois_abuso(ip_dst)
                    
                    asunto = f"[IDS ALERTA - MALWARE] Conexión bloqueada hacia IP: {ip_dst}"
                    cuerpo_html = f"""
                    <div style="font-family: Arial, sans-serif; color: #333;">
                        <h2 style="color: #d9534f; border-bottom: 2px solid #d9534f; padding-bottom: 5px;">🚨 ALERTA CRÍTICA: Tráfico Malicioso Detectado</h2>
                        <p>Un equipo interno intentó comunicarse con una dirección IP clasificada como peligrosa en la base de datos de Threat Intelligence.</p>
                        
                        <h3>Datos del Incidente Interno:</h3>
                        <ul>
                            <li><strong>Equipo Afectado (Origen):</strong> {ip_src} ({obtener_nombre_equipo(ip_src)})</li>
                            <li><strong>IP Maliciosa (Destino):</strong> <span style="color: red; font-weight: bold;">{ip_dst}</span></li>
                            <li><strong>Fecha y Hora:</strong> {hora_local().strftime('%Y-%m-%d %H:%M:%S')}</li>
                        </ul>
                        
                        <h3>Análisis Forense y WHOIS del Destino:</h3>
                        <table style="border-collapse: collapse; width: 100%; max-width: 600px; text-align: left;">
                            <tr style="background-color: #f9f9f9;"><th style="padding: 8px; border: 1px solid #ddd;">Proveedor (ISP/ASN):</th><td style="padding: 8px; border: 1px solid #ddd;">{whois_data['isp']}</td></tr>
                            <tr><th style="padding: 8px; border: 1px solid #ddd;">Organización:</th><td style="padding: 8px; border: 1px solid #ddd;">{whois_data['org']}</td></tr>
                            <tr style="background-color: #f9f9f9;"><th style="padding: 8px; border: 1px solid #ddd;">País de Origen:</th><td style="padding: 8px; border: 1px solid #ddd;">{whois_data['pais']}</td></tr>
                            <tr><th style="padding: 8px; border: 1px solid #ddd;">Contacto de Abuso:</th><td style="padding: 8px; border: 1px solid #ddd;"><a href="mailto:{whois_data['emails']}">{whois_data['emails']}</a></td></tr>
                        </table>
                        <p style="margin-top: 15px;"><em>Se recomienda aislar inmediatamente el equipo origen y utilizar los correos de contacto para reportar la infraestructura maliciosa al proveedor de hosting.</em></p>
                    </div>
                    """
                    EMAIL_POOL.submit(enviar_alerta_estructurada, asunto, cuerpo_html)
                    local_session.add(RegistroAmenazas(ip_implicada=ip_dst, tipo_amenaza="CONEXION_IP_MALICIOSA", alerta_enviada=True, timestamp=hora_local()))
                    local_session.commit()

    except Exception:
        local_session.rollback()
    finally:
        local_session.close()

# §IC-04 
def detectar_interfaz_y_red():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_local = s.getsockname()[0]
        s.close()
        partes = ip_local.split(".")
        prefijo = "10." if ip_local.startswith("10.") else f"172.{partes[1]}." if ip_local.startswith("172.") else f"{partes[0]}.{partes[1]}.{partes[2]}."
        return conf.iface, ip_local, prefijo
    except Exception:
        return None, None, None

def arrancar_sniffer():
    interfaz, _, _ = detectar_interfaz_y_red()
    if interfaz:
        sniff(iface=interfaz, prn=procesar_paquete, store=False, promisc=True)

# §IC-05
def generar_interfaz():
    local_session = Session()
    try:
        amenazas = local_session.query(RegistroAmenazas).filter(RegistroAmenazas.id > ULTIMO_ID_AMENAZA).order_by(RegistroAmenazas.id.desc()).offset(OFFSET_PANTALLA).limit(15).all()
        traficos = local_session.query(BitacoraTrafico).filter(BitacoraTrafico.id > ULTIMO_ID_TRAFICO).order_by(BitacoraTrafico.id.desc()).offset(OFFSET_PANTALLA).limit(15).all()
        total_a = local_session.query(RegistroAmenazas).filter(RegistroAmenazas.id > ULTIMO_ID_AMENAZA).count()
        total_t = local_session.query(BitacoraTrafico).filter(BitacoraTrafico.id > ULTIMO_ID_TRAFICO).count()
    finally:
        local_session.close()

    layout = Layout()
    layout.split_column(Layout(name="header", size=3), Layout(name="stats", size=3), Layout(name="body"), Layout(name="footer", size=3))
    layout["body"].split_row(Layout(name="left"), Layout(name="right"))

    uptime = hora_local() - TIEMPO_INICIO
    horas, rem = divmod(int(uptime.total_seconds()), 3600)
    mins, segs = divmod(rem, 60)
    estado = "[bold white on red] 🔴 EN VIVO [/]" if OFFSET_PANTALLA == 0 else f"[bold white on blue] ⏸ HISTÓRICO (-{OFFSET_PANTALLA}) [/]"
    layout["header"].update(Panel(Align.center(Text.from_markup(f"🛡️  SOC TERMINAL — IDS | {estado} | ⏱ Uptime: {horas:02d}:{mins:02d}:{segs:02d}"), vertical="middle"), style="bold cyan"))

    tb_stats = Table(box=None, expand=True, show_header=False, padding=(0, 4))
    for _ in range(4): tb_stats.add_column(justify="center")
    tb_stats.add_row(f"[bold cyan]Autorizados:[/] [white]{len(CACHE_EQUIPOS_AUTORIZADOS)}[/]", f"[bold red]Lista Negra:[/] [white]{len(BLACKLIST_IPS)}[/]", f"[bold yellow]Amenazas:[/] [white]{total_a}[/]", f"[bold green]Tráfico:[/] [white]{total_t}[/]")
    layout["stats"].update(Panel(tb_stats, border_style="dim cyan"))

    tb_amenazas = Table(box=box.SIMPLE, expand=True, show_header=True, header_style="bold red")
    tb_amenazas.add_column("Hora", style="dim white", width=10); tb_amenazas.add_column("Tipo", style="bold red"); tb_amenazas.add_column("IP", style="yellow")
    for a in amenazas: tb_amenazas.add_row(a.timestamp.strftime('%H:%M:%S'), a.tipo_amenaza, a.ip_implicada)
    layout["left"].update(Panel(tb_amenazas, title="[bold red]🚨 AMENAZAS DETECTADAS[/]", border_style="red"))

    tb_traf = Table(box=box.SIMPLE, expand=True, show_header=True, header_style="bold green")
    tb_traf.add_column("Hora", style="dim white", width=10); tb_traf.add_column("Origen", style="bold green", width=14); tb_traf.add_column("Proto", style="cyan", width=6); tb_traf.add_column("Destino", style="white")
    for t in traficos: tb_traf.add_row(t.timestamp.strftime('%H:%M:%S'), t.ip_origen, t.protocolo, t.dominio_visitado[:35])
    layout["right"].update(Panel(tb_traf, title="[bold green]📡 BITÁCORA DE TRÁFICO[/]", border_style="green"))

    ctrls = "[b white][W][/] Subir [b white][S][/] Bajar [b white][R][/] Vivo │ [b yellow]Reportes:[/] [b white][P][/] Sesión [b white][H][/] 2h [b white][C][/] Completo │ [b red][Q][/] Salir"
    layout["footer"].update(Panel(Align.center(Text.from_markup(ctrls), vertical="middle"), border_style="cyan"))
    return layout

# §IC-06
def ejecutar_reporte_soc(tipo, horas=0):
    os.system('cls' if os.name == 'nt' else 'clear')
    print("\n\033[44m\033[97m  MÓDULO DE EXPORTACIÓN FORENSE  \033[0m\n")
    local_session = Session()
    try:
        t_ref = TIEMPO_INICIO if tipo == 1 else datetime.now() - timedelta(hours=horas) if tipo == 2 else None
        q_t, q_a = local_session.query(BitacoraTrafico), local_session.query(RegistroAmenazas)
        if t_ref: q_t, q_a = q_t.filter(BitacoraTrafico.timestamp >= t_ref), q_a.filter(RegistroAmenazas.timestamp >= t_ref)
        trafico, amenazas = q_t.order_by(BitacoraTrafico.timestamp.desc()).all(), q_a.order_by(RegistroAmenazas.timestamp.desc()).all()
        rango = "SESIÓN ACTUAL" if tipo == 1 else f"ÚLTIMAS {horas} HORAS" if tipo == 2 else "HISTÓRICO INTEGRAL"
    finally:
        local_session.close()

    nombre = input("» Nombre del archivo (Enter auto): ").strip() or f"Reporte_SOC_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    if not nombre.endswith(".txt"): nombre += ".txt"

    with open(nombre, "w", encoding="utf-8") as f:
        f.write("┌" + "─" * 70 + "┐\n")
        f.write(f"│ REPORTE SOC — AUDITORÍA: {rango:<46}│\n")
        f.write(f"│ Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<61}│\n")
        f.write("└" + "─" * 70 + "┘\n\n")
        f.write(f" AMENAZAS ({len(amenazas)}):\n" + " ─" * 68 + "\n")
        for a in amenazas: f.write(f"  • [{a.timestamp}]  {a.tipo_amenaza:<35} | {a.ip_implicada}\n")
        f.write(f"\n TRÁFICO ({len(trafico)}):\n" + " ─" * 68 + "\n")
        for t in trafico: f.write(f"  • [{t.timestamp}]  {t.ip_origen:<15} → {t.protocolo:<5} | {t.dominio_visitado}\n")
    print(f"\n[✓] Guardado: {nombre}\n"); input("Presiona [ENTER] para regresar...")

def realizar_sondeo_arp():
    """Sondeo táctico (Ping Sweep) para forzar visibilidad de red."""
    global RED_LOCAL_PREFIJO, CACHE_EQUIPOS_AUTORIZADOS
    if not RED_LOCAL_PREFIJO: return
    print(f"\n[*] Sondeo táctico de red en {RED_LOCAL_PREFIJO}0/24...")
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=f"{RED_LOCAL_PREFIJO}0/24"), timeout=2, verbose=False)
        local_session = Session()
        for _, resp in ans:
            ip_enc, mac_enc = resp[ARP].psrc, resp[ARP].hwsrc.lower()
            if mac_enc not in CACHE_EQUIPOS_AUTORIZADOS and ip_enc not in RATE_LIMIT_CACHE:
                RATE_LIMIT_CACHE[ip_enc] = time.time()
                local_session.add(RegistroAmenazas(ip_implicada=ip_enc, tipo_amenaza="INTRUSO_POR_SONDEO", alerta_enviada=False, timestamp=hora_local()))
                local_session.commit()
        local_session.close()
        print(f"[✓] Sondeo completado: {len(ans)} dispositivos encontrados.")
        time.sleep(1)
    except Exception as e:
        print(f"[-] Error en sondeo: {e}")

# §IC-07 
def auto_autorizar_maquina_actual():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8", 80))
        ip_p, mac_p = s.getsockname()[0], getmacbyip(s.getsockname()[0]) or conf.iface.mac
        s.close()
    except Exception: return
    
    os.system('cls' if os.name == 'nt' else 'clear')
    print("=" * 50 + f"\n AUTO-DISCOVERY — IP: {ip_p} | MAC: {mac_p}\n" + "=" * 50)
    local_session = Session()
    try:
        existe = local_session.query(EquipoAutorizado).filter_by(mac_address=mac_p, activo=True).first()
        if existe:
            if existe.ip_address != ip_p: existe.ip_address = ip_p; local_session.commit()
            print("[✓] Equipo local validado en lista blanca.")
        else:
            if input("\n[!] Máquina no autorizada. ¿Autorizar ahora? (s/n): ").strip().lower() == 's':
                local_session.add(EquipoAutorizado(mac_address=mac_p, ip_address=ip_p, propietario=input(" Propietario: ").strip() or "Local", activo=True))
                local_session.commit()
                print("[+] Autorizado correctamente.")
    finally:
        local_session.close()
        time.sleep(1)

def autorizar_gateway_automatico():
    print("\n" + "=" * 50)
    print(" AUTO-DISCOVERY — DETECCIÓN DE GATEWAY (ROUTER)")
    print("=" * 50)
    ip_gateway = conf.route.route("0.0.0.0")[2]
    
    if ip_gateway == "0.0.0.0" or not ip_gateway:
        print("[-] No se pudo detectar el Gateway de la red."); time.sleep(1.5); return

    mac_gateway = getmacbyip(ip_gateway)
    if not mac_gateway:
        print(f"[-] IP del Gateway detectada ({ip_gateway}), pero no se resolvió su MAC."); time.sleep(1.5); return

    print(f"  IP del Router  : {ip_gateway}\n  MAC del Router : {mac_gateway}\n" + "-" * 50)
    local_session = Session()
    try:
        existe = local_session.query(EquipoAutorizado).filter_by(mac_address=mac_gateway.lower(), activo=True).first()
        if existe:
            if existe.ip_address != ip_gateway:
                existe.ip_address = ip_gateway
                local_session.commit()
                print("[*] IP del router actualizada en la lista blanca.")
            else:
                print("[✓] Router validado. Ya estaba en la lista blanca.")
        else:
            local_session.add(EquipoAutorizado(mac_address=mac_gateway.lower(), ip_address=ip_gateway, propietario="Router_Gateway_Red", activo=True))
            local_session.commit()
            print("[+] Router autorizado y agregado a la lista blanca automáticamente.")
        time.sleep(1.5)
    except Exception as e:
        local_session.rollback()
        print(f"[-] Error al guardar el router en BD: {e}"); time.sleep(1.5)
    finally:
        local_session.close()

def iniciar_soc_en_vivo():
    global SISTEMA_ACTIVO, PAUSA_INTERFAZ, OFFSET_PANTALLA, TIEMPO_INICIO, RED_LOCAL_PREFIJO
    local_session = Session()
    try:
        local_session.query(RegistroAmenazas).delete(); local_session.query(BitacoraTrafico).delete(); local_session.commit()
    except Exception: local_session.rollback()
    finally: local_session.close()

    SISTEMA_ACTIVO, OFFSET_PANTALLA, PAUSA_INTERFAZ, TIEMPO_INICIO = True, 0, False, hora_local()
    cargar_cache_listas()
    
    interfaz, _, prefijo = detectar_interfaz_y_red()
    if prefijo: RED_LOCAL_PREFIJO = prefijo
    realizar_sondeo_arp()

    threading.Thread(target=sincronizar_bd, daemon=True).start()
    threading.Thread(target=arrancar_sniffer, daemon=True).start()

    fd, ajustes = sys.stdin.fileno(), termios.tcgetattr(sys.stdin.fileno())
    try:
        with Live(generar_interfaz(), refresh_per_second=4, screen=True) as live:
            tty.setcbreak(fd)
            while SISTEMA_ACTIVO:
                live.update(generar_interfaz())
                r, _, _ = select.select([sys.stdin], [], [], 0.25)
                if r:
                    k = sys.stdin.read(1).lower()
                    if k == 'w': OFFSET_PANTALLA += 5
                    elif k == 's': OFFSET_PANTALLA = max(0, OFFSET_PANTALLA - 5)
                    elif k == 'r': OFFSET_PANTALLA = 0
                    elif k == 'q': SISTEMA_ACTIVO = False
                    elif k in ['p', 'h', 'c']:
                        PAUSA_INTERFAZ = True; live.stop(); termios.tcsetattr(fd, termios.TCSADRAIN, ajustes)
                        if k == 'p': ejecutar_reporte_soc(1)
                        elif k == 'h': ejecutar_reporte_soc(2, horas=2)
                        elif k == 'c': ejecutar_reporte_soc(3)
                        tty.setcbreak(fd); live.start(); PAUSA_INTERFAZ = False
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, ajustes)
        print("\n[*] Monitor detenido.")
        time.sleep(1)

if __name__ == "__main__":
    auto_autorizar_maquina_actual()
    autorizar_gateway_automatico()

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("=" * 50 + "\n SISTEMA DE DETECCIÓN DE INTRUSOS (IDS)\n" + "=" * 50)
        opc = input("  1. Monitor SOC en Vivo\n  2. Panel IAM\n  3. Salir\n\nSelección: ").strip()
        if opc == "1": iniciar_soc_en_vivo()
        elif opc == "2":
            u = autenticar_admin()
            if u: menu_configuracion_iam(u)
        elif opc == "3": sys.exit(0)
