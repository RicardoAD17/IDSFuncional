# test_flujo_completo.py
import os
import time
import threading
import socket
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv
from modelos_db import Session, UsuarioIAM

load_dotenv()

def obtener_nombre_equipo(ip):
    try:
        nombre, _, _ = socket.gethostbyaddr(ip)
        return nombre
    except:
        return "Host_No_Resuelto"

def enviar_alerta_estructurada(asunto, cuerpo):
    print(f"\n[*] enviar_alerta_estructurada() ejecutándose en hilo...")
    
    local_session = Session()
    try:
        admin = local_session.query(UsuarioIAM).filter_by(rol='ADMIN').first()
    finally:
        local_session.close()

    print(f"[*] Admin encontrado: {admin}")
    if admin:
        print(f"    username : {admin.username}")
        print(f"    email    : {admin.email}")
        print(f"    rol      : {admin.rol}")

    if not admin or not admin.email:
        print("[-] PROBLEMA ENCONTRADO: No hay admin con email en la BD")
        print("    Solución: ejecuta python crear_admin.py y asegúrate de poner el email")
        return

    REMITENTE = os.getenv("REMITENTE_EMAIL")
    PASSWORD  = os.getenv("REMITENTE_PASSWORD")
    print(f"[*] REMITENTE_EMAIL   : {REMITENTE}")
    print(f"[*] REMITENTE_PASSWORD: {'✓ presente' if PASSWORD else '✗ VACÍO'}")

    if not REMITENTE or not PASSWORD:
        print("[-] PROBLEMA ENCONTRADO: Variables .env no cargadas en este contexto")
        return

    msg = EmailMessage()
    msg['Subject'] = asunto
    msg['From']    = REMITENTE
    msg['To']      = admin.email
    msg.set_content(cuerpo)

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=10) as server:
            server.login(REMITENTE, PASSWORD)
            server.send_message(msg)
        print(f"[+] CORREO ENVIADO correctamente a {admin.email}")
    except Exception as e:
        print(f"[-] Error al enviar: {e}")

# --- Simular exactamente lo que haría procesar_paquete ---
ip_src   = "192.168.1.69"
mac_src  = "28:d0:43:8d:da:b0"
tipo     = "TCP/443"
nombre   = obtener_nombre_equipo(ip_src)

print("=" * 55)
print(" SIMULANDO detección de dispositivo no autorizado")
print("=" * 55)
print(f"  IP  : {ip_src}")
print(f"  MAC : {mac_src}")
print(f"  Host: {nombre}")

cuerpo = (
    f"{'='*58}\n"
    f" EXCEPCIÓN FORENSE: DISPOSITIVO NO AUTORIZADO DETECTADO\n"
    f"{'='*58}\n\n"
    f"  IP Local    : {ip_src}\n"
    f"  MAC Física  : {mac_src}\n"
    f"  Nombre Host : {nombre}\n"
    f"  Protocolo   : {tipo}\n\n"
    f"Requiere autorización en el panel IAM."
)

# Lanzar igual que en el IDS real — en un hilo daemon
hilo = threading.Thread(
    target=enviar_alerta_estructurada,
    args=("IDS TEST: Intruso detectado", cuerpo),
    daemon=True
)
hilo.start()
hilo.join(timeout=20)  # esperar hasta 20 segundos

print("\n[*] Test terminado.")
