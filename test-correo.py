import os
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv()

# §TC-01
REMITENTE = os.getenv("REMITENTE_EMAIL")
PASSWORD = os.getenv("REMITENTE_PASSWORD")

print(f"[*] Remitente cargado: {REMITENTE}")
print(f"[*] Password cargado:  {'✓ (presente)' if PASSWORD else '✗ (VACÍO)'}")

#§TC-02
if not REMITENTE or not PASSWORD:
    print("[-] PROBLEMA: Faltan variables en .env — revisa que el archivo exista y tenga:")
    print("    REMITENTE_EMAIL=tucorreo@gmail.com")
    print("    REMITENTE_PASSWORD=xxxx xxxx xxxx xxxx")
    exit(1)

destinatario = input(f"\n¿A qué correo enviar la prueba? (Enter para usar {REMITENTE}): ").strip()
if not destinatario:
    destinatario = REMITENTE

# §TC-03
msg = EmailMessage()
msg['Subject'] = "[IDS TEST] Prueba de alerta"
msg['From'] = REMITENTE
msg['To'] = destinatario
msg.set_content("Si recibes esto, el sistema de alertas funciona correctamente.")

print("\n--- Intento 1: SMTP_SSL puerto 465 ---")
# §TC-04
try:
    with smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=10) as server:
        print("[*] Conexión establecida...")
        server.login(REMITENTE, PASSWORD)
        print("[*] Login exitoso...")
        server.send_message(msg)
        print("[+] CORREO ENVIADO por SSL:465 — revisa tu bandeja.")
    exit(0)
except Exception as e:
    print(f"[-] SSL:465 falló → {e}")

# §TC-05 
print("\n--- Intento 2: STARTTLS puerto 587 ---")
try:
    with smtplib.SMTP('smtp.gmail.com', 587, timeout=10) as server:
        server.ehlo()
        server.starttls()
        server.login(REMITENTE, PASSWORD)
        server.send_message(msg)
        print("[+] CORREO ENVIADO por STARTTLS:587 — revisa tu bandeja.")
    exit(0)
except Exception as e:
    print(f"[-] STARTTLS:587 falló → {e}")

print("\n[-] AMBOS métodos fallaron.")
