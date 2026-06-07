# descargar_amenazas.py
import urllib.request
from dotenv import load_dotenv
from modelos_db import Session, ListaNegraIP  # ← usa el Session del IDS, ya tiene SQLCipher

load_dotenv()

def descargar_lista_inteligencia():
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    print("[*] Descargando base de datos de amenazas globales (Feodo Tracker)...")
    
    session = Session()  # ← esta ya tiene la clave cifrada configurada
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            lineas = response.read().decode('utf-8').splitlines()

        contador_nuevas = 0
        contador_duplicadas = 0

        for linea in lineas:
            if linea.startswith("#") or not linea.strip():
                continue
            ip = linea.strip().split()[0]

            existe = session.query(ListaNegraIP).filter_by(ip_maliciosa=ip).first()
            if not existe:
                session.add(ListaNegraIP(
                    ip_maliciosa=ip,
                    descripcion="Feodo_Tracker — Botnet/C2"
                ))
                contador_nuevas += 1
            else:
                contador_duplicadas += 1

        session.commit()
        print(f"[+] Descarga completa:")
        print(f"    → {contador_nuevas} IPs nuevas agregadas")
        print(f"    → {contador_duplicadas} ya existían (omitidas)")

    except Exception as e:
        session.rollback()
        print(f"[-] Error: {e}")
    finally:
        session.close()

if __name__ == "__main__":
    descargar_lista_inteligencia()
