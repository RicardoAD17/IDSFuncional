import urllib.request
from dotenv import load_dotenv
from modelos_db import Session, ListaNegraIP  

load_dotenv()

def descargar_lista_inteligencia():
    
    # §TH-01
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    print("[*] Descargando base de datos de amenazas globales (Feodo Tracker)...")
    
    session = Session()  
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            lineas = response.read().decode('utf-8').splitlines()

        contador_nuevas = 0
        contador_duplicadas = 0

        for linea in lineas:
             # §TH-02
            if linea.startswith("#") or not linea.strip():
                continue
            ip = linea.strip().split()[0]

            # §TH-03
            existe = session.query(ListaNegraIP).filter_by(ip_maliciosa=ip).first()
            if not existe:

                # §TH-04
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
