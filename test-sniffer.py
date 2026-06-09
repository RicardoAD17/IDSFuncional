import time
import os
from dotenv import load_dotenv
from scapy.all import sniff, Ether, IP, TCP, UDP
from modelos_db import Session, EquipoAutorizado, ListaNegraIP

load_dotenv()

CACHE_EQUIPOS_AUTORIZADOS = {}
RATE_LIMIT_CACHE = {}

# §TS-01
def cargar_cache():
    global CACHE_EQUIPOS_AUTORIZADOS
    s = Session()
    equipos = s.query(EquipoAutorizado).filter_by(activo=True).all()
    CACHE_EQUIPOS_AUTORIZADOS = {e.mac_address: e.ip_address for e in equipos}
    s.close()
    print(f"[*] Cache cargado: {len(CACHE_EQUIPOS_AUTORIZADOS)} equipos autorizados")
    for mac, ip in CACHE_EQUIPOS_AUTORIZADOS.items():
        print(f"    → {mac} : {ip}")
    print()

# §TS-02 
def analizar_paquete(paquete):
    if not (paquete.haslayer(Ether) and paquete.haslayer(IP)):
        return

    mac_src = paquete[Ether].src
    ip_src  = paquete[IP].src

     # §TS-03
    if ip_src.startswith("127.") or ip_src == "0.0.0.0":
        return

    # §TS-04
    ip_autorizada = CACHE_EQUIPOS_AUTORIZADOS.get(mac_src)
    autorizado = (ip_autorizada == ip_src)

    estado = "✓ AUTORIZADO" if autorizado else "✗ NO AUTORIZADO"
    print(f"[{estado}]  MAC: {mac_src}  |  IP: {ip_src}")

    # §TS-05
    if not autorizado:
        tiempo_actual = time.time()
        ultimo = RATE_LIMIT_CACHE.get(ip_src, 0)
        en_cooldown = (tiempo_actual - ultimo) < 600

        if ip_autorizada is None:
            razon = "MAC no registrada en lista blanca"
        else:
            razon = f"MAC conocida pero IP no coincide (esperada: {ip_autorizada})"

        print(f"         Razón    : {razon}")
        print(f"         Cooldown : {'SÍ (no enviaría correo aún)' if en_cooldown else 'NO (dispararía correo)'}")
        print()

print("=" * 55)
print(" DIAGNÓSTICO DE SNIFFER — Capturando 30 segundos...")
print(" Genera tráfico desde otro dispositivo en la red")
print("=" * 55)
print()

cargar_cache()

#§TS-06
sniff(prn=analizar_paquete, store=False, timeout=30)

print("\n[*] Captura terminada.")
