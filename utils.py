import ipaddress
import re
import getpass
import os

# §UT-01
def es_ip_valida(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
7# §UT-02
def es_mac_valida(mac):
    regex = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
    return re.match(regex, mac) is not None

# §UT-03
def obtener_password_seguro(prompt="Contraseña: "):
    return getpass.getpass(prompt)

# §UT-04
def actualizar_env(key, value):
    lines = []
    if os.path.exists(".env"):
        with open(".env", "r") as f:
            lines = f.readlines()
    
    new_lines = []
    found = False
    for line in lines:
        if line.startswith(f"{key}="):
            new_lines.append(f"{key}={value}\n")
            found = True
        else:
            new_lines.append(line)
    if not found:
        new_lines.append(f"{key}={value}\n")
    
    with open(".env", "w") as f:
        f.writelines(new_lines)
