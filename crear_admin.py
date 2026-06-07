import bcrypt
from modelos_db import Session, UsuarioIAM

def crear_administrador():
    session = Session()
    
    # 1. Verificar si ya existe un admin para no duplicar
    if session.query(UsuarioIAM).filter_by(rol='ADMIN').first():
        print("[!] ¡Ya existe un administrador en la base de datos!")
        session.close()
        return

    print("--- CREACIÓN DE ADMINISTRADOR INICIAL ---")
    user = input("Nombre de usuario: ").strip()
    password = input("Contraseña: ").strip()
    email = input("Correo electrónico para alertas: ").strip()

    # 2. Cifrar la contraseña con bcrypt (importante para la seguridad)
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # 3. Crear el objeto usuario
    # Nota: Asegúrate de añadir el campo 'email' a tu modelo si no lo tienes,
    # o si prefieres, simplemente guarda el usuario y actualiza el email después.
    nuevo_admin = UsuarioIAM(username=user, password_hash=hashed, rol='ADMIN')
    
    try:
        session.add(nuevo_admin)
        session.commit()
        print(f"[+] Administrador '{user}' creado correctamente.")
        print("[+] Base de datos cifrada actualizada.")
    except Exception as e:
        print(f"[-] Error al crear admin: {e}")
        session.rollback()
    finally:
        session.close()

if __name__ == "__main__":
    crear_administrador()
