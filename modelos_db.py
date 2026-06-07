import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
from sqlcipher3 import dbapi2 as sqlite

load_dotenv()
DB_KEY = os.getenv("DB_KEY")

if not DB_KEY:
    raise RuntimeError("[-] FATAL: La variable DB_KEY no está definida en .env")

Base = declarative_base()

class UsuarioIAM(Base):
    __tablename__ = 'usuarios_iam'
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    rol = Column(String(20), default='ADMIN')
    email = Column(String(100), nullable=True)  # ← CAMPO FALTANTE

class EquipoAutorizado(Base):
    __tablename__ = 'equipos_autorizados'
    id = Column(Integer, primary_key=True, autoincrement=True)
    mac_address = Column(String(17), unique=True, nullable=False)
    ip_address = Column(String(15), nullable=False)
    propietario = Column(String(100), nullable=False)
    activo = Column(Boolean, default=True)

class BitacoraTrafico(Base):
    __tablename__ = 'bitacora_trafico'
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.now)  # hora local, consistente con main.py
    ip_origen = Column(String(15), nullable=False)
    dominio_visitado = Column(String(255), nullable=False)
    protocolo = Column(String(10), nullable=False)

class RegistroAmenazas(Base):
    __tablename__ = 'registro_amenazas'
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.now)
    ip_implicada = Column(String(15), nullable=False)
    tipo_amenaza = Column(String(50), nullable=False)
    alerta_enviada = Column(Boolean, default=False)

class ListaNegraIP(Base):
    __tablename__ = 'lista_negra'
    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_maliciosa = Column(String(15), unique=True, nullable=False)
    descripcion = Column(String(100))

def db_creator():
    conn = sqlite.connect('ids_database.db')
    conn.execute(f"PRAGMA key='{DB_KEY}';")
    # Verificamos que la clave sea correcta antes de continuar
    conn.execute("SELECT count(*) FROM sqlite_master;")
    return conn

engine = create_engine(
    'sqlite://',
    creator=db_creator,
    connect_args={"check_same_thread": False}
)
Session = sessionmaker(bind=engine)
Base.metadata.create_all(engine)
