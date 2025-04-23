from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import secrets
import sqlite3
from datetime import datetime

app = FastAPI()
security = HTTPBasic()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = "pacientes.db"

USERS = {
    "admin": {"password": "clave123", "role": "admin"},
    "medico": {"password": "salud2024", "role": "medico"},
    "consulta": {"password": "ver123", "role": "consulta"},
}

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pacientes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre TEXT,
                edad INTEGER,
                diabetes BOOLEAN,
                tabaquismo BOOLEAN,
                tumor BOOLEAN,
                volumen REAL,
                procedimiento TEXT,
                fecha TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS auditoria (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario TEXT,
                endpoint TEXT,
                timestamp TEXT
            )
        """)
        conn.commit()

init_db()

async def verificar_credenciales(request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    user = USERS.get(credentials.username)
    if not user or not secrets.compare_digest(credentials.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales incorrectas",
            headers={"WWW-Authenticate": "Basic"},
        )
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO auditoria (usuario, endpoint, timestamp) VALUES (?, ?, ?)",
            (credentials.username, request.url.path, datetime.utcnow().isoformat())
        )
        conn.commit()
    return {"username": credentials.username, "role": user["role"]}

class Paciente(BaseModel):
    nombre: str
    edad: int
    diabetes: bool
    tabaquismo: bool
    tumor: bool
    volumen: float
    procedimiento: str
    fecha: str

@app.post("/guardar")
async def guardar_datos(paciente: Paciente, user=Depends(verificar_credenciales)):
    if user["role"] not in ["admin", "medico"]:
        raise HTTPException(status_code=403, detail="Permisos insuficientes")
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO pacientes (nombre, edad, diabetes, tabaquismo, tumor, volumen, procedimiento, fecha)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            paciente.nombre, paciente.edad, paciente.diabetes,
            paciente.tabaquismo, paciente.tumor,
            paciente.volumen, paciente.procedimiento, paciente.fecha
        ))
        conn.commit()
    return {"mensaje": f"Datos guardados con éxito por {user['username']}"}

@app.get("/registros")
async def obtener_registros(user=Depends(verificar_credenciales)):
    if user["role"] not in ["admin", "medico", "consulta"]:
        raise HTTPException(status_code=403, detail="Permisos insuficientes")
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM pacientes ORDER BY fecha DESC")
        columnas = [col[0] for col in cursor.description]
        rows = cursor.fetchall()
        resultados = [dict(zip(columnas, row)) for row in rows]
    return resultados

@app.get("/auditoria")
async def ver_auditoria(user=Depends(verificar_credenciales)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Solo administradores pueden ver auditoría")
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM auditoria ORDER BY timestamp DESC")
        columnas = [col[0] for col in cursor.description]
        rows = cursor.fetchall()
        resultados = [dict(zip(columnas, row)) for row in rows]
    return resultados
