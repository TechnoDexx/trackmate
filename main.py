# main.py
import logging
import os
import sqlite3
import uuid
from fastapi import FastAPI, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from jinja2 import Environment, FileSystemLoader
from dotenv import load_dotenv

# --- Загрузка переменных окружения ---
load_dotenv()
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", 8000))

# --- Настройка логирования ---
logging.basicConfig(level=logging.INFO)
file_handler = logging.FileHandler("app.log")
file_handler.setLevel(logging.INFO)
logger = logging.getLogger(__name__)
logger.addHandler(file_handler)

app = FastAPI()

# --- Jinja2 без кэша (исправление ошибки) ---
env = Environment(loader=FileSystemLoader("templates"), cache_size=0)

# --- База данных ---
DB_PATH = "contacts.db"

def get_db_connection():
    """Возвращает соединение с БД и включает обработку строк как словарей."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('''
                CREATE TABLE IF NOT EXISTS contacts (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    phone TEXT,
                    email TEXT,
                    notes TEXT,
                    tags TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()
            logger.info("Database initialized successfully")
    except sqlite3.Error as e:
        logger.error(f"Failed to initialize database: {e}")
        raise RuntimeError("Database initialization failed") from e

init_db()

# --- Функции работы с БД ---
def get_contacts():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT id, name, phone, email, notes, tags FROM contacts ORDER BY created_at DESC")
            rows = c.fetchall()
            return [dict(row) for row in rows]
    except sqlite3.Error as e:
        logger.error(f"Error fetching contacts: {e}")
        raise HTTPException(status_code=500, detail="Database error")

def add_contact(name, phone, email, notes, tags):
    # базовая валидация
    if not name or not name.strip():
        raise ValueError("Name is required")
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute(
                "INSERT INTO contacts (id, name, phone, email, notes, tags) VALUES (?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), name.strip(), phone, email, notes, tags)
            )
            conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Error adding contact: {e}")
        raise HTTPException(status_code=500, detail="Database error")

def delete_contact(contact_id):
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("DELETE FROM contacts WHERE id = ?", (contact_id,))
            if c.rowcount == 0:
                raise HTTPException(status_code=404, detail="Contact not found")
            conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Error deleting contact {contact_id}: {e}")
        raise HTTPException(status_code=500, detail="Database error")

# --- Роуты ---
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    try:
        contacts = get_contacts()
        template = env.get_template("index.html")
        html = template.render(request=request, contacts=contacts)
        return HTMLResponse(content=html)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in index: {e}")
        return HTMLResponse(
            content="<h1>Internal Server Error</h1><p>Please try again later.</p>",
            status_code=500
        )

@app.post("/add")
async def add(
    request: Request,
    name: str = Form(...),
    phone: str = Form(""),
    email: str = Form(""),
    notes: str = Form(""),
    tags: str = Form("")
):
    try:
        add_contact(name, phone, email, notes, tags)
        return RedirectResponse("/", status_code=303)
    except ValueError as e:
        # Ошибка валидации – возвращаем на главную с сообщением
        logger.warning(f"Validation error: {e}")
        return RedirectResponse("/?error=invalid_name", status_code=303)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in add: {e}")
        return RedirectResponse("/?error=server", status_code=303)

@app.get("/delete/{contact_id}")
async def delete(contact_id: str):
    try:
        delete_contact(contact_id)
        return RedirectResponse("/", status_code=303)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in delete: {e}")
        return RedirectResponse("/?error=server", status_code=303)

# --- Запуск (для разработки) ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=HOST,
        port=PORT,
        reload=True if os.getenv("ENV") == "development" else False
    )