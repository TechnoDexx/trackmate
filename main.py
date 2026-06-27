# main.py
# -*- coding: utf-8 -*-

"""
TrackMate – защищённый менеджер встреч с шифрованием, автосохранением,
сбором информации о людях через Yandex Search API и функцией безвозвратного
уничтожения данных.
"""

import logging
import os
import sqlite3
import uuid
import json
import base64
from datetime import datetime
from fastapi import FastAPI, Form, Request, HTTPException, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from jinja2 import Environment, FileSystemLoader
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import httpx  # для запросов к Yandex API

# --- Загрузка переменных окружения ---
load_dotenv()
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", 8000))

# --- Логирование ---
logging.basicConfig(level=logging.INFO)
file_handler = logging.FileHandler("app.log")
file_handler.setLevel(logging.INFO)
logger = logging.getLogger(__name__)
logger.addHandler(file_handler)

# --- FastAPI приложение ---
app = FastAPI()

# --- Jinja2 ---
env = Environment(loader=FileSystemLoader("templates"), cache_size=0)

# --- База данных ---
DB_PATH = "trackmate.db"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# --- Функции шифрования ---
def derive_key(password: str, salt: bytes) -> bytes:
    """Превращает пароль и соль в ключ для Fernet (32 байта, base64)."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_text(text: str, key: bytes) -> str:
    if not text:
        return ""
    f = Fernet(key)
    return f.encrypt(text.encode()).decode()

def decrypt_text(encrypted: str, key: bytes) -> str:
    if not encrypted:
        return ""
    f = Fernet(key)
    return f.decrypt(encrypted.encode()).decode()

# --- Инициализация БД ---
def init_db():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            # Таблица встреч (шифруются: title, description)
            c.execute('''
                CREATE TABLE IF NOT EXISTS meetings (
                    id TEXT PRIMARY KEY,
                    title_enc TEXT NOT NULL,
                    description_enc TEXT,
                    start_time DATETIME,
                    end_time DATETIME,
                    status TEXT DEFAULT 'planned',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            # Таблица участников (шифруются: name, email, role)
            c.execute('''
                CREATE TABLE IF NOT EXISTS participants (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    meeting_id TEXT NOT NULL,
                    name_enc TEXT NOT NULL,
                    email_enc TEXT,
                    role_enc TEXT,
                    profile_id INTEGER,
                    FOREIGN KEY (meeting_id) REFERENCES meetings(id) ON DELETE CASCADE
                )
            ''')
            # Таблица профилей (досье на людей)
            c.execute('''
                CREATE TABLE IF NOT EXISTS profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name_enc TEXT NOT NULL,
                    email_enc TEXT,
                    phone_enc TEXT,
                    raw_data_enc TEXT,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            # Таблица черновиков (автосохранения)
            c.execute('''
                CREATE TABLE IF NOT EXISTS drafts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    meeting_id TEXT,
                    user_id TEXT NOT NULL,
                    draft_data TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (meeting_id) REFERENCES meetings(id) ON DELETE CASCADE
                )
            ''')
            # Таблица секретов (пароль, соль, настройки)
            c.execute('''
                CREATE TABLE IF NOT EXISTS secrets (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    last_login TIMESTAMP,
                    recovery_email TEXT
                )
            ''')
            # Проверяем, есть ли запись в secrets, иначе создаём заглушку
            c.execute("SELECT id FROM secrets WHERE id = 1")
            if not c.fetchone():
                c.execute("INSERT INTO secrets (id, password_hash, salt, last_login) VALUES (1, '', '', CURRENT_TIMESTAMP)")
            conn.commit()
            logger.info("База данных инициализирована")
    except sqlite3.Error as e:
        logger.error(f"Ошибка инициализации БД: {e}")
        raise RuntimeError("Не удалось инициализировать БД")

init_db()

# --- Глобальный словарь для хранения ключей шифрования по user_id ---
active_keys = {}  # user_id -> bytes (ключ)

# --- Функции для работы с паролем ---

def get_salt_and_hash():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT salt, password_hash FROM secrets WHERE id = 1")
        row = c.fetchone()
        if row:
            return row['salt'], row['password_hash']
        return None, None

def set_password(password: str):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    hash_bytes = kdf.derive(password.encode())
    password_hash = base64.urlsafe_b64encode(hash_bytes).decode()
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("UPDATE secrets SET salt = ?, password_hash = ? WHERE id = 1",
                  (base64.urlsafe_b64encode(salt).decode(), password_hash))
        conn.commit()

def verify_password(password: str) -> bool:
    salt_b64, hash_b64 = get_salt_and_hash()
    if not salt_b64 or not hash_b64:
        return False
    salt = base64.urlsafe_b64decode(salt_b64)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    try:
        kdf.verify(password.encode(), base64.urlsafe_b64decode(hash_b64))
        return True
    except Exception:
        return False

def get_key_for_user(user_id: str, password: str) -> bytes:
    salt_b64, _ = get_salt_and_hash()
    if not salt_b64:
        raise ValueError("Соль не найдена")
    salt = base64.urlsafe_b64decode(salt_b64)
    return derive_key(password, salt)

# --- Вспомогательные функции для шифрования/дешифрования объектов БД ---

def decrypt_meeting(row, key):
    if not row:
        return None
    d = dict(row)
    d['title'] = decrypt_text(d.pop('title_enc'), key)
    d['description'] = decrypt_text(d.pop('description_enc'), key)
    return d

def decrypt_participant(row, key):
    if not row:
        return None
    d = dict(row)
    try:
        d['name'] = decrypt_text(d.pop('name_enc'), key)
        d['email'] = decrypt_text(d.pop('email_enc'), key)
        d['role'] = decrypt_text(d.pop('role_enc'), key)
    except Exception as e:
        logger.error(f"Ошибка расшифровки участника ID {d.get('id')}: {e}")
        return None
    return d

def decrypt_profile(row, key):
    if not row:
        return None
    d = dict(row)
    d['name'] = decrypt_text(d.pop('name_enc'), key)
    d['email'] = decrypt_text(d.pop('email_enc'), key)
    d['phone'] = decrypt_text(d.pop('phone_enc'), key)
    raw = decrypt_text(d.pop('raw_data_enc'), key)
    d['raw_data'] = json.loads(raw) if raw else {}
    return d

# --- CRUD для встреч ---

def get_all_meetings(key):
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT id, title_enc, description_enc, start_time, end_time, status, created_at, updated_at FROM meetings ORDER BY created_at DESC")
            rows = c.fetchall()
            return [decrypt_meeting(r, key) for r in rows]
    except sqlite3.Error as e:
        logger.error(f"Ошибка получения встреч: {e}")
        raise HTTPException(500, "Ошибка БД")

def get_meeting(meeting_id, key):
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT id, title_enc, description_enc, start_time, end_time, status FROM meetings WHERE id = ?", (meeting_id,))
            row = c.fetchone()
            if not row:
                raise HTTPException(404, "Встреча не найдена")
            meeting = decrypt_meeting(row, key)
            c.execute("SELECT id, meeting_id, name_enc, email_enc, role_enc, profile_id FROM participants WHERE meeting_id = ?", (meeting_id,))
            p_rows = c.fetchall()
            logger.info(f"Найдено участников в БД: {len(p_rows)}")
            meeting['participants'] = []
            for p in p_rows:
                decrypted = decrypt_participant(p, key)
                if decrypted:
                    meeting['participants'].append(decrypted)
            logger.info(f"После расшифровки осталось: {len(meeting['participants'])}")
            return meeting
    except sqlite3.Error as e:
        logger.error(f"Ошибка получения встречи {meeting_id}: {e}")
        raise HTTPException(500, "Ошибка БД")

def create_meeting(title, description, start_time, end_time, status, participants, key):
    meeting_id = str(uuid.uuid4())
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            title_enc = encrypt_text(title, key)
            desc_enc = encrypt_text(description, key)
            c.execute(
                "INSERT INTO meetings (id, title_enc, description_enc, start_time, end_time, status) VALUES (?, ?, ?, ?, ?, ?)",
                (meeting_id, title_enc, desc_enc, start_time, end_time, status)
            )
            for p in participants:
                name_enc = encrypt_text(p.get('name', ''), key)
                email_enc = encrypt_text(p.get('email', ''), key)
                role_enc = encrypt_text(p.get('role', ''), key)
                profile_id = p.get('profile_id', None)
                c.execute(
                    "INSERT INTO participants (meeting_id, name_enc, email_enc, role_enc, profile_id) VALUES (?, ?, ?, ?, ?)",
                    (meeting_id, name_enc, email_enc, role_enc, profile_id)
                )
            conn.commit()
            return meeting_id
    except sqlite3.Error as e:
        logger.error(f"Ошибка создания встречи: {e}")
        raise HTTPException(500, "Ошибка БД")

def update_meeting(meeting_id, title, description, start_time, end_time, status, participants, key):
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            title_enc = encrypt_text(title, key)
            desc_enc = encrypt_text(description, key)
            c.execute(
                "UPDATE meetings SET title_enc = ?, description_enc = ?, start_time = ?, end_time = ?, status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (title_enc, desc_enc, start_time, end_time, status, meeting_id)
            )
            if c.rowcount == 0:
                raise HTTPException(404, "Встреча не найдена")
            c.execute("DELETE FROM participants WHERE meeting_id = ?", (meeting_id,))
            for p in participants:
                name_enc = encrypt_text(p.get('name', ''), key)
                email_enc = encrypt_text(p.get('email', ''), key)
                role_enc = encrypt_text(p.get('role', ''), key)
                profile_id = p.get('profile_id', None)
                c.execute(
                    "INSERT INTO participants (meeting_id, name_enc, email_enc, role_enc, profile_id) VALUES (?, ?, ?, ?, ?)",
                    (meeting_id, name_enc, email_enc, role_enc, profile_id)
                )
            conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Ошибка обновления встречи {meeting_id}: {e}")
        raise HTTPException(500, "Ошибка БД")

def delete_meeting(meeting_id, key):
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("DELETE FROM meetings WHERE id = ?", (meeting_id,))
            if c.rowcount == 0:
                raise HTTPException(404, "Встреча не найдена")
            conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Ошибка удаления встречи {meeting_id}: {e}")
        raise HTTPException(500, "Ошибка БД")

# --- CRUD для профилей ---

def create_profile(name, email, phone, raw_data, key):
    name_enc = encrypt_text(name, key)
    email_enc = encrypt_text(email, key) if email else ''
    phone_enc = encrypt_text(phone, key) if phone else ''
    raw_data_enc = encrypt_text(json.dumps(raw_data, ensure_ascii=False), key) if raw_data else ''
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute(
            "INSERT INTO profiles (name_enc, email_enc, phone_enc, raw_data_enc) VALUES (?, ?, ?, ?)",
            (name_enc, email_enc, phone_enc, raw_data_enc)
        )
        conn.commit()
        return c.lastrowid

def get_profile(profile_id, key):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT id, name_enc, email_enc, phone_enc, raw_data_enc, last_updated FROM profiles WHERE id = ?", (profile_id,))
        row = c.fetchone()
        if not row:
            return None
        return decrypt_profile(row, key)

def update_profile(profile_id, name, email, phone, raw_data, key):
    name_enc = encrypt_text(name, key)
    email_enc = encrypt_text(email, key) if email else ''
    phone_enc = encrypt_text(phone, key) if phone else ''
    raw_data_enc = encrypt_text(json.dumps(raw_data, ensure_ascii=False), key) if raw_data else ''
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute(
            "UPDATE profiles SET name_enc = ?, email_enc = ?, phone_enc = ?, raw_data_enc = ?, last_updated = CURRENT_TIMESTAMP WHERE id = ?",
            (name_enc, email_enc, phone_enc, raw_data_enc, profile_id)
        )
        conn.commit()

# --- Функции для черновиков (автосохранение) ---

def save_draft(meeting_id, user_id, draft_data, key):
    json_str = json.dumps(draft_data, ensure_ascii=False)
    encrypted = encrypt_text(json_str, key)
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT id FROM drafts WHERE meeting_id = ? AND user_id = ?", (meeting_id, user_id))
            row = c.fetchone()
            if row:
                c.execute("UPDATE drafts SET draft_data = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (encrypted, row['id']))
            else:
                c.execute("INSERT INTO drafts (meeting_id, user_id, draft_data) VALUES (?, ?, ?)", (meeting_id, user_id, encrypted))
            conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Ошибка сохранения черновика: {e}")
        raise HTTPException(500, "Ошибка БД")

def get_draft(meeting_id, user_id, key):
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT draft_data, updated_at FROM drafts WHERE meeting_id = ? AND user_id = ?", (meeting_id, user_id))
            row = c.fetchone()
            if row:
                decrypted = decrypt_text(row['draft_data'], key)
                return {
                    'draft': json.loads(decrypted),
                    'updated_at': row['updated_at']
                }
            return None
    except sqlite3.Error as e:
        logger.error(f"Ошибка загрузки черновика: {e}")
        raise HTTPException(500, "Ошибка БД")

# --- Middleware для установки user_id ---
@app.middleware("http")
async def set_user_id(request: Request, call_next):
    user_id = request.cookies.get("user_id")
    if not user_id:
        user_id = str(uuid.uuid4())
        response = await call_next(request)
        response.set_cookie(key="user_id", value=user_id, max_age=365*24*60*60)
        return response
    return await call_next(request)

# --- Проверка авторизации ---
def get_key_from_request(request: Request):
    user_id = request.cookies.get("user_id")
    if not user_id:
        return None
    return active_keys.get(user_id)

# --- Роуты ---

# 1. Главная
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    key = get_key_from_request(request)
    if key is None:
        return RedirectResponse("/login", status_code=303)
    meetings = get_all_meetings(key)
    template = env.get_template("index.html")
    return HTMLResponse(content=template.render(request=request, meetings=meetings))

# 2. Логин
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = ""):
    template = env.get_template("login.html")
    return HTMLResponse(content=template.render(request=request, error=error))

@app.post("/login")
async def login(request: Request, password: str = Form(...)):
    if verify_password(password):
        user_id = request.cookies.get("user_id")
        if not user_id:
            user_id = str(uuid.uuid4())
            response = RedirectResponse("/", status_code=303)
            response.set_cookie(key="user_id", value=user_id, max_age=365*24*60*60)
        else:
            response = RedirectResponse("/", status_code=303)
        key = get_key_for_user(user_id, password)
        active_keys[user_id] = key
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("UPDATE secrets SET last_login = CURRENT_TIMESTAMP WHERE id = 1")
            conn.commit()
        return response
    else:
        return RedirectResponse("/login?error=Неверный пароль", status_code=303)

@app.get("/logout")
async def logout(request: Request):
    user_id = request.cookies.get("user_id")
    if user_id and user_id in active_keys:
        del active_keys[user_id]
    return RedirectResponse("/login", status_code=303)

# 3. Установка пароля (первый запуск)
@app.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request, error: str = ""):
    salt_b64, _ = get_salt_and_hash()
    if salt_b64 and salt_b64 != '':
        return RedirectResponse("/login", status_code=303)
    template = env.get_template("setup.html")
    return HTMLResponse(content=template.render(request=request, error=error))

@app.post("/setup")
async def setup(request: Request, password: str = Form(...), confirm: str = Form(...)):
    if password != confirm:
        return RedirectResponse("/setup?error=Пароли не совпадают", status_code=303)
    if len(password) < 8:
        return RedirectResponse("/setup?error=Пароль должен быть не менее 8 символов", status_code=303)
    set_password(password)
    return RedirectResponse("/login", status_code=303)

# 4. Страницы встреч
@app.get("/meeting/new", response_class=HTMLResponse)
async def new_meeting_page(request: Request):
    key = get_key_from_request(request)
    if key is None:
        return RedirectResponse("/login", status_code=303)
    template = env.get_template("meeting.html")
    return HTMLResponse(content=template.render(request=request, meeting=None, draft=None))

@app.get("/meeting/{meeting_id}", response_class=HTMLResponse)
async def meeting_page(request: Request, meeting_id: str):
    key = get_key_from_request(request)
    if key is None:
        return RedirectResponse("/login", status_code=303)
    meeting = get_meeting(meeting_id, key)
    user_id = request.cookies.get("user_id")
    draft = None
    if user_id:
        draft = get_draft(meeting_id, user_id, key)
    template = env.get_template("meeting.html")
    return HTMLResponse(content=template.render(request=request, meeting=meeting, draft=draft))

@app.post("/meeting/new")
async def create_meeting_route(
    request: Request,
    title: str = Form(...),
    description: str = Form(""),
    start_time: str = Form(""),
    end_time: str = Form(""),
    status: str = Form("planned"),
    participants_json: str = Form("[]")
):
    key = get_key_from_request(request)
    if key is None:
        return RedirectResponse("/login", status_code=303)
    try:
        participants = json.loads(participants_json)
    except:
        participants = []
    meeting_id = create_meeting(title, description, start_time, end_time, status, participants, key)
    user_id = request.cookies.get("user_id")
    if user_id:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("DELETE FROM drafts WHERE meeting_id = ? AND user_id = ?", (meeting_id, user_id))
            conn.commit()
    return RedirectResponse(f"/meeting/{meeting_id}", status_code=303)

@app.post("/meeting/{meeting_id}/edit")
async def edit_meeting_route(
    request: Request,
    meeting_id: str,
    title: str = Form(...),
    description: str = Form(""),
    start_time: str = Form(""),
    end_time: str = Form(""),
    status: str = Form("planned"),
    participants_json: str = Form("[]")
):
    key = get_key_from_request(request)
    if key is None:
        return RedirectResponse("/login", status_code=303)
    try:
        participants = json.loads(participants_json)
    except:
        participants = []
    update_meeting(meeting_id, title, description, start_time, end_time, status, participants, key)
    user_id = request.cookies.get("user_id")
    if user_id:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("DELETE FROM drafts WHERE meeting_id = ? AND user_id = ?", (meeting_id, user_id))
            conn.commit()
    return RedirectResponse(f"/meeting/{meeting_id}", status_code=303)

@app.get("/meeting/{meeting_id}/delete")
async def delete_meeting_route(request: Request, meeting_id: str):
    key = get_key_from_request(request)
    if key is None:
        return RedirectResponse("/login", status_code=303)
    delete_meeting(meeting_id, key)
    return RedirectResponse("/", status_code=303)

# 5. API для автосохранения
@app.post("/api/meeting/autosave")
async def autosave(request: Request):
    key = get_key_from_request(request)
    if key is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    data = await request.json()
    meeting_id = data.get('meeting_id')
    user_id = request.cookies.get("user_id")
    if not user_id:
        user_id = str(uuid.uuid4())
    save_draft(meeting_id, user_id, data, key)
    return JSONResponse({"status": "ok"})

@app.get("/api/meeting/draft/{meeting_id}")
async def get_draft_api(request: Request, meeting_id: str):
    key = get_key_from_request(request)
    if key is None:
        return JSONResponse({"draft": None}, status_code=401)
    user_id = request.cookies.get("user_id")
    if not user_id:
        return JSONResponse({"draft": None}, status_code=404)
    draft = get_draft(meeting_id, user_id, key)
    if draft:
        return JSONResponse(draft)
    else:
        return JSONResponse({"draft": None}, status_code=404)

# 6. Yandex Search API – поиск информации о человеке
YANDEX_API_KEY = os.getenv("YANDEX_API_KEY")
YANDEX_FOLDER_ID = os.getenv("YANDEX_FOLDER_ID")

@app.get("/api/yandex_search_person")
async def yandex_search_person(request: Request, name: str, email: str = ""):
    """
    Ищет информацию о человеке через Yandex Search API (генеративный ответ).
    Возвращает структурированное досье и список источников.
    """
    key = get_key_from_request(request)
    if key is None:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    # Если API ключи не заданы – возвращаем тестовый ответ (заглушку)
    if not YANDEX_API_KEY or not YANDEX_FOLDER_ID:
        logger.warning("YANDEX_API_KEY или YANDEX_FOLDER_ID не заданы, возвращаем заглушку")
        return JSONResponse({
            "results": [{
                "name": name,
                "email": email,
                "summary": "⚠️ Yandex API не настроен. Добавьте YANDEX_API_KEY и YANDEX_FOLDER_ID в .env",
                "sources": []
            }]
        })

    query = f"Расскажи подробно о человеке: {name} {email}. Укажи профессию, место работы, образование, известные публикации, ссылки на соцсети и любую другую публичную информацию."

    # Документация Yandex Cloud AI Studio (YandexGPT + поиск)
    url = "https://llm.api.cloud.yandex.net/foundationModels/v1/generation"
    headers = {
        "Authorization": f"Api-Key {YANDEX_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "modelUri": f"gpt://{YANDEX_FOLDER_ID}/yandexgpt-lite",
        "completionOptions": {
            "stream": False,
            "temperature": 0.3,
            "maxTokens": 2000
        },
        "messages": [
            {
                "role": "system",
                "text": "Ты — помощник для сбора информации о людях из открытых источников. Отвечай структурированно и указывай источники."
            },
            {
                "role": "user",
                "text": query
            }
        ]
    }
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
            answer = data.get("result", {}).get("alternatives", [{}])[0].get("message", {}).get("text", "Информация не найдена")
            return JSONResponse({
                "results": [{
                    "name": name,
                    "email": email,
                    "summary": answer,
                    "sources": []
                }]
            })
    except httpx.HTTPStatusError as e:
        logger.error(f"Yandex API error: {e.response.text}")
        return JSONResponse({"error": f"API error: {e.response.status_code}"}, status_code=500)
    except Exception as e:
        logger.error(f"Yandex Search error: {e}")
        return JSONResponse({"error": "Search failed"}, status_code=500)

# 7. Сохранение профиля (из результатов поиска)
@app.post("/api/save_profile")
async def save_profile(request: Request, profile_data: dict):
    key = get_key_from_request(request)
    if key is None:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    name = profile_data.get('name', '')
    email = profile_data.get('email', '')
    phone = profile_data.get('phone', '')
    raw_data = profile_data.get('raw_data', {})
    if not name:
        return JSONResponse({"error": "Name required"}, status_code=400)
    profile_id = create_profile(name, email, phone, raw_data, key)
    return JSONResponse({"id": profile_id})

# 8. Экспорт всех данных
@app.get("/export")
async def export_data(request: Request):
    key = get_key_from_request(request)
    if key is None:
        return RedirectResponse("/login", status_code=303)
    meetings = get_all_meetings(key)
    for m in meetings:
        m['participants'] = get_meeting(m['id'], key)['participants']
    # Также экспортируем все профили
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT id, name_enc, email_enc, phone_enc, raw_data_enc FROM profiles")
        rows = c.fetchall()
        profiles = [decrypt_profile(r, key) for r in rows]
    export_data = {
        "meetings": meetings,
        "profiles": profiles,
        "exported_at": datetime.now().isoformat()
    }
    json_data = json.dumps(export_data, ensure_ascii=False, indent=2)
    encrypted = encrypt_text(json_data, key)
    return Response(content=encrypted, media_type="application/octet-stream",
                    headers={"Content-Disposition": "attachment; filename=trackmate_backup.enc"})

# 9. Уничтожение данных
@app.get("/destroy")
async def destroy_page(request: Request):
    key = get_key_from_request(request)
    if key is None:
        return RedirectResponse("/login", status_code=303)
    template = env.get_template("destroy_confirm.html")
    return HTMLResponse(content=template.render(request=request))

@app.post("/destroy/confirm")
async def destroy_confirm(request: Request, confirm: str = Form(...)):
    if confirm != "УНИЧТОЖИТЬ":
        return RedirectResponse("/", status_code=303)
    key = get_key_from_request(request)
    if key is None:
        return RedirectResponse("/login", status_code=303)
    # Удаляем все данные
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM meetings")
        c.execute("DELETE FROM participants")
        c.execute("DELETE FROM profiles")
        c.execute("DELETE FROM drafts")
        c.execute("DELETE FROM secrets")
        conn.commit()
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    user_id = request.cookies.get("user_id")
    if user_id in active_keys:
        del active_keys[user_id]
    init_db()
    return RedirectResponse("/setup", status_code=303)

# --- Запуск ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=HOST,
        port=PORT,
        reload=(os.getenv("ENV") == "development")
    )