# main.py
# -*- coding: utf-8 -*-
import logging
import os
import sqlite3
import uuid
import json
import base64
import shutil
import time
from datetime import datetime, timedelta
from fastapi import FastAPI, Form, Request, HTTPException, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from jinja2 import Environment, FileSystemLoader
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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
            # Таблица встреч (поля, которые шифруются: title, description, participants хранятся в зашифрованном виде)
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
            # Участники теперь хранятся в виде JSON-строки в поле meeting (чтобы не плодить таблицу)
            # Но для удобства оставим отдельную таблицу участников, но их имена/email тоже шифруются.
            c.execute('''
                CREATE TABLE IF NOT EXISTS participants (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    meeting_id TEXT NOT NULL,
                    name_enc TEXT NOT NULL,
                    email_enc TEXT,
                    role_enc TEXT,
                    FOREIGN KEY (meeting_id) REFERENCES meetings(id) ON DELETE CASCADE
                )
            ''')
            # Таблица для хранения пароля, соли и настроек dead man's switch
            c.execute('''
                CREATE TABLE IF NOT EXISTS secrets (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    last_login TIMESTAMP,
                    recovery_email TEXT
                )
            ''')
            # Проверяем, есть ли уже запись в secrets. Если нет – создаём заглушку (пока без пароля)
            c.execute("SELECT id FROM secrets WHERE id = 1")
            if not c.fetchone():
                # Сгенерируем временную соль и хеш для пустого пароля (чтобы структура была)
                # Но мы будем требовать установки пароля при первом запуске.
                # Пока вставим фиктивные данные, чтобы таблица существовала.
                c.execute("INSERT INTO secrets (id, password_hash, salt, last_login) VALUES (1, '', '', CURRENT_TIMESTAMP)")
            conn.commit()
            logger.info("База данных инициализирована")
    except sqlite3.Error as e:
        logger.error(f"Ошибка инициализации БД: {e}")
        raise RuntimeError("Не удалось инициализировать БД")

init_db()

# --- Глобальная переменная для хранения ключа (в сессии не храним, будем получать из cookie/сессии) ---
# В FastAPI нет встроенной сессии, поэтому будем хранить ключ в cookie (зашифрованном виде) или в глобальном словаре.
# Для простоты используем глобальный словарь (в реальном проекте лучше использовать Redis или JWT).
# Но для демонстрации оставим в памяти.
# ВНИМАНИЕ: при перезапуске сервера ключ теряется, и данные станут недоступны до нового ввода пароля.
active_keys = {}  # user_id -> key (bytes)

# --- Функции для работы с паролем и ключом ---

def get_salt_and_hash():
    """Возвращает соль и хеш пароля из БД."""
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT salt, password_hash FROM secrets WHERE id = 1")
        row = c.fetchone()
        if row:
            return row['salt'], row['password_hash']
        return None, None

def set_password(password: str):
    """Устанавливает новый пароль (соль и хеш)."""
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    hash_bytes = kdf.derive(password.encode())
    password_hash = base64.urlsafe_b64encode(hash_bytes).decode()
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("UPDATE secrets SET salt = ?, password_hash = ? WHERE id = 1", (base64.urlsafe_b64encode(salt).decode(), password_hash))
        conn.commit()

def verify_password(password: str) -> bool:
    """Проверяет введённый пароль."""
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
    """Генерирует ключ на основе пароля и соли."""
    salt_b64, _ = get_salt_and_hash()
    if not salt_b64:
        raise ValueError("Соль не найдена")
    salt = base64.urlsafe_b64decode(salt_b64)
    return derive_key(password, salt)

# --- Функции работы с БД (с шифрованием) ---

def decrypt_meeting(meeting_row, key):
    """Преобразует строку из БД в словарь с расшифрованными полями."""
    if not meeting_row:
        return None
    d = dict(meeting_row)
    d['title'] = decrypt_text(d.pop('title_enc'), key)
    d['description'] = decrypt_text(d.pop('description_enc'), key)
    return d

def decrypt_participant(p_row, key):
    if not p_row:
        return None
    d = dict(p_row)
    d['name'] = decrypt_text(d.pop('name_enc'), key)
    d['email'] = decrypt_text(d.pop('email_enc'), key)
    d['role'] = decrypt_text(d.pop('role_enc'), key)
    return d

# --- CRUD для встреч (с шифрованием) ---

def get_all_meetings(key):
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT id, title_enc, description_enc, start_time, end_time, status, created_at, updated_at FROM meetings ORDER BY created_at DESC")
            rows = c.fetchall()
            meetings = []
            for row in rows:
                m = decrypt_meeting(row, key)
                meetings.append(m)
            return meetings
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
            # Загружаем участников
            c.execute("SELECT id, meeting_id, name_enc, email_enc, role_enc FROM participants WHERE meeting_id = ?", (meeting_id,))
            p_rows = c.fetchall()
            meeting['participants'] = [decrypt_participant(p, key) for p in p_rows]
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
                c.execute(
                    "INSERT INTO participants (meeting_id, name_enc, email_enc, role_enc) VALUES (?, ?, ?, ?)",
                    (meeting_id, name_enc, email_enc, role_enc)
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
            # Удаляем старых участников
            c.execute("DELETE FROM participants WHERE meeting_id = ?", (meeting_id,))
            for p in participants:
                name_enc = encrypt_text(p.get('name', ''), key)
                email_enc = encrypt_text(p.get('email', ''), key)
                role_enc = encrypt_text(p.get('role', ''), key)
                c.execute(
                    "INSERT INTO participants (meeting_id, name_enc, email_enc, role_enc) VALUES (?, ?, ?, ?)",
                    (meeting_id, name_enc, email_enc, role_enc)
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

# --- Функции для черновиков (drafts) — они тоже шифруются? Нет, черновик содержит незашифрованные данные?
# Лучше хранить черновики в зашифрованном виде, но для простоты оставим как есть,
# так как они хранятся кратковременно и пользователь может не хотеть их шифровать.
# Однако для конфиденциальности зашифруем и их.
# Для черновиков используем те же функции шифрования.

def save_draft(meeting_id, user_id, draft_data, key):
    # Сериализуем draft_data в JSON и шифруем целиком
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

# --- Middleware для установки user_id (без изменений) ---
@app.middleware("http")
async def set_user_id(request: Request, call_next):
    user_id = request.cookies.get("user_id")
    if not user_id:
        user_id = str(uuid.uuid4())
        response = await call_next(request)
        response.set_cookie(key="user_id", value=user_id, max_age=365*24*60*60)
        return response
    return await call_next(request)

# --- Проверка аутентификации (наличие ключа в сессии) ---
# В FastAPI нет сессий, поэтому будем использовать глобальный словарь active_keys, привязанный к user_id.
# При входе пользователь вводит пароль, мы вычисляем ключ и сохраняем в active_keys[user_id].
# Для проверки используем декоратор или зависимость.

def get_key_from_request(request: Request):
    user_id = request.cookies.get("user_id")
    if not user_id:
        return None
    key = active_keys.get(user_id)
    if key is None:
        return None
    return key

# --- Роуты ---

# 1. Главная страница — требует авторизации (если ключа нет — редирект на /login)
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    key = get_key_from_request(request)
    if key is None:
        return RedirectResponse("/login", status_code=303)
    meetings = get_all_meetings(key)
    template = env.get_template("index.html")
    return HTMLResponse(content=template.render(request=request, meetings=meetings))

# 2. Страница входа (login)
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = ""):
    template = env.get_template("login.html")
    return HTMLResponse(content=template.render(request=request, error=error))

# 3. Обработка входа (POST)
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
        # Генерируем ключ и сохраняем
        key = get_key_for_user(user_id, password)
        active_keys[user_id] = key
        # Обновляем last_login
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("UPDATE secrets SET last_login = CURRENT_TIMESTAMP WHERE id = 1")
            conn.commit()
        return response
    else:
        return RedirectResponse("/login?error=Неверный пароль", status_code=303)

# 4. Выход (удаляем ключ, но не пароль)
@app.get("/logout")
async def logout(request: Request):
    user_id = request.cookies.get("user_id")
    if user_id and user_id in active_keys:
        del active_keys[user_id]
    return RedirectResponse("/login", status_code=303)

# 5. Первоначальная настройка пароля (если ещё не задан)
@app.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request, error: str = ""):
    # Проверяем, задан ли пароль
    salt_b64, _ = get_salt_and_hash()
    if salt_b64 and salt_b64 != '':
        # Если пароль уже есть, редирект на логин
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
    # После установки пароля перенаправляем на логин
    return RedirectResponse("/login", status_code=303)

# 6. Страницы встреч (требуют ключ)
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
    # Очищаем черновик
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

# 7. API для автосохранения (требует ключ)
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

# --- 8. Экспорт всех данных (зашифрованный дамп) ---
@app.get("/export")
async def export_data(request: Request):
    key = get_key_from_request(request)
    if key is None:
        return RedirectResponse("/login", status_code=303)
    # Собираем все встречи
    meetings = get_all_meetings(key)
    for m in meetings:
        # Загружаем участников для каждой встречи
        m['participants'] = get_meeting(m['id'], key)['participants']
    # Формируем JSON
    json_data = json.dumps(meetings, ensure_ascii=False, indent=2)
    # Шифруем тем же ключом
    encrypted = encrypt_text(json_data, key)
    # Возвращаем как файл для скачивания
    from fastapi.responses import Response
    return Response(content=encrypted, media_type="application/octet-stream", headers={"Content-Disposition": "attachment; filename=trackmate_backup.enc"})

# --- 9. Уничтожение всех данных (безвозвратно) ---
@app.get("/destroy")
async def destroy_data(request: Request):
    key = get_key_from_request(request)
    if key is None:
        return RedirectResponse("/login", status_code=303)
    # Запрашиваем подтверждение через шаблон
    template = env.get_template("destroy_confirm.html")
    return HTMLResponse(content=template.render(request=request))

@app.post("/destroy/confirm")
async def destroy_confirm(request: Request, confirm: str = Form(...)):
    if confirm != "УНИЧТОЖИТЬ":
        return RedirectResponse("/", status_code=303)
    key = get_key_from_request(request)
    if key is None:
        return RedirectResponse("/login", status_code=303)
    # 1. Удаляем все записи из таблиц
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM meetings")
        c.execute("DELETE FROM participants")
        c.execute("DELETE FROM drafts")
        # Обнуляем last_login, но не удаляем пароль (чтобы можно было восстановить, если пользователь передумал?)
        # Но он хочет безвозвратно. Удалим и секреты.
        c.execute("DELETE FROM secrets")
        conn.commit()
    # 2. Закрываем соединение и удаляем файл БД
    # Принудительно закроем все соединения? Просто удалим файл.
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    # 3. Удаляем ключ из памяти
    user_id = request.cookies.get("user_id")
    if user_id in active_keys:
        del active_keys[user_id]
    # 4. Пересоздаём БД заново (чтобы приложение не упало)
    init_db()
    # 5. Редирект на установку пароля (теперь он заново создастся)
    return RedirectResponse("/setup", status_code=303)

# --- 10. Dead man's switch (опционально) — фоновый поток ---
# Запускаем в отдельном потоке проверку last_login и отправку почты.
# Для отправки почты нужно настроить SMTP.
# Здесь я покажу только логику проверки, а отправку можно добавить.

def deadman_switch_worker():
    """Фоновый процесс, проверяющий каждые 24 часа, не прошло ли больше N дней с последнего входа."""
    # Настройки: количество дней до тревоги (например, 30)
    DEAD_DAYS = 30
    while True:
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("SELECT last_login, recovery_email FROM secrets WHERE id = 1")
                row = c.fetchone()
                if row:
                    last_login_str = row['last_login']
                    email = row['recovery_email']
                    if last_login_str and email:
                        last_login = datetime.fromisoformat(last_login_str)
                        if datetime.now() - last_login > timedelta(days=DEAD_DAYS):
                            logger.warning(f"Dead man's switch triggered! Last login was {last_login_str}. Sending email to {email}")
                            # Здесь вызываем функцию отправки email с зашифрованным дампом
                            # Нужно сгенерировать ключ? Но ключ может быть неизвестен, если пароль не введён.
                            # Лучше заранее сохранить зашифрованный дамп при каждом изменении? Или использовать пароль, хранящийся в памяти?
                            # Это сложно. Для простоты можно хранить резервную копию в отдельном файле, но это нарушает безопасность.
                            # Я рекомендую не реализовывать автоматическую отправку, а оставить только ручной экспорт.
                            # Но для полноты я оставлю заглушку.
                            pass
        except Exception as e:
            logger.error(f"Dead man's switch error: {e}")
        time.sleep(86400)  # 24 часа

# Запуск фонового потока (если нужно)
# import threading
# t = threading.Thread(target=deadman_switch_worker, daemon=True)
# t.start()

# --- Запуск ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=HOST,
        port=PORT,
        reload=(os.getenv("ENV") == "development")
    )