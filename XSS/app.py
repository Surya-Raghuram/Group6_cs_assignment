import os
import sqlite3
import hashlib
import hmac

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from fastapi.staticfiles import StaticFiles


app = FastAPI()
templates = Jinja2Templates(directory="templates")

app.mount("/static", StaticFiles(directory="static"), name="static")

# Change this secret and keep it private.
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get("SESSION_SECRET", "dev-secret-change-this")
)


def get_db():
    conn = sqlite3.connect("comments.db")
    return conn


def hash_password(password: str):
    salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        200000
    )
    return salt.hex() + ":" + hashed.hex()


def verify_password(password: str, stored_hash: str):
    salt_hex, hash_hex = stored_hash.split(":")
    salt = bytes.fromhex(salt_hex)

    new_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        200000
    )

    return hmac.compare_digest(new_hash.hex(), hash_hex)


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL
        )
    """)

    # Add author column to existing comments table if necessary.
    columns = [
        row[1] for row in conn.execute(
            "PRAGMA table_info(comments)"
        ).fetchall()
    ]

    if "username" not in columns:
        conn.execute(
            "ALTER TABLE comments ADD COLUMN username TEXT DEFAULT 'Anonymous'"
        )

    conn.commit()
    conn.close()


# -------------------------
# HOME / BLOG
# -------------------------

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "username": request.session.get("username")
        }
    )


# -------------------------
# USER REGISTRATION
# -------------------------

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="register.html",
        context={"error": None}
    )


@app.post("/register")
async def register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    username = username.strip()

    if not username or len(username) > 30:
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={"error": "Username must be 1-30 characters."},
            status_code=400
        )

    if len(password) < 8:
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={"error": "Password must contain at least 8 characters."},
            status_code=400
        )

    conn = get_db()

    try:
        conn.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hash_password(password))
        )
        conn.commit()

    except sqlite3.IntegrityError:
        conn.close()

        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={"error": "Username already exists."},
            status_code=400
        )

    conn.close()

    return RedirectResponse("/login", status_code=303)


# -------------------------
# USER LOGIN
# -------------------------

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"error": None}
    )


@app.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    conn = get_db()

    user = conn.execute(
        "SELECT username, password FROM users WHERE username = ?",
        (username.strip(),)
    ).fetchone()

    conn.close()

    if user is None or not verify_password(password, user[1]):
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": "Invalid username or password."},
            status_code=401
        )

    request.session.clear()
    request.session["username"] = user[0]

    return RedirectResponse("/", status_code=303)


# -------------------------
# USER LOGOUT
# -------------------------

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=303)


# -------------------------
# ADD COMMENT (LOGIN REQUIRED)
# -------------------------

@app.post("/comment")
async def add_comment(
    request: Request,
    comment: str = Form(...)
):
    username = request.session.get("username")

    if not username:
        return RedirectResponse("/login", status_code=303)

    comment = comment.strip()

    if not comment or len(comment) > 2000:
        return RedirectResponse("/#comments", status_code=303)

    conn = get_db()

    conn.execute(
        "INSERT INTO comments (content, username) VALUES (?, ?)",
        (comment, username)
    )

    conn.commit()
    conn.close()

    return RedirectResponse("/comments", status_code=303)


# -------------------------
# VIEW COMMENTS
# -------------------------

@app.get("/comment", response_class=HTMLResponse)
async def comment_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "username": request.session.get("username")
        }
    )


@app.get("/comments", response_class=HTMLResponse)
async def view_comments(request: Request):
    conn = get_db()

    comments = conn.execute(
        "SELECT username, content FROM comments ORDER BY id DESC"
    ).fetchall()

    conn.close()

    return templates.TemplateResponse(
        request=request,
        name="comments.html",
        context={
            "comments": comments,
            "username": request.session.get("username")
        }
    )


# -------------------------
# SEARCH COMMENTS
# -------------------------

@app.get("/search", response_class=HTMLResponse)
async def search(request: Request, search: str = ""):
    conn = get_db()

    cursor = conn.execute(
        "SELECT username, content FROM comments WHERE content LIKE ?",
        (f"%{search}%",)
    )

    results = cursor.fetchall()
    conn.close()

    return templates.TemplateResponse(
        request=request,
        name="search.html",
        context={
            "query": search,
            "results": results
        }
    )

from fastapi import Body

@app.post("/webhook-test")
async def webhook_test(data: dict = Body(...)):

    print("\n========== WEBHOOK EVENT ==========")
    print("Username:", data.get("username"))
    print("Event:", data.get("event"))
    print("Status:", data.get("status"))
    print("===================================\n")

    return {"status": "received"}
init_db()
