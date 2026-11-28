"""Minimal secure API foundation for Kalkulačka E-liquidů 2.6.

Run with: uvicorn app:app --host 0.0.0.0 --port 8000
Required env: DATABASE_URL, JWT_SECRET (32+ random bytes).
This service is ONLINE-only. HOST continues to use the existing local SQLite core.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage
from datetime import datetime, timezone
from typing import Annotated

import psycopg
from fastapi import Depends, FastAPI, Header, HTTPException, Request, WebSocket, WebSocketDisconnect, status
from fastapi.responses import HTMLResponse
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field, ConfigDict

DATABASE_URL = os.environ.get("DATABASE_URL", "")
JWT_SECRET = os.environ.get("JWT_SECRET", "")
TOKEN_TTL_SECONDS = int(os.environ.get("TOKEN_TTL_SECONDS", "3600"))
EMAIL_TOKEN_TTL_SECONDS = int(os.environ.get("EMAIL_TOKEN_TTL_SECONDS", "86400"))
RESET_TOKEN_TTL_SECONDS = min(max(int(os.environ.get("RESET_TOKEN_TTL_SECONDS", "900")), 60), 900)
RESET_CODE_MAX_ATTEMPTS = 5
RESET_RESEND_COOLDOWN_SECONDS = 60
MAKE_WEBHOOK_URL = os.environ.get("MAKE_WEBHOOK_URL", "").strip()
MAKE_API_KEY = os.environ.get("MAKE_API_KEY", "").strip()
PUBLIC_API_URL = os.environ.get("PUBLIC_API_URL", "https://kalkulacka-eliquidu-api.onrender.com").strip().rstrip("/")

logger = logging.getLogger("eliquid_api")

app = FastAPI(title="Kalkulačka E-liquidů API", version="2.6.0-dev", docs_url="/docs", redoc_url="/redoc")

class SyncSocketHub:
    """Per-process authenticated WebSocket fan-out with thread-safe publish."""
    def __init__(self):
        self.connections: dict[int, set[WebSocket]] = {}
        self.loop = None
    def bind_loop(self):
        # FastAPI sync endpoints run in a worker thread. Keep the ASGI loop so
        # committed writes can safely schedule notifications back onto it.
        import asyncio
        self.loop = asyncio.get_running_loop()
    def disconnect(self, user_id: int, ws: WebSocket):
        peers=self.connections.get(user_id)
        if peers:
            peers.discard(ws)
            if not peers: self.connections.pop(user_id, None)
    async def publish(self, user_id: int, revision: int):
        payload={"type":"sync_changed","revision":int(revision)}
        for ws in list(self.connections.get(user_id, set())):
            try: await ws.send_json(payload)
            except Exception: self.disconnect(user_id, ws)

sync_socket_hub=SyncSocketHub()

# CORS je povolen pouze pro explicitně nakonfigurované webové originy.
# Nikdy nepoužívat wildcard (*) spolu s přihlašovacími údaji.
_allowed_origins = [
    origin.strip().rstrip("/")
    for origin in os.environ.get("ALLOWED_ORIGINS", "").split(",")
    if origin.strip()
]
if any(origin == "*" for origin in _allowed_origins):
    raise RuntimeError("ALLOWED_ORIGINS nesmí obsahovat wildcard '*'.")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def hash_password(password: str, salt: bytes | None = None) -> str:
    """PBKDF2-SHA256 password hash; salt and parameters are stored with hash."""
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000)
    return f"pbkdf2_sha256$310000${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, rounds, salt, expected = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256" or int(rounds) < 310_000:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), _unb64(salt), int(rounds))
        return hmac.compare_digest(actual, _unb64(expected))
    except (ValueError, TypeError):
        return False


def create_token(user_id: int, auth_version: int = 0) -> str:
    if len(JWT_SECRET.encode("utf-8")) < 32:
        raise RuntimeError("JWT_SECRET musí obsahovat alespoň 32 znaků.")
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    now = int(time.time())
    payload = _b64(json.dumps({"sub": str(user_id), "ver": int(auth_version), "iat": now, "exp": now + TOKEN_TTL_SECONDS}, separators=(",", ":")).encode())
    body = f"{header}.{payload}"
    signature = _b64(hmac.new(JWT_SECRET.encode(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{signature}"


def decode_token(token: str) -> tuple[int, int]:
    try:
        head, payload, signature = token.split(".")
        body = f"{head}.{payload}"
        expected = _b64(hmac.new(JWT_SECRET.encode(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            raise ValueError("signature")
        claims = json.loads(_unb64(payload))
        if claims.get("exp", 0) <= int(time.time()):
            raise ValueError("expired")
        user_id = int(claims["sub"])
        if user_id <= 0:
            raise ValueError("subject")
        auth_version = int(claims.get("ver", 0))
        if auth_version < 0:
            raise ValueError("version")
        return user_id, auth_version
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Neplatné nebo vypršené přihlášení.") from exc


def get_connection():
    if not DATABASE_URL:
        raise HTTPException(status_code=503, detail="Online databáze není nakonfigurována.")
    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=5) as conn:
            yield conn
    except psycopg.OperationalError as exc:
        raise HTTPException(status_code=503, detail="Online databáze není dostupná.") from exc


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _send_account_email(recipient: str, email_type: str, language: str, token: str) -> None:
    """Send account email through the authenticated Make.com webhook."""
    if not MAKE_WEBHOOK_URL or not MAKE_API_KEY:
        logger.error("Make email delivery is not configured on the server.")
        raise HTTPException(status_code=503, detail="E-mailovou službu se nepodařilo kontaktovat. Zkuste to později.")
    if email_type not in {"verify", "resend", "reset"}:
        raise ValueError("Unsupported account email type")
    lang = str(language or "CS").upper()
    if lang not in {"CS", "EN", "DE", "FR", "PL", "ES"}:
        lang = "CS"
    # VERIFY/RESEND use a one-click confirmation link. RESET sends an
    # eight-digit code that is entered in the desktop app, not a web link.
    link = ""
    if email_type != "reset":
        link = f"{PUBLIC_API_URL}/account/verify?{urllib.parse.urlencode({'lang': lang})}#{urllib.parse.urlencode({'token': token})}"
    payload = {
        "email": recipient,
        "type": email_type,
        "lang": lang.lower(),
        "link": link,
        "code": token if email_type == "reset" else "",
        "requestId": str(uuid.uuid4()),
        "timestamp": int(time.time()),
    }
    request = urllib.request.Request(
        MAKE_WEBHOOK_URL,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"x-make-apikey": MAKE_API_KEY, "Content-Type": "application/json", "Accept": "application/json", "User-Agent": "Kalkulacka-Eliquidu-API/2.6"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            response.read(4096)
            if response.status < 200 or response.status >= 300:
                raise ValueError("Make did not accept the email request")
    except urllib.error.HTTPError as exc:
        logger.error("Make rejected account email request: HTTP %s.", exc.code)
        raise HTTPException(status_code=503, detail="E-mailovou službu se nepodařilo kontaktovat. Zkuste to později.") from exc
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        logger.error("Make account email request failed: %s.", type(exc).__name__)
        raise HTTPException(status_code=503, detail="E-mailovou službu se nepodařilo kontaktovat. Zkuste to později.") from exc


_EMAIL_PAGE_TEXT = {
    "CS": {"verify_title":"Ověření e-mailové adresy", "verify_text":"Kliknutím potvrďte, že tato e-mailová adresa patří vám.", "verify_button":"OVĚŘIT E-MAIL", "reset_title":"Nastavení nového hesla", "reset_text":"Zadejte nové heslo. Musí obsahovat alespoň 12 znaků.", "password":"Nové heslo", "confirm":"Zopakujte nové heslo", "reset_button":"ZMĚNIT HESLO", "success_verify":"E-mailová adresa byla ověřena. Nyní se můžete vrátit do Kalkulačky E-liquidů a přihlásit se.", "success_reset":"Heslo bylo změněno. Nyní se můžete vrátit do Kalkulačky E-liquidů a přihlásit se.", "expired":"Odkaz je neplatný nebo jeho platnost vypršela. Vyžádejte si nový e-mail.", "mismatch":"Zadaná hesla se neshodují.", "working":"Zpracovávám…", "min":"Heslo musí mít alespoň 12 znaků."},
    "EN": {"verify_title":"Verify your email address", "verify_text":"Confirm that this email address belongs to you.", "verify_button":"VERIFY EMAIL", "reset_title":"Set a new password", "reset_text":"Enter a new password with at least 12 characters.", "password":"New password", "confirm":"Confirm new password", "reset_button":"CHANGE PASSWORD", "success_verify":"Your email address has been verified. Return to Kalkulačka E-liquidů and sign in.", "success_reset":"Your password has been changed. Return to Kalkulačka E-liquidů and sign in.", "expired":"This link is invalid or has expired. Request a new email.", "mismatch":"The passwords do not match.", "working":"Please wait…", "min":"The password must contain at least 12 characters."},
    "DE": {"verify_title":"E-Mail-Adresse bestätigen", "verify_text":"Bestätigen Sie, dass diese E-Mail-Adresse Ihnen gehört.", "verify_button":"E-MAIL BESTÄTIGEN", "reset_title":"Neues Passwort festlegen", "reset_text":"Geben Sie ein neues Passwort mit mindestens 12 Zeichen ein.", "password":"Neues Passwort", "confirm":"Neues Passwort bestätigen", "reset_button":"PASSWORT ÄNDERN", "success_verify":"Ihre E-Mail-Adresse wurde bestätigt. Kehren Sie zu Kalkulačka E-liquidů zurück und melden Sie sich an.", "success_reset":"Ihr Passwort wurde geändert. Kehren Sie zu Kalkulačka E-liquidů zurück und melden Sie sich an.", "expired":"Dieser Link ist ungültig oder abgelaufen. Fordern Sie eine neue E-Mail an.", "mismatch":"Die Passwörter stimmen nicht überein.", "working":"Bitte warten…", "min":"Das Passwort muss mindestens 12 Zeichen enthalten."},
    "FR": {"verify_title":"Vérifier votre adresse e-mail", "verify_text":"Confirmez que cette adresse e-mail vous appartient.", "verify_button":"VÉRIFIER L’E-MAIL", "reset_title":"Définir un nouveau mot de passe", "reset_text":"Saisissez un nouveau mot de passe d’au moins 12 caractères.", "password":"Nouveau mot de passe", "confirm":"Confirmer le nouveau mot de passe", "reset_button":"MODIFIER LE MOT DE PASSE", "success_verify":"Votre adresse e-mail est vérifiée. Revenez à Kalkulačka E-liquidů et connectez-vous.", "success_reset":"Votre mot de passe a été modifié. Revenez à Kalkulačka E-liquidů et connectez-vous.", "expired":"Ce lien est invalide ou a expiré. Demandez un nouvel e-mail.", "mismatch":"Les mots de passe ne correspondent pas.", "working":"Veuillez patienter…", "min":"Le mot de passe doit contenir au moins 12 caractères."},
    "PL": {"verify_title":"Potwierdź adres e-mail", "verify_text":"Potwierdź, że ten adres e-mail należy do Ciebie.", "verify_button":"POTWIERDŹ E-MAIL", "reset_title":"Ustaw nowe hasło", "reset_text":"Wpisz nowe hasło zawierające co najmniej 12 znaków.", "password":"Nowe hasło", "confirm":"Potwierdź nowe hasło", "reset_button":"ZMIEŃ HASŁO", "success_verify":"Adres e-mail został potwierdzony. Wróć do Kalkulačka E-liquidů i zaloguj się.", "success_reset":"Hasło zostało zmienione. Wróć do Kalkulačka E-liquidů i zaloguj się.", "expired":"Ten link jest nieprawidłowy lub wygasł. Poproś o nową wiadomość.", "mismatch":"Hasła nie są zgodne.", "working":"Proszę czekać…", "min":"Hasło musi zawierać co najmniej 12 znaków."},
    "ES": {"verify_title":"Verificar dirección de correo", "verify_text":"Confirma que esta dirección de correo te pertenece.", "verify_button":"VERIFICAR CORREO", "reset_title":"Crear una nueva contraseña", "reset_text":"Introduce una contraseña nueva de al menos 12 caracteres.", "password":"Nueva contraseña", "confirm":"Confirmar nueva contraseña", "reset_button":"CAMBIAR CONTRASEÑA", "success_verify":"Tu dirección de correo ha sido verificada. Vuelve a Kalkulačka E-liquidů e inicia sesión.", "success_reset":"Tu contraseña ha sido cambiada. Vuelve a Kalkulačka E-liquidů e inicia sesión.", "expired":"Este enlace no es válido o ha caducado. Solicita un nuevo correo.", "mismatch":"Las contraseñas no coinciden.", "working":"Procesando…", "min":"La contraseña debe tener al menos 12 caracteres."},
}


def _account_action_page(kind: str, language: str) -> HTMLResponse:
    """Render a confirmation page. GET does not consume tokens (mail scanners)."""
    lang = language.upper() if language.upper() in _EMAIL_PAGE_TEXT else "CS"
    t = _EMAIL_PAGE_TEXT[lang]
    is_reset = kind == "reset"
    title = t["reset_title"] if is_reset else t["verify_title"]
    description = t["reset_text"] if is_reset else t["verify_text"]
    button = t["reset_button"] if is_reset else t["verify_button"]
    if is_reset:
        controls = f"<label>{t['password']}<input id=\"password\" type=\"password\" minlength=\"12\" maxlength=\"256\" autocomplete=\"new-password\" required></label><label>{t['confirm']}<input id=\"confirm\" type=\"password\" minlength=\"12\" maxlength=\"256\" autocomplete=\"new-password\" required></label>"
        script_action = f"const p1=document.getElementById('password').value;const p2=document.getElementById('confirm').value;if(p1!==p2){{show({json.dumps(t['mismatch'])});btn.disabled=false;return}}if(p1.length<12){{show({json.dumps(t['min'])});btn.disabled=false;return}}body={{token:T,new_password:p1}};path='/auth/password/reset';"
    else:
        controls = ""
        script_action = "body={token:T};path='/auth/verify-email';"
    success = t["success_reset"] if is_reset else t["success_verify"]
    html = f'''<!doctype html><html lang="{lang.lower()}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><meta name="referrer" content="no-referrer"><title>{title} – Kalkulačka E-liquidů</title><style>
*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(ellipse at top,#173d60 0,#071827 58%,#030b14 100%);font-family:Arial,sans-serif;color:#edf6ff}}main{{width:min(100%,480px);padding:30px;border:1px solid #087fbd;border-radius:18px;background:rgba(5,23,39,.96);box-shadow:0 0 28px #008bd633}}.brand{{font-size:22px;font-weight:700;margin-bottom:26px}}.brand span{{color:#13baf2}}h1{{font-size:24px;margin:0 0 12px}}p{{color:#bfd2e2;line-height:1.5}}label{{display:block;margin:16px 0 6px;color:#d9e9f7;font-weight:600}}input{{display:block;width:100%;margin-top:7px;padding:13px;border:1px solid #315779;border-radius:9px;background:#0b1c2e;color:white;font-size:16px}}button{{width:100%;margin-top:22px;padding:15px;border:0;border-radius:10px;background:linear-gradient(120deg,#078ad7,#1766c9);color:white;font-weight:700;font-size:15px;cursor:pointer}}button:disabled{{opacity:.65;cursor:wait}}#result{{margin-top:18px;line-height:1.5;color:#cde7f7}}.small{{font-size:12px;color:#7897b0;margin-top:24px}}</style></head><body><main><div class="brand">Kalkulačka <span>E-liquidů</span></div><h1>{title}</h1><p>{description}</p><form id="action">{controls}{('<button id="submit" type="submit">'+button+'</button>') if is_reset else ''}</form><div id="result" role="status" aria-live="polite">{t['working'] if not is_reset else ''}</div><div class="small">Kalkulačka E-liquidů</div></main><script>
const T=new URLSearchParams(window.location.hash.slice(1)).get('token')||'';const form=document.getElementById('action');const result=document.getElementById('result');const btn=document.getElementById('submit');function show(s){{result.textContent=s}}form.addEventListener('submit',async e=>{{e.preventDefault();if(!T){{show({json.dumps(t['expired'])});return}}if(btn)btn.disabled=true;show({json.dumps(t['working'])});let body,path;{script_action}try{{const r=await fetch(path,{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(body)}});const d=await r.json().catch(()=>({{}}));if(!r.ok)throw new Error(d.detail||{json.dumps(t['expired'])});form.remove();show({json.dumps(success)})}}catch(err){{show(err.message||{json.dumps(t['expired'])});if(btn)btn.disabled=false}}}});if(!{str(is_reset).lower()})form.requestSubmit();</script></body></html>'''
    response = HTMLResponse(html)
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    return response

def _issue_account_token(conn, user_id: int, purpose: str, ttl: int, pending_email: str | None = None) -> str:
    token = secrets.token_urlsafe(32)
    _store_account_token(conn, user_id, purpose, token, ttl, pending_email)
    return token


def _store_account_token(conn, user_id: int, purpose: str, token: str, ttl: int, pending_email: str | None = None) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM account_tokens WHERE user_id=%s AND purpose=%s",
            (user_id, purpose),
        )
        cur.execute(
            "INSERT INTO account_tokens(user_id,purpose,token_hash,expires_at,pending_email) "
            "VALUES(%s,%s,%s,now() + (%s * interval '1 second'),%s)",
            (user_id, purpose, _token_hash(token), ttl, pending_email),
        )


def _issue_password_reset_code(conn, user_id: int) -> str | None:
    # Numeric, eight-digit, single-use code. Only its SHA-256 hash is stored.
    # Retry on the extremely unlikely collision with another active code.
    with conn.cursor() as cur:
        cur.execute(
            "SELECT created_at FROM account_tokens WHERE user_id=%s AND purpose='password_reset' AND expires_at>now()",
            (user_id,),
        )
        existing = cur.fetchone()
        if existing:
            cur.execute("SELECT EXTRACT(EPOCH FROM (now() - %s))", (existing[0],))
            age = cur.fetchone()
            if age and float(age[0]) < RESET_RESEND_COOLDOWN_SECONDS:
                return None
        cur.execute(
            "DELETE FROM account_tokens WHERE user_id=%s AND purpose='password_reset'",
            (user_id,),
        )
        for _ in range(10):
            code = f"{secrets.randbelow(100_000_000):08d}"
            cur.execute(
                "INSERT INTO account_tokens(user_id,purpose,token_hash,expires_at,attempts) "
                "VALUES(%s,'password_reset',%s,now() + (%s * interval '1 second'),0) "
                "ON CONFLICT (token_hash) DO NOTHING RETURNING id",
                (user_id, _token_hash(code), RESET_TOKEN_TTL_SECONDS),
            )
            if cur.fetchone():
                return code
    raise HTTPException(status_code=503, detail="Nepodařilo se vytvořit obnovovací kód. Zkuste to později.")


def _consume_account_token(conn, token: str, purpose: str):
    if not token or len(token) > 256:
        raise HTTPException(status_code=400, detail="Kód je neplatný nebo vypršel.")
    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM account_tokens WHERE token_hash=%s AND purpose=%s AND expires_at>now() "
            "RETURNING user_id",
            (_token_hash(token), purpose),
        )
        row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=400, detail="Kód je neplatný nebo vypršel.")
    return int(row[0])


def current_user(authorization: Annotated[str | None, Header()] = None, conn=Depends(get_connection)) -> int:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Je vyžadováno přihlášení.")
    user_id, token_version = decode_token(authorization[7:].strip())
    with conn.cursor() as cur:
        cur.execute("SELECT auth_version FROM app_users WHERE id=%s", (user_id,))
        row = cur.fetchone()
    if not row or int(row[0]) != token_version:
        raise HTTPException(status_code=401, detail="Přihlášení bylo zneplatněno. Přihlaste se znovu.")
    return user_id


class RegisterInput(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=256)
    language: str = Field(default="CS", pattern="^(CS|EN|DE|FR|PL|ES)$")


class LoginInput(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class MaterialInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=160)
    kind: str = Field(min_length=1, max_length=40)
    stock: float = Field(default=0, ge=0, le=1_000_000_000)
    minimum: float = Field(default=0, ge=0, le=1_000_000_000)
    unit_price: float = Field(default=0, ge=0, le=1_000_000_000)
    strength: float = Field(default=0, ge=0, le=1_000_000)
    vg: float = Field(default=0, ge=0, le=100)


class MaterialUpdate(BaseModel):
    # Zásoba se mění výhradně přes endpoint skladových pohybů.
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    name: str | None = Field(default=None, min_length=1, max_length=160)
    kind: str | None = Field(default=None, min_length=1, max_length=40)
    minimum: float | None = Field(default=None, ge=0, le=1_000_000_000)
    unit_price: float | None = Field(default=None, ge=0, le=1_000_000_000)
    strength: float | None = Field(default=None, ge=0, le=1_000_000)
    vg: float | None = Field(default=None, ge=0, le=100)


@app.get("/health")
def health():
    return {"status": "ok", "service": "eliquid-online-api", "version": "2.6.0-dev"}


@app.get("/health/ready")
def readiness(conn=Depends(get_connection)):
    with conn.cursor() as cur:
        cur.execute("SELECT 1")
        cur.fetchone()
    return {"status": "ready", "database": "connected"}


@app.post("/auth/register", status_code=201)
def register(data: RegisterInput, conn=Depends(get_connection)):
    email = str(data.email).strip().lower()
    password_hash = hash_password(data.password)
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO app_users(email,password_hash,preferred_language,email_verified) "
                "VALUES(%s,%s,%s,FALSE) RETURNING id",
                (email, password_hash, data.language),
            )
            user_id = int(cur.fetchone()[0])
        token = _issue_account_token(conn, user_id, "verify_email", EMAIL_TOKEN_TTL_SECONDS)
        conn.commit()
    except psycopg.errors.UniqueViolation as exc:
        conn.rollback()
        raise HTTPException(status_code=409, detail="Účet s tímto e-mailem již existuje.") from exc
    try:
        _send_account_email(email, "verify", data.language, token)
    except HTTPException:
        # Účet zůstane neověřený; uživatel může později vyžádat nový kód.
        raise
    return {"message": "Účet byl vytvořen. Pro aktivaci ověřte e-mailovou adresu.", "email_verification_required": True}


@app.post("/auth/verify-email")
def verify_email(data: dict, conn=Depends(get_connection)):
    token = str(data.get("token", ""))
    if not token or len(token) > 256:
        raise HTTPException(status_code=400, detail="Kód je neplatný nebo vypršel.")
    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM account_tokens WHERE token_hash=%s AND purpose='verify_email' AND expires_at>now() RETURNING user_id",
            (_token_hash(token),),
        )
        row = cur.fetchone()
    if row:
        user_id = int(row[0])
        with conn.cursor() as cur:
            cur.execute("UPDATE app_users SET email_verified=TRUE WHERE id=%s RETURNING id", (user_id,))
            updated = cur.fetchone()
        conn.commit()
        if not updated:
            raise HTTPException(status_code=400, detail="Účet již neexistuje.")
        return {"verified": True, "message": "E-mailová adresa byla ověřena. Nyní se můžete přihlásit."}

    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM account_tokens WHERE token_hash=%s AND purpose='email_change' AND expires_at>now() RETURNING user_id,pending_email",
            (_token_hash(token),),
        )
        change = cur.fetchone()
    if not change or not change[1]:
        conn.rollback()
        raise HTTPException(status_code=400, detail="Kód je neplatný nebo vypršel.")
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE app_users SET email=%s,email_verified=TRUE,auth_version=auth_version+1 WHERE id=%s RETURNING id", (str(change[1]).lower(), int(change[0])))
            updated = cur.fetchone()
        conn.commit()
    except psycopg.errors.UniqueViolation as exc:
        conn.rollback()
        raise HTTPException(status_code=409, detail="Tato e-mailová adresa je již používána jiným účtem.") from exc
    if not updated:
        raise HTTPException(status_code=400, detail="Účet již neexistuje.")
    return {"verified": True, "email_changed": True, "message": "Nová e-mailová adresa byla ověřena. Přihlaste se znovu."}


@app.post("/auth/verification/resend")
def resend_verification(data: dict, conn=Depends(get_connection)):
    email = str(data.get("email", "")).strip().lower()
    with conn.cursor() as cur:
        cur.execute("SELECT id,email_verified,preferred_language FROM app_users WHERE email=%s", (email,))
        row = cur.fetchone()
    # Stejná odpověď pro existující i neexistující adresy omezuje enumeraci účtů.
    if row and not row[1]:
        token = _issue_account_token(conn, int(row[0]), "verify_email", EMAIL_TOKEN_TTL_SECONDS)
        conn.commit()
        _send_account_email(email, "resend", row[2], token)
    return {"message": "Pokud účet vyžaduje ověření, byl odeslán nový kód."}


@app.post("/auth/password/forgot")
def forgot_password(data: dict, conn=Depends(get_connection)):
    email = str(data.get("email", "")).strip().lower()
    with conn.cursor() as cur:
        cur.execute("SELECT id,preferred_language FROM app_users WHERE email=%s AND email_verified=TRUE", (email,))
        row = cur.fetchone()
    if row:
        code = _issue_password_reset_code(conn, int(row[0]))
        conn.commit()
        if code:
            _send_account_email(email, "reset", row[1], code)
    return {"message": "Pokud účet existuje a je ověřený, byl odeslán jednorázový kód pro obnovu hesla."}


class PasswordResetInput(BaseModel):
    # `token` remains for compatibility with reset links already sent before
    # the in-app numeric-code flow was enabled.
    token: str | None = Field(default=None, min_length=20, max_length=256)
    email: EmailStr | None = None
    code: str | None = Field(default=None, pattern=r"^\d{8}$")
    new_password: str = Field(min_length=12, max_length=256)


@app.post("/auth/password/reset")
def reset_password(data: PasswordResetInput, conn=Depends(get_connection)):
    if data.token:
        user_id = _consume_account_token(conn, data.token, "password_reset")
    elif data.email and data.code:
        invalid_code = False
        with conn.cursor() as cur:
            cur.execute(
                "SELECT t.id,t.user_id,t.token_hash,t.attempts FROM account_tokens t "
                "JOIN app_users u ON u.id=t.user_id "
                "WHERE u.email=%s AND t.purpose='password_reset' AND t.expires_at>now() "
                "FOR UPDATE OF t",
                (str(data.email).strip().lower(),),
            )
            token_row = cur.fetchone()
            if not token_row or int(token_row[3]) >= RESET_CODE_MAX_ATTEMPTS:
                invalid_code = True
            elif not hmac.compare_digest(str(token_row[2]), _token_hash(data.code)):
                cur.execute("UPDATE account_tokens SET attempts=attempts+1 WHERE id=%s", (int(token_row[0]),))
                if int(token_row[3]) + 1 >= RESET_CODE_MAX_ATTEMPTS:
                    cur.execute("DELETE FROM account_tokens WHERE id=%s", (int(token_row[0]),))
                conn.commit()
                invalid_code = True
            else:
                cur.execute("DELETE FROM account_tokens WHERE id=%s RETURNING user_id", (int(token_row[0]),))
                token_row = cur.fetchone()
                user_id = int(token_row[0]) if token_row else 0
        if invalid_code or not user_id:
            raise HTTPException(status_code=400, detail="Obnovovací kód je nesprávný nebo jeho platnost vypršela.")
    else:
        raise HTTPException(status_code=400, detail="Zadejte platný obnovovací odkaz nebo e-mail a osmimístný kód.")
    new_hash = hash_password(data.new_password)
    with conn.cursor() as cur:
        cur.execute("UPDATE app_users SET password_hash=%s,auth_version=auth_version+1 WHERE id=%s RETURNING id", (new_hash, user_id))
        row = cur.fetchone()
        # Zneplatnit všechny dřívější resetovací i ověřovací kódy uživatele.
        cur.execute("DELETE FROM account_tokens WHERE user_id=%s", (user_id,))
    conn.commit()
    if not row:
        raise HTTPException(status_code=400, detail="Účet již neexistuje.")
    return {"password_changed": True, "message": "Heslo bylo změněno. Přihlaste se novým heslem."}


@app.get("/account/verify", response_class=HTMLResponse)
def account_verify_page(lang: str = "CS"):
    return _account_action_page("verify", lang)


@app.get("/account/reset", response_class=HTMLResponse)
def account_reset_page(lang: str = "CS"):
    return _account_action_page("reset", lang)


class PasswordChangeInput(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


@app.post("/auth/password/change")
def change_password(data: PasswordChangeInput, user_id: Annotated[int, Depends(current_user)], conn=Depends(get_connection)):
    with conn.cursor() as cur:
        cur.execute("SELECT password_hash FROM app_users WHERE id=%s", (user_id,))
        row = cur.fetchone()
    if not row or not verify_password(data.current_password, row[0]):
        raise HTTPException(status_code=400, detail="Současné heslo není správné.")
    with conn.cursor() as cur:
        cur.execute("UPDATE app_users SET password_hash=%s,auth_version=auth_version+1 WHERE id=%s", (hash_password(data.new_password), user_id))
        cur.execute("DELETE FROM account_tokens WHERE user_id=%s", (user_id,))
    conn.commit()
    return {"password_changed": True, "message": "Heslo bylo změněno. Přihlaste se znovu."}


class EmailChangeInput(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_email: EmailStr


@app.post("/auth/email/change")
def request_email_change(data: EmailChangeInput, user_id: Annotated[int, Depends(current_user)], conn=Depends(get_connection)):
    new_email = str(data.new_email).strip().lower()
    with conn.cursor() as cur:
        cur.execute("SELECT email,password_hash,preferred_language FROM app_users WHERE id=%s", (user_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Účet již neexistuje.")
        if not verify_password(data.current_password, row[1]):
            raise HTTPException(status_code=400, detail="Současné heslo není správné.")
        if new_email == str(row[0]).lower():
            raise HTTPException(status_code=400, detail="Nová e-mailová adresa je stejná jako současná.")
        cur.execute("SELECT 1 FROM app_users WHERE email=%s AND id<>%s", (new_email, user_id))
        if cur.fetchone():
            raise HTTPException(status_code=409, detail="Tato e-mailová adresa je již používána jiným účtem.")
    token = _issue_account_token(conn, user_id, "email_change", EMAIL_TOKEN_TTL_SECONDS, pending_email=new_email)
    conn.commit()
    _send_account_email(new_email, "verify", row[2], token)
    return {"email_change_pending": True, "message": "Na novou adresu jsme odeslali ověřovací e-mail. Změna se dokončí po ověření odkazu."}


@app.post("/auth/login")
def login(data: LoginInput, conn=Depends(get_connection)):
    with conn.cursor() as cur:
        cur.execute("SELECT id,password_hash,email_verified,auth_version FROM app_users WHERE email=%s", (str(data.email).strip().lower(),))
        row = cur.fetchone()
    if not row or not verify_password(data.password, row[1]):
        raise HTTPException(status_code=401, detail="Nesprávný e-mail nebo heslo.")
    if not row[2]:
        raise HTTPException(status_code=403, detail="Nejprve ověřte e-mailovou adresu.")
    return {"access_token": create_token(row[0], row[3]), "token_type": "bearer", "user_id": row[0]}


@app.get("/auth/me")
def me(user_id: Annotated[int, Depends(current_user)], conn=Depends(get_connection)):
    with conn.cursor() as cur:
        cur.execute("SELECT email,preferred_language,created_at FROM app_users WHERE id=%s", (user_id,))
        row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Účet již neexistuje.")
    return {"user_id": user_id, "email": row[0], "language": row[1], "created_at": row[2]}


@app.get("/data/materials/count")
def materials_count(user_id: Annotated[int, Depends(current_user)], conn=Depends(get_connection)):
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM materials WHERE owner_id=%s", (user_id,))
        count = cur.fetchone()[0]
    return {"count": count}


@app.get("/data/materials")
def list_materials(user_id: Annotated[int, Depends(current_user)], conn=Depends(get_connection)):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id,name,kind,stock,minimum,unit_price,strength,vg,updated_at "
            "FROM materials WHERE owner_id=%s ORDER BY name,id", (user_id,)
        )
        rows = cur.fetchall()
    return [{"id": r[0], "name": r[1], "kind": r[2], "stock": r[3],
             "minimum": r[4], "unit_price": r[5], "strength": r[6],
             "vg": r[7], "updated_at": r[8]} for r in rows]


@app.post("/data/materials", status_code=201)
def create_material(data: MaterialInput, user_id: Annotated[int, Depends(current_user)], conn=Depends(get_connection)):
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO materials(owner_id,name,kind,stock,minimum,unit_price,strength,vg) "
                "VALUES(%s,%s,%s,%s,%s,%s,%s,%s) "
                "RETURNING id,name,kind,stock,minimum,unit_price,strength,vg,updated_at",
                (user_id, data.name, data.kind, data.stock, data.minimum,
                 data.unit_price, data.strength, data.vg),
            )
            r = cur.fetchone()
            if data.stock > 0:
                cur.execute(
                    "INSERT INTO stock_movements(owner_id,material_id,movement_type,quantity,stock_after,note) "
                    "VALUES(%s,%s,'IN',%s,%s,%s)",
                    (user_id, r[0], data.stock, data.stock, "Počáteční stav při založení položky"),
                )
        conn.commit()
    except psycopg.errors.UniqueViolation as exc:
        conn.rollback()
        raise HTTPException(status_code=409, detail="Položka s tímto názvem již existuje.") from exc
    return {"id": r[0], "name": r[1], "kind": r[2], "stock": r[3],
            "minimum": r[4], "unit_price": r[5], "strength": r[6],
            "vg": r[7], "updated_at": r[8]}


@app.patch("/data/materials/{material_id}")
def update_material(material_id: int, data: MaterialUpdate,
                    user_id: Annotated[int, Depends(current_user)], conn=Depends(get_connection)):
    changes = data.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=400, detail="Nebyla zadána žádná změna.")
    columns = {"name", "kind", "stock", "minimum", "unit_price", "strength", "vg"}
    if not set(changes).issubset(columns):
        raise HTTPException(status_code=400, detail="Neplatná změna.")
    assignments = ",".join(f"{key}=%s" for key in changes)
    values = list(changes.values()) + [material_id, user_id]
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"UPDATE materials SET {assignments},updated_at=now() "
                "WHERE id=%s AND owner_id=%s "
                "RETURNING id,name,kind,stock,minimum,unit_price,strength,vg,updated_at",
                values,
            )
            r = cur.fetchone()
        conn.commit()
    except psycopg.errors.UniqueViolation as exc:
        conn.rollback()
        raise HTTPException(status_code=409, detail="Položka s tímto názvem již existuje.") from exc
    if not r:
        raise HTTPException(status_code=404, detail="Položka nebyla nalezena.")
    return {"id": r[0], "name": r[1], "kind": r[2], "stock": r[3],
            "minimum": r[4], "unit_price": r[5], "strength": r[6],
            "vg": r[7], "updated_at": r[8]}


@app.delete("/data/materials/{material_id}", status_code=204)
def delete_material(material_id: int, user_id: Annotated[int, Depends(current_user)], conn=Depends(get_connection)):
    with conn.cursor() as cur:
        cur.execute("DELETE FROM materials WHERE id=%s AND owner_id=%s RETURNING id", (material_id, user_id))
        deleted = cur.fetchone()
    conn.commit()
    if not deleted:
        raise HTTPException(status_code=404, detail="Položka nebyla nalezena.")
    return None


class RecipeInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=160)
    payload: dict = Field(default_factory=dict)


class PreferenceInput(BaseModel):
    value: str = Field(max_length=4000)


class LanguageInput(BaseModel):
    language: str = Field(pattern="^(CS|EN|DE|FR|PL|ES)$")


@app.get("/data/recipes")
def list_recipes(user_id: Annotated[int, Depends(current_user)], conn=Depends(get_connection)):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id,name,payload,created_at FROM recipes WHERE owner_id=%s ORDER BY name,id",
            (user_id,),
        )
        rows = cur.fetchall()
    return [{"id": r[0], "name": r[1], "payload": r[2], "created_at": r[3]} for r in rows]


@app.post("/data/recipes", status_code=201)
def create_recipe(data: RecipeInput, user_id: Annotated[int, Depends(current_user)], conn=Depends(get_connection)):
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO recipes(owner_id,name,payload) VALUES(%s,%s,%s) "
            "RETURNING id,name,payload,created_at",
            (user_id, data.name, json.dumps(data.payload)),
        )
        row = cur.fetchone()
    conn.commit()
    return {"id": row[0], "name": row[1], "payload": row[2], "created_at": row[3]}


@app.put("/data/recipes/{recipe_id}")
def update_recipe(recipe_id: int, data: RecipeInput,
                  user_id: Annotated[int, Depends(current_user)], conn=Depends(get_connection)):
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE recipes SET name=%s,payload=%s WHERE id=%s AND owner_id=%s "
            "RETURNING id,name,payload,created_at",
            (data.name, json.dumps(data.payload), recipe_id, user_id),
        )
        row = cur.fetchone()
    conn.commit()
    if not row:
        raise HTTPException(status_code=404, detail="Receptura nebyla nalezena.")
    return {"id": row[0], "name": row[1], "payload": row[2], "created_at": row[3]}


@app.delete("/data/recipes/{recipe_id}", status_code=204)
def delete_recipe(recipe_id: int, user_id: Annotated[int, Depends(current_user)], conn=Depends(get_connection)):
    with conn.cursor() as cur:
        cur.execute("DELETE FROM recipes WHERE id=%s AND owner_id=%s RETURNING id", (recipe_id, user_id))
        deleted = cur.fetchone()
    conn.commit()
    if not deleted:
        raise HTTPException(status_code=404, detail="Receptura nebyla nalezena.")
    return None


@app.get("/settings/preferences")
def list_preferences(user_id: Annotated[int, Depends(current_user)], conn=Depends(get_connection)):
    with conn.cursor() as cur:
        cur.execute("SELECT key,value FROM user_preferences WHERE owner_id=%s ORDER BY key", (user_id,))
        rows = cur.fetchall()
    return {key: value for key, value in rows}


@app.put("/settings/preferences/{key}")
def set_preference(key: str, data: PreferenceInput,
                   user_id: Annotated[int, Depends(current_user)], conn=Depends(get_connection)):
    if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_.-]{0,79}", key):
        raise HTTPException(status_code=400, detail="Neplatný klíč nastavení.")
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO user_preferences(owner_id,key,value) VALUES(%s,%s,%s) "
            "ON CONFLICT(owner_id,key) DO UPDATE SET value=EXCLUDED.value RETURNING key,value",
            (user_id, key, data.value),
        )
        row = cur.fetchone()
    conn.commit()
    return {"key": row[0], "value": row[1]}


@app.put("/settings/language")
def set_language(data: LanguageInput, user_id: Annotated[int, Depends(current_user)], conn=Depends(get_connection)):
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE app_users SET preferred_language=%s WHERE id=%s RETURNING preferred_language",
            (data.language, user_id),
        )
        row = cur.fetchone()
    conn.commit()
    if not row:
        raise HTTPException(status_code=404, detail="Účet nebyl nalezen.")
    return {"language": row[0]}


class StockMovementInput(BaseModel):
    movement_type: str = Field(pattern="^(IN|OUT|ADJUSTMENT)$")
    quantity: float = Field(gt=0, le=1_000_000_000)
    note: str = Field(default="", max_length=500)


@app.post("/data/materials/{material_id}/movements", status_code=201)
def create_stock_movement(
    material_id: int,
    data: StockMovementInput,
    user_id: Annotated[int, Depends(current_user)],
    conn=Depends(get_connection),
):
    """Apply a stock movement atomically and write an immutable audit record."""
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT stock FROM materials WHERE id=%s AND owner_id=%s FOR UPDATE",
                (material_id, user_id),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Položka nebyla nalezena.")
            current_stock = float(row[0])
            if data.movement_type == "IN":
                new_stock = current_stock + data.quantity
            elif data.movement_type == "OUT":
                new_stock = current_stock - data.quantity
            else:
                # ADJUSTMENT quantity is the absolute target stock level.
                new_stock = data.quantity
            if new_stock < 0:
                raise HTTPException(status_code=409, detail="Nedostatek skladu.")
            applied_quantity = abs(new_stock - current_stock)
            if applied_quantity == 0:
                raise HTTPException(status_code=400, detail="Pohyb by nezměnil stav skladu.")
            cur.execute(
                "UPDATE materials SET stock=%s,updated_at=now() WHERE id=%s AND owner_id=%s",
                (new_stock, material_id, user_id),
            )
            cur.execute(
                "INSERT INTO stock_movements(owner_id,material_id,movement_type,quantity,stock_after,note) "
                "VALUES(%s,%s,%s,%s,%s,%s) RETURNING id,created_at",
                (user_id, material_id, data.movement_type, applied_quantity, new_stock, data.note),
            )
            movement_id, created_at = cur.fetchone()
        conn.commit()
    except HTTPException:
        conn.rollback()
        raise
    except Exception:
        conn.rollback()
        raise
    return {
        "id": movement_id, "material_id": material_id,
        "movement_type": data.movement_type, "quantity": applied_quantity,
        "stock_after": new_stock, "note": data.note, "created_at": created_at,
    }


@app.get("/data/materials/{material_id}/movements")
def list_stock_movements(
    material_id: int,
    user_id: Annotated[int, Depends(current_user)],
    conn=Depends(get_connection),
    limit: int = 100,
):
    limit = max(1, min(limit, 500))
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id,movement_type,quantity,stock_after,note,created_at "
            "FROM stock_movements WHERE owner_id=%s AND material_id=%s "
            "ORDER BY created_at DESC,id DESC LIMIT %s",
            (user_id, material_id, limit),
        )
        rows = cur.fetchall()
    return [
        {"id": r[0], "movement_type": r[1], "quantity": r[2],
         "stock_after": r[3], "note": r[4], "created_at": r[5]}
        for r in rows
    ]


class BatchMaterialUse(BaseModel):
    material_id: int = Field(gt=0)
    quantity: float = Field(gt=0, le=1_000_000_000)


class BatchInput(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    payload: dict = Field(default_factory=dict)
    materials: list[BatchMaterialUse] = Field(min_length=1, max_length=200)


@app.get("/data/batches")
def list_batches(user_id: Annotated[int, Depends(current_user)], conn=Depends(get_connection), limit: int = 100):
    limit = max(1, min(limit, 500))
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id,name,payload,cost,created_at FROM batches "
            "WHERE owner_id=%s ORDER BY created_at DESC,id DESC LIMIT %s",
            (user_id, limit),
        )
        rows = cur.fetchall()
    return [{"id": r[0], "name": r[1], "payload": r[2], "cost": r[3], "created_at": r[4]} for r in rows]


@app.get("/data/batches/{batch_id}")
def get_batch(batch_id: int, user_id: Annotated[int, Depends(current_user)], conn=Depends(get_connection)):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id,name,payload,cost,created_at FROM batches WHERE id=%s AND owner_id=%s",
            (batch_id, user_id),
        )
        row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Várka nebyla nalezena.")
    return {"id": row[0], "name": row[1], "payload": row[2], "cost": row[3], "created_at": row[4]}


@app.post("/data/batches", status_code=201)
def create_batch(data: BatchInput, user_id: Annotated[int, Depends(current_user)], conn=Depends(get_connection)):
    """Consume all materials and save batch plus audit movements atomically."""
    material_ids = [item.material_id for item in data.materials]
    if len(set(material_ids)) != len(material_ids):
        raise HTTPException(status_code=400, detail="Stejná skladová položka je ve várce uvedena vícekrát.")
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id,stock,unit_price FROM materials WHERE owner_id=%s AND id=ANY(%s) ORDER BY id FOR UPDATE",
                (user_id, material_ids),
            )
            material_rows = {int(mid): (float(stock), float(unit_price)) for mid, stock, unit_price in cur.fetchall()}
            stocks = {mid: values[0] for mid, values in material_rows.items()}
            if len(stocks) != len(material_ids):
                raise HTTPException(status_code=404, detail="Některá skladová položka nebyla nalezena.")
            for item in data.materials:
                if stocks[item.material_id] + 1e-9 < item.quantity:
                    raise HTTPException(status_code=409, detail=f"Nedostatek skladu u položky ID {item.material_id}.")
            snapshots = [
                {"material_id": item.material_id, "quantity": item.quantity,
                 "unit_price": material_rows[item.material_id][1]}
                for item in data.materials
            ]
            calculated_cost = sum(x["quantity"] * x["unit_price"] for x in snapshots)
            cur.execute(
                "INSERT INTO batches(owner_id,name,payload,cost) VALUES(%s,%s,%s,%s) "
                "RETURNING id,created_at",
                (user_id, data.name, json.dumps({**data.payload, "materials": snapshots}), calculated_cost),
            )
            batch_id, created_at = cur.fetchone()
            for item in data.materials:
                after = stocks[item.material_id] - item.quantity
                cur.execute(
                    "UPDATE materials SET stock=%s,updated_at=now() WHERE id=%s AND owner_id=%s",
                    (after, item.material_id, user_id),
                )
                cur.execute(
                    "INSERT INTO stock_movements(owner_id,material_id,movement_type,quantity,stock_after,note) "
                    "VALUES(%s,%s,'OUT',%s,%s,%s)",
                    (user_id, item.material_id, item.quantity, after, f"Várka #{batch_id}: {data.name}"),
                )
        conn.commit()
    except HTTPException:
        conn.rollback()
        raise
    except Exception:
        conn.rollback()
        raise
    return {"id": batch_id, "name": data.name, "cost": calculated_cost, "created_at": created_at}


# Online zálohy: pouze data vlastníka; hesla, tokeny ani identifikátory účtu se neexportují.
BACKUP_TABLES = {
    "materials": ["id", "name", "kind", "stock", "minimum", "unit_price", "strength", "vg", "updated_at"],
    "recipes": ["id", "name", "payload", "created_at"],
    "batches": ["id", "name", "payload", "cost", "created_at"],
    "stock_movements": ["id", "material_id", "movement_type", "quantity", "stock_after", "note", "created_at"],
    "user_preferences": ["key", "value"],
}


@app.get("/account/backup")
def export_account_backup(user_id: Annotated[int, Depends(current_user)], conn=Depends(get_connection)):
    tables = {}
    with conn.cursor() as cur:
        for table, columns in BACKUP_TABLES.items():
            projection = ",".join(columns)
            cur.execute(f"SELECT {projection} FROM {table} WHERE owner_id=%s ORDER BY 1", (user_id,))
            rows = cur.fetchall()
            tables[table] = [dict(zip(columns, row)) for row in rows]
    payload = jsonable_encoder({
        "format": "eliquid-account-backup", "format_version": 1,
        "created_at": datetime.now(timezone.utc), "tables": tables,
    })
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    payload["sha256"] = hashlib.sha256(canonical).hexdigest()
    return payload


class AccountBackupInput(BaseModel):
    backup: dict


@app.post("/account/backup/restore")
def restore_account_backup(data: AccountBackupInput, user_id: Annotated[int, Depends(current_user)], conn=Depends(get_connection)):
    backup = data.backup
    if backup.get("format") != "eliquid-account-backup" or backup.get("format_version") != 1:
        raise HTTPException(status_code=400, detail="Nepodporovaný formát online zálohy.")
    supplied_hash = backup.get("sha256")
    unsigned = {k: v for k, v in backup.items() if k != "sha256"}
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    expected_hash = hashlib.sha256(canonical).hexdigest()
    if not isinstance(supplied_hash, str) or not hmac.compare_digest(supplied_hash, expected_hash):
        raise HTTPException(status_code=400, detail="Kontrolní součet zálohy nesouhlasí. Obnova byla zastavena.")
    raw = json.dumps(backup, default=str).encode("utf-8")
    if len(raw) > 20 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Záloha je příliš velká (maximum 20 MB).")
    tables = backup.get("tables")
    if not isinstance(tables, dict) or set(tables) != set(BACKUP_TABLES):
        raise HTTPException(status_code=400, detail="Záloha neobsahuje očekávané datové tabulky.")
    for table, columns in BACKUP_TABLES.items():
        rows = tables.get(table)
        if not isinstance(rows, list) or len(rows) > 100000:
            raise HTTPException(status_code=400, detail=f"Neplatná data tabulky {table}.")
        for row in rows:
            if not isinstance(row, dict) or set(row) != set(columns):
                raise HTTPException(status_code=400, detail=f"Neplatná struktura záznamu v tabulce {table}.")
    owned_material_ids = {row.get("id") for row in tables["materials"]}
    if len(owned_material_ids) != len(tables["materials"]):
        raise HTTPException(status_code=400, detail="Záloha obsahuje duplicitní ID skladových položek.")
    if any(row.get("material_id") not in owned_material_ids for row in tables["stock_movements"]):
        raise HTTPException(status_code=400, detail="Záloha obsahuje skladový pohyb bez odpovídající vlastní položky.")
    try:
        with conn.cursor() as cur:
            # Nejprve odstranění v pořadí respektujícím cizí klíče.
            for table in ("stock_movements", "batches", "recipes", "materials", "user_preferences"):
                cur.execute(f"DELETE FROM {table} WHERE owner_id=%s", (user_id,))
            # Vkládání v pořadí rodič -> potomek. owner_id nikdy nepřebíráme ze souboru.
            for table in ("materials", "recipes", "batches", "stock_movements", "user_preferences"):
                columns = BACKUP_TABLES[table]
                insert_columns = ["owner_id", *columns]
                placeholders = ",".join(["%s"] * len(insert_columns))
                sql = f"INSERT INTO {table} ({','.join(insert_columns)}) VALUES ({placeholders})"
                for row in tables[table]:
                    cur.execute(sql, [user_id, *[row[col] for col in columns]])
            for table in ("materials", "recipes", "batches", "stock_movements"):
                cur.execute(
                    "SELECT setval(pg_get_serial_sequence(%s,'id'), COALESCE((SELECT MAX(id) FROM " + table + "),1), "
                    "EXISTS(SELECT 1 FROM " + table + "))", (table,)
                )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return {"restored": True, "message": "Online záloha byla obnovena."}


@app.get("/account/backup/verify")
def verify_account_backup(user_id: Annotated[int, Depends(current_user)], conn=Depends(get_connection)):
    """Verify the actual device-sync snapshot; legacy account tables are not the sync source."""
    with conn.cursor() as cur:
        cur.execute("SELECT payload,checksum,revision,updated_at FROM sync_documents WHERE owner_id=%s", (user_id,))
        row = cur.fetchone()
    if not row:
        return {"restorable": False, "message": "ONLINE účet zatím neobsahuje synchronizační snímek.", "counts": {}, "checked_at": datetime.now(timezone.utc).isoformat()}
    payload, stored_checksum, revision, updated_at = row
    try:
        computed_checksum, verified = _validate_sync_snapshot(payload)
        if not hmac.compare_digest(str(stored_checksum or ""), computed_checksum):
            raise HTTPException(status_code=400, detail="Kontrolní součet uložené ONLINE zálohy nesouhlasí.")
    except HTTPException as exc:
        return {"restorable": False, "message": exc.detail, "counts": {}, "revision": int(revision), "checked_at": datetime.now(timezone.utc).isoformat()}
    counts = {table: len(rows) for table, rows in verified["tables"].items()}
    return {"restorable": True, "message": "ONLINE synchronizační snímek prošel kontrolou integrity a lze jej obnovit.", "counts": counts, "revision": int(revision), "updated_at": updated_at, "checked_at": datetime.now(timezone.utc).isoformat()}


@app.get("/sync/history")
def get_sync_history(user_id: Annotated[int, Depends(current_user)], conn=Depends(get_connection)):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT revision,checksum,created_at FROM sync_document_history "
            "WHERE owner_id=%s ORDER BY revision DESC LIMIT 20", (user_id,)
        )
        rows = cur.fetchall()
    return [{"revision": int(r[0]), "checksum": r[1], "created_at": r[2]} for r in rows]


@app.get("/data/statistics")
def get_statistics(
    user_id: Annotated[int, Depends(current_user)],
    conn=Depends(get_connection),
    date_from: str | None = None,
    date_to: str | None = None,
):
    """Return owner-scoped production and cost totals with daily aggregates.

    Dates are inclusive ISO YYYY-MM-DD values. The query uses timestamptz
    boundaries and never reads another user's batches.
    """
    from datetime import date, datetime, time, timedelta, timezone

    try:
        start = date.fromisoformat(date_from) if date_from else None
        end = date.fromisoformat(date_to) if date_to else None
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Datum musí být ve formátu YYYY-MM-DD.") from exc
    if start and end and start > end:
        raise HTTPException(status_code=400, detail="Počáteční datum nesmí být po koncovém datu.")

    start_at = datetime.combine(start, time.min, tzinfo=timezone.utc) if start else None
    end_at = datetime.combine(end + timedelta(days=1), time.min, tzinfo=timezone.utc) if end else None
    clauses = ["owner_id=%s"]
    params: list = [user_id]
    if start_at:
        clauses.append("created_at >= %s")
        params.append(start_at)
    if end_at:
        clauses.append("created_at < %s")
        params.append(end_at)
    where = " AND ".join(clauses)

    with conn.cursor() as cur:
        cur.execute(
            f"SELECT count(*),COALESCE(sum((payload->>'final_ml')::double precision),0), "
            f"COALESCE(sum(cost),0) FROM batches WHERE {where}", params,
        )
        total_count, total_ml, total_cost = cur.fetchone()
        cur.execute(
            f"SELECT created_at::date,count(*), "
            f"COALESCE(sum((payload->>'final_ml')::double precision),0),COALESCE(sum(cost),0) "
            f"FROM batches WHERE {where} GROUP BY created_at::date ORDER BY created_at::date", params,
        )
        rows = cur.fetchall()
    return {
        "batch_count": int(total_count),
        "final_ml": float(total_ml),
        "cost": float(total_cost),
        "daily": [
            {"date": day.isoformat(), "batch_count": int(count),
             "final_ml": float(volume), "cost": float(cost)}
            for day, count, volume, cost in rows
        ],
    }


# Synchronizace úplného lokálního SQLite snímku mezi zařízeními.
# Optimistické zamykání revision zabraňuje tichému přepsání souběžných změn.
class SyncPushInput(BaseModel):
    base_revision: int = Field(ge=0)
    snapshot: dict

SYNC_TABLES = {"materials", "purchases", "movements", "recipes", "batches", "batch_items", "settings"}
SYNC_COLUMNS = {
    "materials": {"id", "name", "kind", "stock", "minimum", "unit_price", "strength", "vg", "updated", "note", "buy_again", "aging_days"},
    "purchases": {"id", "material_id", "date", "qty", "price", "unit_price", "note"},
    "movements": {"id", "material_id", "date", "kind", "delta", "balance", "note", "hidden"},
    "recipes": {"id", "signature", "name", "aroma_id", "booster_id", "base_vg", "aroma_pct", "target_nic", "target_vg", "rating", "note", "created"},
    "batches": {"id", "recipe_id", "name", "date", "base_ml", "booster_ml", "aroma_ml", "add_vg", "add_pg", "final_ml", "nic", "vg", "cost", "hidden", "aging_days", "aroma_name", "aging_due_date"},
    "batch_items": {"id", "batch_id", "material_id", "qty", "unit_price", "cost"},
    "settings": {"key", "value"},
}
SYNC_FORMAT = "eliquid-device-sync"
SYNC_FORMAT_VERSION = 2

def _sync_hash_normalize(value):
    from decimal import Decimal, InvalidOperation
    import math
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, int):
        return {"$eliquid_number": str(value)}
    if isinstance(value, float):
        if not math.isfinite(value):
            raise HTTPException(status_code=400, detail="Synchronizační data obsahují neplatné číslo.")
        try:
            number = Decimal(str(value))
            text = "0" if number == 0 else format(number.normalize(), "f")
        except (InvalidOperation, ValueError):
            raise HTTPException(status_code=400, detail="Synchronizační data obsahují neplatné číslo.")
        return {"$eliquid_number": text}
    if isinstance(value, list):
        return [_sync_hash_normalize(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _sync_hash_normalize(item) for key, item in value.items()}
    return value

def _sync_hash_json(value):
    return json.dumps(_sync_hash_normalize(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")

def _validate_sync_snapshot(snapshot: dict) -> tuple[str, dict]:
    if not isinstance(snapshot, dict) or snapshot.get("format") != SYNC_FORMAT or snapshot.get("format_version") != SYNC_FORMAT_VERSION:
        raise HTTPException(status_code=400, detail="Nepodporovaný formát synchronizačních dat.")
    tables = snapshot.get("tables")
    if not isinstance(tables, dict) or set(tables) != SYNC_TABLES:
        raise HTTPException(status_code=400, detail="Synchronizační data neobsahují očekávané tabulky.")
    raw = json.dumps(snapshot, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8")
    if len(raw) > 20 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Synchronizační data překračují limit 20 MB.")
    supplied = snapshot.get("sha256")
    expected_content = hashlib.sha256(_sync_hash_json(tables)).hexdigest()
    if not isinstance(snapshot.get("content_sha256"), str) or not hmac.compare_digest(snapshot["content_sha256"], expected_content):
        raise HTTPException(status_code=400, detail="Kontrolní součet obsahu synchronizačních dat nesouhlasí.")
    unsigned = {k: v for k, v in snapshot.items() if k != "sha256"}
    expected = hashlib.sha256(_sync_hash_json(unsigned)).hexdigest()
    if not isinstance(supplied, str) or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=400, detail="Kontrolní součet synchronizačních dat nesouhlasí.")
    for table, rows in tables.items():
        if not isinstance(rows, list) or len(rows) > 100000 or any(not isinstance(row, dict) for row in rows):
            raise HTTPException(status_code=400, detail=f"Neplatná data tabulky {table}.")
        if any(set(row) != SYNC_COLUMNS[table] for row in rows):
            raise HTTPException(status_code=400, detail=f"Struktura záznamu v tabulce {table} neodpovídá podporované verzi.")
    for table in ("materials", "purchases", "movements", "recipes", "batches", "batch_items"):
        ids = [r.get("id") for r in tables[table]]
        if any(not isinstance(value, int) or isinstance(value, bool) or value <= 0 for value in ids):
            raise HTTPException(status_code=400, detail=f"Synchronizace obsahuje neplatné ID v tabulce {table}.")
        if len(ids) != len(set(ids)):
            raise HTTPException(status_code=400, detail=f"Synchronizace obsahuje duplicitní ID v tabulce {table}.")
    material_ids = {r.get("id") for r in tables["materials"]}
    recipe_ids = {r.get("id") for r in tables["recipes"]}
    batch_ids = {r.get("id") for r in tables["batches"]}
    if any(r.get("material_id") not in material_ids for t in ("purchases", "movements", "batch_items") for r in tables[t]):
        raise HTTPException(status_code=400, detail="Synchronizace obsahuje vazbu na neexistující skladovou položku.")
    if any(r.get("batch_id") not in batch_ids for r in tables["batch_items"]):
        raise HTTPException(status_code=400, detail="Synchronizace obsahuje položku neexistující várky.")
    if any(r.get("recipe_id") is not None and r.get("recipe_id") not in recipe_ids for r in tables["batches"]):
        raise HTTPException(status_code=400, detail="Synchronizace obsahuje várku s neexistující recepturou.")
    if any(r.get(key) not in material_ids for r in tables["recipes"] for key in ("aroma_id", "booster_id")):
        raise HTTPException(status_code=400, detail="Synchronizace obsahuje recepturu s neexistující surovinou.")
    setting_keys = [r.get("key") for r in tables["settings"]]
    if any(not isinstance(key, str) or not key for key in setting_keys) or len(setting_keys) != len(set(setting_keys)):
        raise HTTPException(status_code=400, detail="Synchronizace obsahuje neplatné nebo duplicitní nastavení.")
    return expected, snapshot

@app.websocket("/sync/ws")
async def sync_websocket(websocket: WebSocket):
    """Authenticated revision notifications; the bearer token is sent inside WSS, never in the URL."""
    sync_socket_hub.bind_loop()
    await websocket.accept()
    try:
        auth_message=await websocket.receive_json()
        if auth_message.get("type") != "auth": raise ValueError("missing auth")
        user_id, token_version = decode_token(str(auth_message.get("token", "")))
        if not DATABASE_URL: raise ValueError("database unavailable")
        with psycopg.connect(DATABASE_URL, connect_timeout=5) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT auth_version FROM app_users WHERE id=%s", (user_id,))
                row=cur.fetchone()
        if not row or int(row[0]) != token_version: raise ValueError("invalid session")
    except Exception:
        await websocket.close(code=4401, reason="Authentication required")
        return
    sync_socket_hub.connections.setdefault(user_id, set()).add(websocket)
    try:
        await websocket.send_json({"type":"ready"})
        while True:
            # Client heartbeat keeps intermediaries from silently expiring idle sockets.
            message=await websocket.receive_text()
            if message == "ping": await websocket.send_text("pong")
    except WebSocketDisconnect:
        pass
    finally:
        sync_socket_hub.disconnect(user_id, websocket)

@app.get("/sync/revision")
def get_sync_revision(user_id: Annotated[int, Depends(current_user)], conn=Depends(get_connection)):
    """Lightweight fallback check; does not transfer the database snapshot."""
    with conn.cursor() as cur:
        cur.execute("SELECT revision,updated_at FROM sync_documents WHERE owner_id=%s", (user_id,))
        row = cur.fetchone()
    if not row:
        return {"exists": False, "revision": 0, "updated_at": None}
    return {"exists": True, "revision": int(row[0]), "updated_at": row[1]}

@app.get("/sync/state")
def get_sync_state(user_id: Annotated[int, Depends(current_user)], conn=Depends(get_connection)):
    with conn.cursor() as cur:
        cur.execute("SELECT revision,payload,checksum,updated_at FROM sync_documents WHERE owner_id=%s", (user_id,))
        row = cur.fetchone()
    if not row:
        return {"exists": False, "revision": 0, "snapshot": None, "updated_at": None}
    return {"exists": True, "revision": int(row[0]), "snapshot": row[1], "checksum": row[2], "updated_at": row[3]}

@app.put("/sync/state")
def put_sync_state(data: SyncPushInput, user_id: Annotated[int, Depends(current_user)], conn=Depends(get_connection)):
    checksum, snapshot = _validate_sync_snapshot(data.snapshot)
    try:
        with conn.cursor() as cur:
            # Serializuje první zápis i aktualizace pro jednoho vlastníka.
            cur.execute("SELECT pg_advisory_xact_lock(%s, 73125)", (user_id,))
            cur.execute("SELECT revision FROM sync_documents WHERE owner_id=%s FOR UPDATE", (user_id,))
            row = cur.fetchone()
            current_revision = int(row[0]) if row else 0
            if current_revision != data.base_revision:
                raise HTTPException(status_code=409, detail=f"ONLINE data se mezitím změnila (revize {current_revision}). Nejprve načtěte aktuální stav ze serveru.")
            if row:
                cur.execute("SELECT payload FROM sync_documents WHERE owner_id=%s", (user_id,))
                current_payload_row = cur.fetchone()
                current_payload = current_payload_row[0] if current_payload_row else None
                if isinstance(current_payload, str):
                    try: current_payload = json.loads(current_payload)
                    except Exception: current_payload = None
                # Re-uploading an identical database must not create a fake revision.
                if isinstance(current_payload, dict) and current_payload.get("content_sha256") == snapshot.get("content_sha256"):
                    conn.commit()
                    return {"saved": True, "unchanged": True, "revision": current_revision, "checksum": checksum}
            if row:
                cur.execute(
                    "INSERT INTO sync_document_history(owner_id,revision,payload,checksum) "
                    "SELECT owner_id,revision,payload,checksum FROM sync_documents WHERE owner_id=%s",
                    (user_id,),
                )
                # Uchováváme posledních 20 verzí; starší snímky by zbytečně
                # zvětšovaly databázi, zatímco auditní historie zůstává dostupná.
                cur.execute(
                    "DELETE FROM sync_document_history WHERE owner_id=%s AND revision NOT IN "
                    "(SELECT revision FROM sync_document_history WHERE owner_id=%s ORDER BY revision DESC LIMIT 20)",
                    (user_id, user_id),
                )
            new_revision = current_revision + 1
            cur.execute(
                "INSERT INTO sync_documents(owner_id,revision,payload,checksum,updated_at) VALUES(%s,%s,%s,%s,now()) "
                "ON CONFLICT(owner_id) DO UPDATE SET revision=EXCLUDED.revision,payload=EXCLUDED.payload,checksum=EXCLUDED.checksum,updated_at=now()",
                (user_id, new_revision, json.dumps(snapshot, ensure_ascii=False, default=str), checksum),
            )
        conn.commit()
        # Notify all connected devices only after the revision is durably committed.
        # This endpoint is synchronous and FastAPI runs it in a worker thread;
        # get_running_loop() therefore fails here. Schedule onto the ASGI loop.
        try:
            import asyncio
            loop = sync_socket_hub.loop
            if loop is not None and loop.is_running():
                future = asyncio.run_coroutine_threadsafe(
                    sync_socket_hub.publish(user_id, new_revision), loop
                )
                def _log_publish_failure(done):
                    try:
                        done.result()
                    except Exception:
                        logger.exception("WebSocket notification failed for user %s revision %s", user_id, new_revision)
                future.add_done_callback(_log_publish_failure)
            else:
                logger.warning("WebSocket loop is not available for user %s revision %s; clients will recover through revision polling", user_id, new_revision)
        except Exception:
            logger.exception("Could not schedule WebSocket notification for user %s revision %s", user_id, new_revision)
    except HTTPException:
        conn.rollback()
        raise
    except Exception:
        conn.rollback()
        raise
    return {"saved": True, "revision": new_revision, "checksum": checksum}