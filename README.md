# Nexai.enem
Seu assistente particular parar o enem 
Rumo ao Enem: subscription-gated study assistant.

Run behind HTTPS in production with a persistent DATABASE_PATH.
"""
import hmac
import json
import os
import re
import secrets
import sqlite3
import smtplib
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from email.message import EmailMessage
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import check_password_hash, generate_password_hash

ROOT = Path(__file__).resolve().parent
for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines() if (ROOT / ".env").exists() else []:
    if line.strip() and not line.startswith("#") and "=" in line:
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())

PUBLIC_URL = os.environ.get("PUBLIC_URL") or os.environ.get("RENDER_EXTERNAL_URL") or "http://127.0.0.1:8000"
PUBLIC_URL = PUBLIC_URL.rstrip("/")
if PUBLIC_URL.startswith("https://") and (not os.environ.get("SECRET_KEY") or os.environ["SECRET_KEY"].startswith("substitua_")):
    raise RuntimeError("Configure uma SECRET_KEY fixa antes de publicar o aplicativo.")
DB_PATH = Path(os.environ.get("DATABASE_PATH", str(ROOT / "data/rumo_enem.sqlite3")))
if not DB_PATH.is_absolute():
    DB_PATH = ROOT / DB_PATH
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
MP_TOKEN = os.environ.get("MP_ACCESS_TOKEN", "")
OPENAI_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4.1-mini")
OWNER_EMAIL = os.environ.get("OWNER_EMAIL", "").lower().strip()
SMTP_HOST = os.environ.get("SMTP_HOST", "")
if PUBLIC_URL.startswith("https://") and (not SMTP_HOST or not os.environ.get("SMTP_PASSWORD")):
    raise RuntimeError("Configure o serviÃ§o de e-mail antes de publicar o aplicativo.")
AMOUNT = 19.90
DAILY_LIMIT = 20
PROMPT = (ROOT / "instrucoes.txt").read_text(encoding="utf-8")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_urlsafe(48))
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=PUBLIC_URL.startswith("https://"), MAX_CONTENT_LENGTH=100_000)


@contextmanager
def db():
    connection = sqlite3.connect(DB_PATH, timeout=15)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


with db() as c:
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL, mp_id TEXT, created_at TEXT NOT NULL, verified INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS usage(user_id TEXT NOT NULL, day TEXT NOT NULL, count INTEGER NOT NULL,
        PRIMARY KEY(user_id, day));
    CREATE TABLE IF NOT EXISTS attempts(email TEXT PRIMARY KEY, failures INTEGER NOT NULL, until REAL NOT NULL);
    CREATE TABLE IF NOT EXISTS mail_limits(email TEXT NOT NULL, purpose TEXT NOT NULL, sent_at REAL NOT NULL,
        PRIMARY KEY(email,purpose));
    """)


def api(url, token, payload=None, method=None):
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None
    headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
    req = Request(url, data=data, headers=headers, method=method or ("POST" if data else "GET"))
    try:
        with urlopen(req, timeout=35) as res:
            return json.load(res)
    except HTTPError as e:
        raise RuntimeError(f"ServiÃ§o externo respondeu com erro {e.code}.") from e
    except (URLError, TimeoutError) as e:
        raise RuntimeError("ServiÃ§o externo indisponÃ­vel. Tente novamente.") from e


def mp(path, payload=None):
    if not MP_TOKEN or MP_TOKEN.startswith("COLE_"):
        raise RuntimeError("Configure a conta Mercado Pago antes de vender assinaturas.")
    return api("https://api.mercadopago.com" + path, MP_TOKEN, payload)


def user():
    uid = session.get("uid")
    if not uid:
        return None
    with db() as c:
        return c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()


def mail_link(email, purpose):
    claim = {"email": email}
    if purpose == "reset":
        with db() as c:
            row = c.execute("SELECT password_hash FROM users WHERE email=?", (email,)).fetchone()
        claim["hash"] = row["password_hash"] if row else ""
    token = URLSafeTimedSerializer(app.secret_key).dumps(claim, salt=purpose)
    return PUBLIC_URL + "/" + purpose + "/" + token


def send_mail(address, subject, link):
    purpose = "verify" if "/verify/" in link else "reset"
    with db() as c:
        record = c.execute("SELECT sent_at FROM mail_limits WHERE email=? AND purpose=?", (address, purpose)).fetchone()
        if record and time.time() - record["sent_at"] < 60:
            raise RuntimeError("Aguarde um minuto antes de solicitar outro e-mail.")
        c.execute("INSERT INTO mail_limits VALUES(?,?,?) ON CONFLICT(email,purpose) DO UPDATE SET sent_at=?",
                  (address, purpose, time.time(), time.time()))
    if not SMTP_HOST:
        return link if PUBLIC_URL.startswith("http://127.0.0.1") else None
    msg = EmailMessage()
    msg["From"] = os.environ.get("SMTP_FROM", os.environ.get("SMTP_USER", ""))
    msg["To"] = address
    msg["Subject"] = subject
    msg.set_content("Para continuar no Rumo ao Enem, abra este link (vÃ¡lido por 1 hora):\n\n" + link)
    try:
        with smtplib.SMTP(SMTP_HOST, int(os.environ.get("SMTP_PORT", "587")), timeout=15) as server:
            server.starttls()
            server.login(os.environ.get("SMTP_USER", ""), os.environ.get("SMTP_PASSWORD", ""))
            server.send_message(msg)
    except (OSError, smtplib.SMTPException) as e:
        raise RuntimeError("NÃ£o foi possÃ­vel enviar o e-mail. Tente novamente.") from e
    return None


def read_token(token, purpose):
    try:
        claim = URLSafeTimedSerializer(app.secret_key).loads(token, salt=purpose, max_age=3600)
        if not isinstance(claim, dict) or not isinstance(claim.get("email"), str):
            return None
        if purpose == "reset":
            with db() as c:
                row = c.execute("SELECT password_hash FROM users WHERE email=?", (claim["email"],)).fetchone()
            if not row or not hmac.compare_digest(row["password_hash"], claim.get("hash", "")):
                return None
        return claim["email"]
    except (BadSignature, SignatureExpired):
        return None


def csrf_ok():
    supplied = request.headers.get("X-CSRF-Token", "") or request.form.get("csrf", "")
    return hmac.compare_digest(supplied, session.get("csrf", "unused"))


def error(message, status=400):
    return jsonify(error=message), status


@app.before_request
def protect():
    if request.method in ("POST", "PUT", "DELETE") and not csrf_ok():
        return error("SessÃ£o expirada. Atualize a pÃ¡gina e tente novamente.", 403)


@app.get("/")
def home():
    session.setdefault("csrf", secrets.token_urlsafe(32))
    return render_template("index.html", csrf=session["csrf"], public_url=PUBLIC_URL)


@app.get("/verify/<token>")
def verify(token):
    email = read_token(token, "verify")
    if not email:
        return redirect("/?notice=invalid")
    with db() as c:
        c.execute("UPDATE users SET verified=1 WHERE email=?", (email,))
    return redirect("/?notice=verified")


@app.get("/reset/<token>")
def reset_page(token):
    if not read_token(token, "reset"):
        return redirect("/?notice=invalid")
    session.setdefault("csrf", secrets.token_urlsafe(32))
    return render_template("index.html", csrf=session["csrf"], reset_token=token)


@app.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(email) > 250 or len(password) < 12 or len(password) > 128:
        return error("Informe um e-mail vÃ¡lido e uma senha de 12 a 128 caracteres.")
    uid = secrets.token_hex(16)
    try:
        with db() as c:
            c.execute("INSERT INTO users VALUES(?,?,?,?,?,0)", (uid, email, generate_password_hash(password), None, datetime.now(timezone.utc).isoformat()))
    except sqlite3.IntegrityError:
        return error("Este e-mail jÃ¡ estÃ¡ cadastrado.")
    try:
        local_link = send_mail(email, "Confirme seu e-mail â Rumo ao Enem", mail_link(email, "verify"))
    except RuntimeError as e:
        with db() as c:
            c.execute("DELETE FROM users WHERE id=? AND verified=0", (uid,))
        return error(str(e), 503)
    return jsonify(ok=True, message="Abra o link enviado ao seu e-mail e depois entre na sua conta.", dev_link=local_link)


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    if len(email) > 250 or len(password) > 128:
        return error("Dados invÃ¡lidos.")
    with db() as c:
        attempt = c.execute("SELECT * FROM attempts WHERE email=?", (email,)).fetchone()
        if attempt and attempt["until"] > time.time():
            return error("Aguarde alguns minutos antes de tentar novamente.", 429)
        row = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not row or not check_password_hash(row["password_hash"], password):
            failures = (attempt["failures"] if attempt else 0) + 1
            until = time.time() + 900 if failures >= 5 else 0
            c.execute("INSERT INTO attempts VALUES(?,?,?) ON CONFLICT(email) DO UPDATE SET failures=?, until=?",
                      (email, failures, until, failures, until))
            return error("E-mail ou senha incorretos.", 401)
        if not row["verified"]:
            return error("Confirme seu e-mail antes de entrar. Use Reenviar confirmaÃ§Ã£o se necessÃ¡rio.", 403)
        c.execute("DELETE FROM attempts WHERE email=?", (email,))
    session.clear()
    session.update(uid=row["id"], csrf=secrets.token_urlsafe(32))
    return jsonify(ok=True, csrf=session["csrf"])


@app.post("/api/resend")
def resend():
    email = str((request.get_json(silent=True) or {}).get("email", "")).strip().lower()
    with db() as c:
        row = c.execute("SELECT verified FROM users WHERE email=?", (email,)).fetchone()
    if row and not row["verified"]:
        try:
            link = send_mail(email, "Confirme seu e-mail â Rumo ao Enem", mail_link(email, "verify"))
        except RuntimeError as e:
            return error(str(e), 503)
        return jsonify(ok=True, message="Confira sua caixa de entrada.", dev_link=link)
    return jsonify(ok=True, message="Se houver uma conta pendente, vocÃª receberÃ¡ um e-mail.")


@app.post("/api/forgot")
def forgot():
    email = str((request.get_json(silent=True) or {}).get("email", "")).strip().lower()
    with db() as c:
        row = c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    if row:
        try:
            link = send_mail(email, "Recupere sua senha â Rumo ao Enem", mail_link(email, "reset"))
        except RuntimeError as e:
            return error(str(e), 503)
        return jsonify(ok=True, message="Se houver uma conta, vocÃª receberÃ¡ um link para trocar a senha.", dev_link=link)
    return jsonify(ok=True, message="Se houver uma conta, vocÃª receberÃ¡ um link para trocar a senha.")


@app.post("/api/reset")
def reset_password():
    data = request.get_json(silent=True) or {}
    email = read_token(str(data.get("token", "")), "reset")
    password = str(data.get("password", ""))
    if not email or not 12 <= len(password) <= 128:
        return error("Link invÃ¡lido ou expirado, ou senha fora do tamanho permitido.")
    with db() as c:
        c.execute("UPDATE users SET password_hash=? WHERE email=?", (generate_password_hash(password), email))
    session.clear()
    session["csrf"] = secrets.token_urlsafe(32)
    return jsonify(ok=True, csrf=session["csrf"], message="Senha atualizada. Entre na sua conta.")


@app.post("/api/logout")
def logout():
    session.clear()
    session["csrf"] = secrets.token_urlsafe(32)
    return jsonify(ok=True, csrf=session["csrf"])


def paid(row):
    """Always ask Mercado Pago; a return URL or a locally stored flag never grants access."""
    if not row["mp_id"]:
        return False
    ident = row["mp_id"]
    subscription = mp("/preapproval/" + ident)
    if subscription.get("status") != "authorized" or str(subscription.get("external_reference")) != row["id"]:
        return False
    if subscription.get("payer_email", "").lower() != row["email"]:
        return False
    terms = subscription.get("auto_recurring") or {}
    if terms.get("currency_id") != "BRL" or float(terms.get("transaction_amount", 0)) != AMOUNT:
        return False
    invoices = mp("/authorized_payments/search?" + urlencode({"preapproval_id": ident, "limit": 20}))
    recent = datetime.now(timezone.utc) - timedelta(days=35)
    for invoice in invoices.get("results", []):
        payment = invoice.get("payment") or {}
        if (invoice.get("preapproval_id") != ident or payment.get("status") != "approved"
                or invoice.get("currency_id") != "BRL"
                or float(invoice.get("transaction_amount", 0)) != AMOUNT):
            continue
        date = invoice.get("debit_date") or invoice.get("date_created") or ""
        try:
            if datetime.fromisoformat(date.replace("Z", "+00:00")) >= recent:
                return True
        except ValueError:
            pass
    return False


@app.get("/api/account")
def account():
    row = user()
    if not row:
        return jsonify(logged=False, price="R$ 19,90/mÃªs")
    try:
        active = paid(row)
        note = ""
    except RuntimeError as e:
        active, note = False, str(e)
    today = datetime.now(timezone.utc).date().isoformat()
    with db() as c:
        usage = c.execute("SELECT count FROM usage WHERE user_id=? AND day=?", (row["id"], today)).fetchone()
    return jsonify(logged=True, email=row["email"], active=active,
                   used=usage["count"] if usage else 0, limit=DAILY_LIMIT, note=note,
                   price="R$ 19,90/mÃªs", owner=row["email"] == OWNER_EMAIL)


@app.post("/api/subscribe")
def subscribe():
    row = user()
    if not row:
        return error("Entre ou crie sua conta para assinar.", 401)
    try:
        if row["mp_id"]:
            current = mp("/preapproval/" + row["mp_id"])
            if current.get("status") in ("pending", "authorized") and current.get("init_point"):
                return jsonify(url=current["init_point"])
        subscription = mp("/preapproval", {
            "reason": "Rumo ao Enem - assinatura mensal",
            "external_reference": row["id"],
            "payer_email": row["email"],
            "back_url": PUBLIC_URL + "/",
            "auto_recurring": {"frequency": 1, "frequency_type": "months",
                               "transaction_amount": AMOUNT, "currency_id": "BRL"},
            "status": "pending",
        })
        ident, url = subscription.get("id"), subscription.get("init_point")
        if not ident or not url or not url.startswith("https://"):
            return error("NÃ£o foi possÃ­vel abrir o pagamento. Tente novamente.", 502)
        with db() as c:
            c.execute("UPDATE users SET mp_id=? WHERE id=?", (ident, row["id"]))
        return jsonify(url=url)
    except RuntimeError as e:
        return error(str(e), 503)


@app.post("/api/chat")
def chat():
    row = user()
    if not row:
        return error("Entre para conversar com a IA.", 401)
    try:
        if not paid(row):
            return error("A assinatura ainda nÃ£o tem uma cobranÃ§a aprovada. Verifique seu pagamento e tente novamente.", 402)
    except RuntimeError as e:
        return error("NÃ£o consegui confirmar a assinatura: " + str(e), 503)
    if not OPENAI_KEY or OPENAI_KEY.startswith("COLE_"):
        return error("A chave do modelo de IA ainda nÃ£o foi configurada.", 503)
    data = request.get_json(silent=True) or {}
    messages = data.get("messages")
    if not isinstance(messages, list) or not 1 <= len(messages) <= 12:
        return error("Envie uma conversa de atÃ© 12 mensagens.")
    clean = []
    for item in messages:
        if not isinstance(item, dict) or item.get("role") not in ("user", "assistant"):
            return error("Mensagem invÃ¡lida.")
        text = item.get("content")
        if not isinstance(text, str) or not 1 <= len(text) <= 5000:
            return error("Cada mensagem deve ter atÃ© 5.000 caracteres.")
        clean.append({"role": item["role"], "content": text})
    if clean[-1]["role"] != "user" or sum(len(i["content"]) for i in clean) > 16000:
        return error("Mensagem invÃ¡lida ou conversa muito longa.")
    today = datetime.now(timezone.utc).date().isoformat()
    with db() as c:
        c.execute("BEGIN IMMEDIATE")
        c.execute("INSERT OR IGNORE INTO usage VALUES(?,?,0)", (row["id"], today))
        current = c.execute("SELECT count FROM usage WHERE user_id=? AND day=?", (row["id"], today)).fetchone()[0]
        if current >= DAILY_LIMIT:
            return error("VocÃª atingiu 20 perguntas hoje. Volte amanhÃ£.", 429)
        c.execute("UPDATE usage SET count=count+1 WHERE user_id=? AND day=?", (row["id"], today))
    try:
        result = api("https://api.openai.com/v1/responses", OPENAI_KEY, {
            "model": OPENAI_MODEL, "instructions": PROMPT, "input": clean,
            "max_output_tokens": 1400, "store": False,
        })
        answer = "\n".join(part.get("text", "") for item in result.get("output", [])
                           for part in item.get("content", []) if part.get("type") == "output_text").strip()
        if not answer:
            raise RuntimeError("A IA nÃ£o devolveu uma resposta.")
        return jsonify(answer=answer, used=current + 1, limit=DAILY_LIMIT)
    except RuntimeError as e:
        with db() as c:
            c.execute("UPDATE usage SET count=MAX(0,count-1) WHERE user_id=? AND day=?", (row["id"], today))
        return error(str(e), 503)


@app.get("/api/admin")
def admin():
    row = user()
    if not row or not OWNER_EMAIL or row["email"] != OWNER_EMAIL:
        return error("Acesso restrito.", 403)
    with db() as c:
        rows = c.execute("SELECT email,created_at,mp_id FROM users ORDER BY created_at DESC LIMIT 500").fetchall()
    return jsonify(total=len(rows), users=[dict(r) for r in rows])


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "8000")))
