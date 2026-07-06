import os
import time
import random
import hashlib
import smtplib
import base64
from email.mime.text import MIMEText
from pathlib import Path

import requests
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from typing import List, Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# CONFIG #RAM KUMAR ji ji
GEMINI_API_KEY    = os.getenv("GEMINI_API_KEY", "")
GROQ_API_KEY      = os.getenv("GROQ_API_KEY", "")
HF_API_KEY        = os.getenv("HF_API_KEY", "")
HF_MODEL          = os.getenv("HF_MODEL", "stabilityai/stable-diffusion-xl-base-1.0")
GOOGLE_SCRIPT_URL = os.getenv("GOOGLE_SCRIPT_URL", "")
SMTP_EMAIL        = os.getenv("SMTP_EMAIL", "")
SMTP_APP_PASSWORD = os.getenv("SMTP_APP_PASSWORD", "")

BASE_DIR = Path(__file__).parent.resolve()

# ══════════════════════════════════════════════════════════
#  AI CLIENTS
# ══════════════════════════════════════════════════════════
gemini_client = None
groq_client   = None

if GEMINI_API_KEY:
    try:
        from google import genai
        gemini_client = genai.Client(api_key=GEMINI_API_KEY)
        print("✅ Gemini client ready")
    except Exception as e:
        print(f"⚠️  Gemini init failed: {e}")

if GROQ_API_KEY:
    try:
        from groq import Groq
        groq_client = Groq(api_key=GROQ_API_KEY)
        print("✅ Groq client ready")
    except Exception as e:
        print(f"⚠️  Groq init failed: {e}")

if not SMTP_EMAIL or not SMTP_APP_PASSWORD:
    print("⚠️  SMTP_EMAIL / SMTP_APP_PASSWORD not set — OTP emails disabled")
if not GOOGLE_SCRIPT_URL:
    print("⚠️  GOOGLE_SCRIPT_URL not set — Sheet read/write disabled")

# ══════════════════════════════════════════════════════════
#  APP
# ══════════════════════════════════════════════════════════
app = FastAPI(title="NexusAI Backend", version="4.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Model map ──────────────────────────────────────────────
#  FIX: added gemini-1.5-flash (frontend default was missing here)
MODEL_MAP = {
    "gemini-2.5-flash":     {"provider": "gemini", "model": "gemini-2.5-flash"},
    "llama-3.1-8b-instant": {"provider": "groq",   "model": "llama-3.1-8b-instant"},
}
DEFAULT_MODEL = "gemini-2.5-flash"

# ── In-memory OTP store ────────────────────────────────────
# otp_store[email] = {otp, name, expires_at, verified}
# NOTE: lost on server restart — fine for single-process demo
otp_store: dict = {}
OTP_TTL = 300  # 5 minutes


# ══════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def sheet_request(data: dict) -> dict:
    """POST data to the Google Apps Script Web App."""
    if not GOOGLE_SCRIPT_URL:
        return {"success": False, "message": "GOOGLE_SCRIPT_URL not configured"}
    try:
        r = requests.post(GOOGLE_SCRIPT_URL, json=data, timeout=15)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.Timeout:
        return {"success": False, "message": "Google Script timed out (15s)"}
    except Exception as e:
        return {"success": False, "message": f"Sheet error: {e}"}


def sheet_find_user(email: str) -> dict:
    """Look up a user row by email.  Returns success=True + fields if found."""
    return sheet_request({"action": "login", "email": email.lower().strip()})


def sheet_save_user(name: str, email: str, password_hash: str) -> dict:
    """Append a new user row: Name | Email | PasswordHash | Status=active"""
    return sheet_request({
        "action":       "saveUser",
        "name":         name,
        "email":        email.lower().strip(),
        "passwordHash": password_hash,
        "status":       "active",
    })


def send_otp_email(name: str, email: str, otp: str) -> tuple:
    """
    FIX: uses SMTP_SSL on port 465 (matches the test script that works).
    Old code used STARTTLS on 587 which was failing.
    """
    if not SMTP_EMAIL or not SMTP_APP_PASSWORD:
        return False, "SMTP not configured on server"
    try:
        body = f"""\
Hi {name},

Welcome to NexusAI! 🎉

Your One-Time Password (OTP) for email verification is:

        ━━━━━━━━━━━━━━━━
              {otp}
        ━━━━━━━━━━━━━━━━

This OTP is valid for 5 minutes only.
Please do not share it with anyone.

If you did not sign up for NexusAI, simply ignore this email.

Best regards,
The NexusAI Team
─────────────────────────────────────
Powered by AI · Built for Everyone
"""
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = "Your NexusAI Verification Code"
        msg["From"]    = f"NexusAI <{SMTP_EMAIL}>"
        msg["To"]      = email

        # FIX: SMTP_SSL port 465 (not STARTTLS 587)
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=15) as smtp:
            smtp.login(SMTP_EMAIL, SMTP_APP_PASSWORD)
            smtp.send_message(msg)

        print(f"📧 OTP sent to {email}")
        return True, "OTP sent"

    except smtplib.SMTPAuthenticationError:
        msg = "SMTP auth failed — make sure SMTP_APP_PASSWORD is a Gmail App Password, not your login password"
        print(f"❌ {msg}")
        return False, msg
    except Exception as e:
        print(f"❌ Email error: {e}")
        return False, str(e)


# ══════════════════════════════════════════════════════════
#  PYDANTIC MODELS
# ══════════════════════════════════════════════════════════

class SendOTPRequest(BaseModel):
    # FIX: only name + email here; password arrives separately in /save-password
    name:  str
    email: str

class VerifyOTPRequest(BaseModel):
    email: str
    otp:   str

class ResendOTPRequest(BaseModel):
    email: str
    name:  Optional[str] = ""   # optional — we keep name from otp_store

class SavePasswordRequest(BaseModel):
    # FIX: new endpoint — frontend calls this after OTP is verified
    email:    str
    password: str

class LoginRequest(BaseModel):
    email:    str
    password: str

class HistoryItem(BaseModel):
    role:    str
    content: str

class ChatRequest(BaseModel):
    message:    str
    model:      Optional[str]             = DEFAULT_MODEL
    history:    Optional[List[HistoryItem]] = []
    web_search: Optional[bool]            = False
    email:      Optional[str]             = "guest"

class ImageGenRequest(BaseModel):
    prompt: str


# ══════════════════════════════════════════════════════════
#  AUTH ROUTES
# ══════════════════════════════════════════════════════════

@app.post("/send-otp")
def api_send_otp(data: SendOTPRequest):
    """Step 1: validate input, send OTP email, store in memory."""
    name  = data.name.strip()
    email = data.email.strip().lower()

    if not name or not email:
        return {"success": False, "message": "Name and email are required"}

    # Reject if account already exists in the Sheet
    existing = sheet_find_user(email)
    if existing.get("success"):
        return {"success": False, "message": "An account already exists with this email — please sign in"}

    otp = str(random.randint(100000, 999999))
    otp_store[email] = {
        "otp":        otp,
        "name":       name,
        "expires_at": time.time() + OTP_TTL,
        "verified":   False,
    }

    ok, msg = send_otp_email(name, email, otp)
    if not ok:
        return {"success": False, "message": msg}

    return {"success": True, "message": "OTP sent — check your inbox"}


@app.post("/resend-otp")
def api_resend_otp(data: ResendOTPRequest):
    """Regenerate OTP and resend email for an existing pending signup."""
    email   = data.email.strip().lower()
    pending = otp_store.get(email)

    if not pending:
        return {"success": False, "message": "No pending signup for this email — register again"}

    new_otp = str(random.randint(100000, 999999))
    pending["otp"]        = new_otp
    pending["expires_at"] = time.time() + OTP_TTL
    pending["verified"]   = False

    ok, msg = send_otp_email(pending["name"], email, new_otp)
    if not ok:
        return {"success": False, "message": msg}

    return {"success": True, "message": "New OTP sent — check your inbox"}


@app.post("/verify-otp")
def api_verify_otp(data: VerifyOTPRequest):
    """
    Step 2: verify OTP.
    FIX: does NOT save to Sheet here (password hasn't arrived yet).
    Marks otp_store entry as verified=True so /save-password can proceed.
    """
    email   = data.email.strip().lower()
    pending = otp_store.get(email)

    if not pending:
        return {"success": False, "message": "No pending signup found — please register again"}

    if time.time() > pending["expires_at"]:
        del otp_store[email]
        return {"success": False, "message": "OTP has expired — click Resend"}

    if data.otp.strip() != pending["otp"]:
        return {"success": False, "message": "Incorrect OTP — try again"}

    # Mark as verified; wait for /save-password to write to Sheet
    otp_store[email]["verified"] = True
    return {"success": True, "message": "OTP verified"}


@app.post("/save-password")
def api_save_password(data: SavePasswordRequest):
    """
    Step 3 (NEW ENDPOINT): receive password after OTP verify,
    save complete account (Name | Email | PasswordHash | Status=active) to Sheet.
    """
    email    = data.email.strip().lower()
    password = data.password

    pending = otp_store.get(email)
    if not pending:
        return {"success": False, "message": "Session expired — please register again"}

    if not pending.get("verified"):
        return {"success": False, "message": "OTP not yet verified"}

    if len(password) < 6:
        return {"success": False, "message": "Password must be at least 6 characters"}

    pw_hash = hash_password(password)
    result  = sheet_save_user(pending["name"], email, pw_hash)

    if not result.get("success"):
        return {
            "success": False,
            "message": result.get("message", "Failed to save account to Sheet"),
        }

    name = pending["name"]
    del otp_store[email]   # clean up memory
    print(f"✅ Account created: {name} <{email}>")
    return {"success": True, "name": name, "email": email}


@app.post("/login")
def api_login(data: LoginRequest):
    """Fetch user row from Sheet, compare hashed password."""
    email = data.email.strip().lower()
    user  = sheet_find_user(email)

    if not user.get("success"):
        return {"success": False, "message": user.get("message", "No account found with this email")}

    status = str(user.get("status") or user.get("Status", "")).lower()
    if status != "active":
        return {"success": False, "message": "Account is not active — contact support"}

    # Support multiple casing variants the Sheet script might return
    sheet_hash = (
        user.get("passwordHash")
        or user.get("passwordhash")
        or user.get("PasswordHash")
        or ""
    )
    if hash_password(data.password) != sheet_hash:
        return {"success": False, "message": "Incorrect password"}

    return {
        "success": True,
        "name":    user.get("name")  or user.get("Name",  email.split("@")[0]),
        "email":   user.get("email") or user.get("Email", email),
    }


# ══════════════════════════════════════════════════════════
#  AI CHAT
# ══════════════════════════════════════════════════════════

def chat_with_ai(data: ChatRequest) -> dict:
    model_key = data.model if data.model in MODEL_MAP else DEFAULT_MODEL
    info      = MODEL_MAP[model_key]
    provider  = info["provider"]
    model_id  = info["model"]

    try:
        if provider == "gemini":
            if not gemini_client:
                msg = "❌ Gemini API key not set. Add GEMINI_API_KEY to your .env file."
                return {"response": msg, "reply": msg, "error": False}

            history_text = ""
            for h in (data.history or []):
                role = "User" if h.role == "user" else "Assistant"
                history_text += f"{role}: {h.content}\n"
            full_prompt = history_text + f"User: {data.message}\nAssistant:"

            result = gemini_client.models.generate_content(
                model=model_id, contents=full_prompt.strip()
            )
            reply = result.text

        elif provider == "groq":
            if not groq_client:
                msg = "❌ Groq API key not set. Add GROQ_API_KEY to your .env file."
                return {"response": msg, "reply": msg, "error": False}

            messages = [{"role": h.role, "content": h.content} for h in (data.history or [])]
            messages.append({"role": "user", "content": data.message})

            result = groq_client.chat.completions.create(
                model=model_id, messages=messages, max_tokens=2048
            )
            reply = result.choices[0].message.content

        else:
            return {"response": f"Unknown provider: {provider}", "error": True}

        return {"response": reply, "reply": reply, "error": False}

    except Exception as e:
        err_msg = f"⚠️ AI Error: {e}"
        print(f"❌ Chat error: {e}")
        return {"error": str(e), "reply": err_msg, "response": err_msg}


@app.post("/chat")
def chat(data: ChatRequest):
    return chat_with_ai(data)


@app.post("/api/chat")
def chat_api(data: ChatRequest):
    return chat_with_ai(data)


# ══════════════════════════════════════════════════════════
#  IMAGE GENERATION (Hugging Face)
# ══════════════════════════════════════════════════════════

def generate_image_hf(prompt: str, retries: int = 3) -> dict:
    if not HF_API_KEY:
        return {"success": False, "message": "HF_API_KEY not configured"}

    url     = f"https://api-inference.huggingface.co/models/{HF_MODEL}"
    headers = {"Authorization": f"Bearer {HF_API_KEY}"}

    for _ in range(retries):
        try:
            r            = requests.post(url, headers=headers, json={"inputs": prompt}, timeout=60)
            content_type = r.headers.get("content-type", "")

            if r.status_code == 200 and content_type.startswith("image"):
                b64 = base64.b64encode(r.content).decode()
                return {"success": True, "image": f"data:{content_type};base64,{b64}"}

            try:
                data = r.json()
            except Exception:
                return {"success": False, "message": f"HF error (status {r.status_code})"}

            if isinstance(data, dict) and "estimated_time" in data:
                wait = min(float(data["estimated_time"]), 20)
                time.sleep(wait)
                continue

            err = data.get("error") if isinstance(data, dict) else str(data)
            return {"success": False, "message": err or f"HF error ({r.status_code})"}

        except requests.exceptions.Timeout:
            return {"success": False, "message": "Hugging Face request timed out"}
        except Exception as e:
            return {"success": False, "message": str(e)}

    return {"success": False, "message": "Model still loading on HF — try again in ~20s"}


@app.post("/generate-image")
def api_generate_image(data: ImageGenRequest):
    prompt = (data.prompt or "").strip()
    if not prompt:
        return {"success": False, "message": "Prompt cannot be empty"}
    return generate_image_hf(prompt)


# ══════════════════════════════════════════════════════════
#  HEALTH CHECK
# ══════════════════════════════════════════════════════════

@app.get("/health")
def health():
    return {
        "status": "ok",
        "gemini": gemini_client is not None,
        "groq":   groq_client   is not None,
        "hf":     bool(HF_API_KEY),
        "smtp":   bool(SMTP_EMAIL and SMTP_APP_PASSWORD),
        "sheet":  bool(GOOGLE_SCRIPT_URL),
    }


# ══════════════════════════════════════════════════════════
#  SERVE FRONTEND
# ══════════════════════════════════════════════════════════

@app.get("/")
def serve_frontend():
    p = BASE_DIR / "index.html"
    if p.exists():
        return FileResponse(str(p))
    return JSONResponse({"error": f"index.html not found at {p}"}, status_code=404)


@app.get("/{file_path:path}")
def serve_static(file_path: str):
    p = BASE_DIR / file_path
    if p.exists() and p.is_file():
        return FileResponse(str(p))
    return JSONResponse({"error": f"Not found: {file_path}"}, status_code=404)


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
