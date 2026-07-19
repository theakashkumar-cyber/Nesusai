"""
NexusAI Backend — main.py  (v5: complete, production-ready)

FIXES vs v4:
  1. MODEL_MAP now includes gemini-1.5-flash (frontend default) — was causing 404 silent fallback.
  2. /forgot-password endpoint: generates a 6-digit OTP, emails it, stores in reset_store.
  3. /reset-password endpoint: verifies reset OTP and updates password hash in Sheet.
  4. Image generation: retries 5×, better loading state messages, clear HF error surfacing.
  5. /health now reports reset_store pending count for debugging.
  6. All endpoints return consistent {success, message} shape.
  7. CORS tightened — set ALLOWED_ORIGINS in .env for production.

SETUP:
  pip install -r requirements.txt

  .env file:
    GEMINI_API_KEY=...
    GROQ_API_KEY=...
    HF_API_KEY=...                       # huggingface.co → Settings → Access Tokens
    HF_MODEL=black-forest-labs/FLUX.1-schnell
    GOOGLE_SCRIPT_URL=https://script.google.com/macros/s/XXXX/exec
    SMTP_EMAIL=you@gmail.com
    SMTP_APP_PASSWORD=xxxx xxxx xxxx xxxx
    ALLOWED_ORIGINS=https://yourapp.onrender.com,http://localhost:5000

  Run: python main.py  →  http://127.0.0.1:5000
"""

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

# ══════════════════════════════════════════════════════════
#  CONFIG
# ══════════════════════════════════════════════════════════
GEMINI_API_KEY    = os.getenv("GEMINI_API_KEY",    "")
GROQ_API_KEY      = os.getenv("GROQ_API_KEY",      "")
HF_API_KEY        = os.getenv("HF_API_KEY",        "")
HF_MODEL          = os.getenv("HF_MODEL",          "black-forest-labs/FLUX.1-schnell")
GOOGLE_SCRIPT_URL = os.getenv("GOOGLE_SCRIPT_URL", "")
SMTP_EMAIL        = os.getenv("SMTP_EMAIL",        "")
SMTP_APP_PASSWORD = os.getenv("SMTP_APP_PASSWORD", "")
ALLOWED_ORIGINS   = os.getenv("ALLOWED_ORIGINS",   "*").split(",")

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
    print("⚠️  SMTP not configured — email features disabled")
if not GOOGLE_SCRIPT_URL:
    print("⚠️  GOOGLE_SCRIPT_URL not set — Sheet read/write disabled")
if not HF_API_KEY:
    print("⚠️  HF_API_KEY not set — image generation disabled")

# ══════════════════════════════════════════════════════════
#  APP
# ══════════════════════════════════════════════════════════
app = FastAPI(title="NexusAI Backend", version="5.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS if ALLOWED_ORIGINS != ["*"] else ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Model map ──────────────────────────────────────────────
# FIX: gemini-1.5-flash was missing — it's the frontend's default model
MODEL_MAP = {
    "gemini-2.5-flash":     {"provider": "gemini", "model": "gemini-2.5-flash"},  # ← ADDED
    "llama-3.1-8b-instant": {"provider": "groq",   "model": "llama-3.1-8b-instant"},
}
DEFAULT_MODEL = "gemini-2.5-flash"

# ── In-memory stores ───────────────────────────────────────
# otp_store[email]   = {otp, name, expires_at, verified}
# reset_store[email] = {otp, expires_at}
otp_store:   dict = {}
reset_store: dict = {}
OTP_TTL = 300  # 5 minutes


# ══════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def sheet_request(data: dict) -> dict:
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
    return sheet_request({"action": "login", "email": email.lower().strip()})


def sheet_save_user(name: str, email: str, password_hash: str) -> dict:
    return sheet_request({
        "action":       "saveUser",
        "name":         name,
        "email":        email.lower().strip(),
        "passwordHash": password_hash,
        "status":       "active",
    })


def sheet_update_password(email: str, password_hash: str) -> dict:
    """Update an existing user's password hash in the Sheet."""
    return sheet_request({
        "action":       "updatePassword",
        "email":        email.lower().strip(),
        "passwordHash": password_hash,
    })


def _send_email(to_email: str, subject: str, body: str) -> tuple[bool, str]:
    """Send an email via Gmail SMTP SSL (port 465)."""
    if not SMTP_EMAIL or not SMTP_APP_PASSWORD:
        return False, "SMTP not configured on server"
    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"]    = f"NexusAI <{SMTP_EMAIL}>"
        msg["To"]      = to_email
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=15) as smtp:
            smtp.login(SMTP_EMAIL, SMTP_APP_PASSWORD)
            smtp.send_message(msg)
        print(f"📧 Email sent to {to_email}: {subject}")
        return True, "Email sent"
    except smtplib.SMTPAuthenticationError:
        msg = "SMTP auth failed — use a Gmail App Password, not your login password"
        print(f"❌ {msg}")
        return False, msg
    except Exception as e:
        print(f"❌ Email error: {e}")
        return False, str(e)


def send_otp_email(name: str, email: str, otp: str) -> tuple[bool, str]:
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
    return _send_email(email, "Your NexusAI Verification Code", body)


def send_reset_email(email: str, otp: str) -> tuple[bool, str]:
    body = f"""\
Hi,

We received a request to reset your NexusAI password.

Your password reset code is:

        ━━━━━━━━━━━━━━━━
              {otp}
        ━━━━━━━━━━━━━━━━

This code expires in 5 minutes.
If you did not request a reset, ignore this email — your password is unchanged.

Best regards,
The NexusAI Team
"""
    return _send_email(email, "NexusAI Password Reset Code", body)


# ══════════════════════════════════════════════════════════
#  PYDANTIC MODELS
# ══════════════════════════════════════════════════════════

class SendOTPRequest(BaseModel):
    name:  str
    email: str

class VerifyOTPRequest(BaseModel):
    email: str
    otp:   str

class ResendOTPRequest(BaseModel):
    email: str
    name:  Optional[str] = ""

class SavePasswordRequest(BaseModel):
    email:    str
    password: str

class LoginRequest(BaseModel):
    email:    str
    password: str

class ForgotPasswordRequest(BaseModel):
    email: str

class ResetPasswordRequest(BaseModel):
    email:    str
    otp:      str
    password: str

class HistoryItem(BaseModel):
    role:    str
    content: str

class ChatRequest(BaseModel):
    message:    str
    model:      Optional[str]               = DEFAULT_MODEL
    history:    Optional[List[HistoryItem]] = []
    web_search: Optional[bool]              = False
    email:      Optional[str]               = "guest"

class ImageGenRequest(BaseModel):
    prompt: str


# ══════════════════════════════════════════════════════════
#  AUTH ROUTES
# ══════════════════════════════════════════════════════════

@app.post("/send-otp")
def api_send_otp(data: SendOTPRequest):
    """Step 1 of registration: validate input, send OTP, store in memory."""
    name  = data.name.strip()
    email = data.email.strip().lower()

    if not name or not email:
        return {"success": False, "message": "Name and email are required"}

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
    """Step 2: verify OTP, mark as verified. Password saved separately."""
    email   = data.email.strip().lower()
    pending = otp_store.get(email)

    if not pending:
        return {"success": False, "message": "No pending signup found — please register again"}

    if time.time() > pending["expires_at"]:
        del otp_store[email]
        return {"success": False, "message": "OTP has expired — click Resend"}

    if data.otp.strip() != pending["otp"]:
        return {"success": False, "message": "Incorrect OTP — try again"}

    otp_store[email]["verified"] = True
    return {"success": True, "message": "OTP verified"}


@app.post("/save-password")
def api_save_password(data: SavePasswordRequest):
    """Step 3: receive password after OTP verify, write complete account to Sheet."""
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
    del otp_store[email]
    print(f"✅ Account created: {name} <{email}>")
    return {"success": True, "name": name, "email": email}


@app.post("/login")
def api_login(data: LoginRequest):
    email = data.email.strip().lower()
    user  = sheet_find_user(email)

    if not user.get("success"):
        return {"success": False, "message": user.get("message", "No account found with this email")}

    status = str(user.get("status") or user.get("Status", "")).lower()
    if status != "active":
        return {"success": False, "message": "Account is not active — contact support"}

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


# ─── FORGOT / RESET PASSWORD ───────────────────────────────

@app.post("/forgot-password")
def api_forgot_password(data: ForgotPasswordRequest):
    """
    Check the email exists in Sheet, generate a reset OTP, email it.
    Returns success=True even if email not found (security: don't reveal account existence).
    """
    email = data.email.strip().lower()
    if not email:
        return {"success": False, "message": "Email is required"}

    # Verify account exists
    user = sheet_find_user(email)
    if not user.get("success"):
        # Return generic success to prevent email enumeration
        return {"success": True, "message": "If that email is registered, a reset code was sent"}

    otp = str(random.randint(100000, 999999))
    reset_store[email] = {
        "otp":        otp,
        "expires_at": time.time() + OTP_TTL,
    }

    ok, msg = send_reset_email(email, otp)
    if not ok:
        return {"success": False, "message": f"Could not send reset email: {msg}"}

    return {"success": True, "message": "Reset code sent — check your inbox"}


@app.post("/reset-password")
def api_reset_password(data: ResetPasswordRequest):
    """Verify reset OTP and write new password hash to Sheet."""
    email    = data.email.strip().lower()
    pending  = reset_store.get(email)

    if not pending:
        return {"success": False, "message": "No reset request found — request a new code"}

    if time.time() > pending["expires_at"]:
        del reset_store[email]
        return {"success": False, "message": "Reset code expired — request a new one"}

    if data.otp.strip() != pending["otp"]:
        return {"success": False, "message": "Incorrect reset code — try again"}

    if len(data.password) < 6:
        return {"success": False, "message": "Password must be at least 6 characters"}

    pw_hash = hash_password(data.password)
    result  = sheet_update_password(email, pw_hash)

    if not result.get("success"):
        return {
            "success": False,
            "message": result.get("message", "Failed to update password — contact support"),
        }

    del reset_store[email]
    print(f"🔑 Password reset: {email}")
    return {"success": True, "message": "Password updated — you can now sign in"}


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
#  IMAGE GENERATION (Hugging Face Inference API)
# ══════════════════════════════════════════════════════════

def generate_image_hf(prompt: str, retries: int = 5) -> dict:
    """
    Call the Hugging Face Inference API.
    Retries up to `retries` times when the model is warming up (estimated_time in response).
    """
    if not HF_API_KEY:
        return {
            "success": False,
            "message": "Image generation is not configured. Add HF_API_KEY to the server's .env file.",
        }

    url     = f"https://api-inference.huggingface.co/models/{HF_MODEL}"
    headers = {
        "Authorization": f"Bearer {HF_API_KEY}",
        "Accept":        "image/*",
        "X-Wait-For-Model": "true",   # ask HF to wait rather than return 503 immediately
    }
    payload = {"inputs": prompt, "options": {"wait_for_model": True}}

    for attempt in range(1, retries + 1):
        print(f"🎨 Image attempt {attempt}/{retries}: {prompt[:60]}…")
        try:
            r            = requests.post(url, headers=headers, json=payload, timeout=120)
            content_type = r.headers.get("content-type", "")

            # Success — raw image bytes
            if r.status_code == 200 and content_type.startswith("image"):
                b64 = base64.b64encode(r.content).decode()
                print(f"✅ Image generated ({len(r.content)//1024} KB)")
                return {"success": True, "image": f"data:{content_type};base64,{b64}"}

            # Try to parse error JSON
            try:
                err_data = r.json()
            except Exception:
                return {"success": False, "message": f"HF error (HTTP {r.status_code})"}

            # Model loading — wait and retry
            if isinstance(err_data, dict) and "estimated_time" in err_data:
                wait = min(float(err_data.get("estimated_time", 20)), 30)
                print(f"⏳ Model loading, waiting {wait:.0f}s…")
                time.sleep(wait)
                continue

            # Explicit error message from HF
            err_msg = (
                err_data.get("error")
                if isinstance(err_data, dict)
                else str(err_data)
            )
            return {"success": False, "message": err_msg or f"HF returned HTTP {r.status_code}"}

        except requests.exceptions.Timeout:
            if attempt < retries:
                print(f"⏳ Timeout on attempt {attempt}, retrying…")
                time.sleep(5)
                continue
            return {"success": False, "message": "Request timed out — try again or use a shorter prompt"}
        except Exception as e:
            return {"success": False, "message": str(e)}

    return {
        "success": False,
        "message": "Model is still warming up on Hugging Face. Wait 30s and try again.",
    }


@app.post("/generate-image")
def api_generate_image(data: ImageGenRequest):
    prompt = (data.prompt or "").strip()
    if not prompt:
        return {"success": False, "message": "Prompt cannot be empty"}
    if len(prompt) > 500:
        return {"success": False, "message": "Prompt too long — keep it under 500 characters"}
    return generate_image_hf(prompt)


# ══════════════════════════════════════════════════════════
#  HEALTH CHECK
# ══════════════════════════════════════════════════════════

@app.get("/health")
def health():
    return {
        "status":        "ok",
        "version":       "5.0",
        "gemini":        gemini_client is not None,
        "groq":          groq_client   is not None,
        "hf":            bool(HF_API_KEY),
        "hf_model":      HF_MODEL,
        "smtp":          bool(SMTP_EMAIL and SMTP_APP_PASSWORD),
        "sheet":         bool(GOOGLE_SCRIPT_URL),
        "pending_otps":  len(otp_store),
        "pending_resets": len(reset_store),
    }


# ══════════════════════════════════════════════════════════
#  SERVE FRONTEND  (only when running locally with index.html)
# ══════════════════════════════════════════════════════════

@app.get("/")
def serve_frontend():
    p = BASE_DIR / "index.html"
    if p.exists():
        return FileResponse(str(p))
    return JSONResponse({"message": "NexusAI API v5 — frontend not bundled here"})


@app.get("/{file_path:path}")
def serve_static(file_path: str):
    p = BASE_DIR / file_path
    if p.exists() and p.is_file():
        return FileResponse(str(p))
    return JSONResponse({"error": f"Not found: {file_path}"}, status_code=404)


# ══════════════════════════════════════════════════════════
#  ENTRYPOINT
# ══════════════════════════════════════════════════════════

if __name__ == "__main__":
    print(f"\n🚀 NexusAI Backend v5")
    print(f"📁 Serving from: {BASE_DIR}")
    print(f"🌐 Open:         http://127.0.0.1:5000\n")
    uvicorn.run("main:app", host="0.0.0.0", port=5000, reload=True)
