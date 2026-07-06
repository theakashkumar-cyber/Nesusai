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

# CONFIG
GEMINI_API_KEY    = os.getenv("GEMINI_API_KEY", "")
GROQ_API_KEY      = os.getenv("GROQ_API_KEY", "")
HF_API_KEY        = os.getenv("HF_API_KEY", "")
HF_MODEL          = os.getenv("HF_MODEL", "stabilityai/stable-diffusion-xl-base-1.0")
GOOGLE_SCRIPT_URL = os.getenv("GOOGLE_SCRIPT_URL", "")
SMTP_EMAIL        = os.getenv("SMTP_EMAIL", "")
SMTP_APP_PASSWORD = os.getenv("SMTP_APP_PASSWORD", "")

BASE_DIR = Path(__file__).parent.resolve()

# AI CLIENTS
gemini_client = None
groq_client   = None

if GEMINI_API_KEY:
    try:
        from google import genai
        gemini_client = genai.Client(api_key=GEMINI_API_KEY)
    except Exception:
        pass

if GROQ_API_KEY:
    try:
        from groq import Groq
        groq_client = Groq(api_key=GROQ_API_KEY)
    except Exception:
        pass

app = FastAPI(title="NexusAI Backend")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

MODEL_MAP = {
    "gemini-2.5-flash":     {"provider": "gemini", "model": "gemini-2.5-flash"},
    "gemini-1.5-flash":     {"provider": "gemini", "model": "gemini-1.5-flash"},
    "llama-3.1-8b-instant": {"provider": "groq",   "model": "llama-3.1-8b-instant"},
}
DEFAULT_MODEL = "gemini-2.5-flash"

otp_store: dict = {}
OTP_TTL = 300 

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def sheet_request(data: dict) -> dict:
    if not GOOGLE_SCRIPT_URL: return {"success": False, "message": "Database URL missing"}
    try:
        r = requests.post(GOOGLE_SCRIPT_URL, json=data, timeout=15)
        return r.json()
    except Exception as e:
        return {"success": False, "message": str(e)}

def send_otp_email(name: str, email: str, otp: str, purpose: str) -> tuple:
    if not SMTP_EMAIL or not SMTP_APP_PASSWORD: return False, "SMTP Error"
    try:
        body = f"Hi {name},\n\nYour OTP for {purpose} is: {otp}\n\nValid for 5 minutes."
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = f"NexusAI {purpose} Code"
        msg["From"] = f"NexusAI <{SMTP_EMAIL}>"
        msg["To"] = email
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=15) as smtp:
            smtp.login(SMTP_EMAIL, SMTP_APP_PASSWORD)
            smtp.send_message(msg)
        return True, "Sent"
    except Exception as e:
        return False, str(e)

# MODELS
class SendOTPRequest(BaseModel): name: str; email: str
class VerifyOTPRequest(BaseModel): email: str; otp: str
class SavePasswordRequest(BaseModel): email: str; password: str
class LoginRequest(BaseModel): email: str; password: str
class ForgotPasswordRequest(BaseModel): email: str
class ResetPasswordRequest(BaseModel): email: str; otp: str; new_password: str
class HistoryItem(BaseModel): role: str; content: str
class ChatRequest(BaseModel):
    message: str
    model: Optional[str] = DEFAULT_MODEL
    history: Optional[List[HistoryItem]] = []
class ImageGenRequest(BaseModel): prompt: str

# ROUTES
@app.post("/send-otp")
def api_send_otp(data: SendOTPRequest):
    email = data.email.strip().lower()
    if sheet_request({"action": "login", "email": email}).get("success"):
        return {"success": False, "message": "User already exists"}
    otp = str(random.randint(100000, 999999))
    otp_store[email] = {"otp": otp, "name": data.name, "expires_at": time.time() + OTP_TTL, "verified": False}
    ok, msg = send_otp_email(data.name, email, otp, "Verification")
    return {"success": ok, "message": "OTP Sent" if ok else msg}

@app.post("/verify-otp")
def api_verify_otp(data: VerifyOTPRequest):
    email = data.email.strip().lower()
    pending = otp_store.get(email)
    if not pending or time.time() > pending["expires_at"]: return {"success": False, "message": "Expired"}
    if data.otp.strip() != pending["otp"]: return {"success": False, "message": "Wrong OTP"}
    otp_store[email]["verified"] = True
    return {"success": True}

@app.post("/save-password")
def api_save_password(data: SavePasswordRequest):
    email = data.email.strip().lower()
    pending = otp_store.get(email)
    if not pending or not pending.get("verified"): return {"success": False, "message": "Unauthorized"}
    res = sheet_request({"action": "saveUser", "name": pending["name"], "email": email, "passwordHash": hash_password(data.password), "status": "active"})
    if res.get("success"):
        del otp_store[email]
        return {"success": True, "name": pending["name"]}
    return {"success": False, "message": "Error saving"}

@app.post("/login")
def api_login(data: LoginRequest):
    user = sheet_request({"action": "login", "email": data.email.strip().lower()})
    if not user.get("success"): return {"success": False, "message": "User not found"}
    if hash_password(data.password) != user.get("passwordHash"): return {"success": False, "message": "Wrong Password"}
    return {"success": True, "name": user.get("name")}

@app.post("/forgot-password-otp")
def forgot_otp(data: ForgotPasswordRequest):
    email = data.email.strip().lower()
    user = sheet_request({"action": "login", "email": email})
    if not user.get("success"): return {"success": False, "message": "No account found"}
    otp = str(random.randint(100000, 999999))
    otp_store[email] = {"otp": otp, "name": user.get("name"), "expires_at": time.time() + OTP_TTL, "verified": False}
    ok, msg = send_otp_email(user.get("name"), email, otp, "Password Reset")
    return {"success": ok, "message": "OTP Sent" if ok else msg}

@app.post("/reset-password")
def reset_pw(data: ResetPasswordRequest):
    email = data.email.strip().lower()
    pending = otp_store.get(email)
    if not pending or data.otp.strip() != pending["otp"]: return {"success": False, "message": "Invalid OTP"}
    res = sheet_request({"action": "updatePassword", "email": email, "passwordHash": hash_password(data.new_password)})
    if res.get("success"):
        del otp_store[email]
        return {"success": True}
    return {"success": False, "message": "Failed"}

@app.post("/chat")
def chat_api(data: ChatRequest):
    model_key = data.model if data.model in MODEL_MAP else DEFAULT_MODEL
    info = MODEL_MAP[model_key]
    try:
        if info["provider"] == "gemini":
            prompt = "".join([f"{'User' if h.role=='user' else 'Assistant'}: {h.content}\n" for h in data.history]) + f"User: {data.message}\nAssistant:"
            reply = gemini_client.models.generate_content(model=info["model"], contents=prompt.strip()).text
        else:
            msg_list = [{"role": h.role, "content": h.content} for h in data.history] + [{"role": "user", "content": data.message}]
            reply = groq_client.chat.completions.create(model=info["model"], messages=msg_list).choices[0].message.content
        return {"response": reply, "reply": reply}
    except Exception as e:
        return {"response": f"Error: {e}", "reply": f"Error: {e}"}

@app.post("/generate-image")
def img_api(data: ImageGenRequest):
    if not HF_API_KEY: return {"success": False, "message": "API Key Missing"}
    try:
        r = requests.post(f"https://api-inference.huggingface.co/models/{HF_MODEL}", headers={"Authorization": f"Bearer {HF_API_KEY}"}, json={"inputs": data.prompt}, timeout=30)
        if r.status_code == 200:
            return {"success": True, "image": f"data:image/jpeg;base64,{base64.b64encode(r.content).decode()}"}
        return {"success": False, "message": "Model busy, retry."}
    except Exception as e:
        return {"success": False, "message": str(e)}

@app.get("/")
def serve_home(): return FileResponse(str(BASE_DIR / "index.html"))

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))