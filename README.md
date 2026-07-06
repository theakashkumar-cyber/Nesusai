# NexusAI Pro 🚀

NexusAI Pro ek powerful, full-stack AI workspace hai jahan users authentication (OTP-based signup/login) ke sath AI Chat aur Image Generation ka maza le sakte hain. Is project ki sabse khas baat yeh hai ki iska database ek **Google Sheet** hai, jisse yeh bohot lightweight aur manage karne mein aasan banta hai.

---

## ✨ Features

*   🔐 **Secure Authentication:** Email verification ke liye secure SMTP SSL ke sath 6-digit OTP system.
*   🔑 **Forgot Password Flow:** Agar password bhool jayein, toh OTP ke zariye naya password set karne ki suvidha.
*   💬 **Advanced AI Chat:** Gemini 2.5 Flash, Gemini 1.5 Flash, aur Llama 3.1 (Groq) models ka support chat history ke sath.
*   🎨 **AI Image Generator:** Hugging Face Inference API (Stable Diffusion XL) ka use karke text se images generate karna.
*   📊 **Google Sheet Database:** Bina kisi complex SQL/NoSQL database ke, Google Apps Script ke zariye direct Google Sheet mein user data save aur read karna.
*   🌐 **All-in-One Deployment:** FastAPI backend hi frontend (`index.html`) ko serve karta hai, jisse deployment super easy ho jata hai.

---

## 🛠️ Tech Stack

*   **Backend:** FastAPI (Python), Uvicorn
*   **Frontend:** HTML5, Tailwind CSS, JavaScript (Vanilla)
*   **Database:** Google Sheets + Google Apps Script
*   **AI Models:** Google Gemini API, Groq Cloud API, Hugging Face API
*   **Deployment Platform:** Render

---

## 🚀 Local Setup Instructions

Apne computer par is project ko chalane ke liye yeh steps follow karein:

1. **Repository ko clone ya download karein:**
   ```bash
   git clone [https://github.com/theakashkumar-cyber/Nesusai/.git](https://github.com/your-username/NexusAI.git)
   cd NexusAI
