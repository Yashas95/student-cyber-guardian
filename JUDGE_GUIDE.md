# 👨‍⚖️ Judge Guide — Student Cyber Guardian

Welcome! **Student Cyber Guardian** is a privacy-first, community-driven threat detection system built for students, by students. It transforms the internet into a safer place through anonymous, collective intelligence.

## 🚀 Quick Installation (Run Locally)

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Yashas95/student-cyber-guardian.git
   cd student-cyber-guardian
   ```

2. **Build the Extension**:
   ```bash
   cd extension
   npm install
   npm run build
   ```

3. **Load in Chrome**:
   - Open `chrome://extensions/`
   - Enable **Developer mode** (top right)
   - Click **Load unpacked**
   - Select the `extension/dist` folder

4. **Access the Dashboard**:
   - [Live Campus Pulse Dashboard](https://yashas95.github.io/campus-pulse-dashboard/?campus=mit)

---

## 🛡️ Key Features to Judge

### 1. Campus Pulse (Community Protection)
When 3 independent students encounter a high-severity threat (like a campus-wide phishing campaign), our **FastAPI backend** automatically escalates it to a **Campus Alert**. Every student on that campus receives an instant, animated whisper toast.

### 2. Privacy by Design
Cybersecurity shouldn't come at the cost of privacy. Our "Campus Pulse" system is strictly anonymous:
- **No PII collected**: We never send names, emails, IPs, or full URLs.
- **SHA-256 Hashing**: Hostnames are hashed (first 8 chars only) before transmission.
- **Hourly Rounding**: Timestamps are rounded to the hour to prevent timing-based identification.
- **Rotating Tokens**: Session tokens rotate every 24 hours.

### 3. Friendly Persona (The "Guardian")
Unlike typical blockers that use alarmist language, the Guardian uses a supportive, knowledgeable tone. It doesn't just block; it explains and advises, turning every threat into a "teaching moment."

### 4. Live IT Dashboard
A real-time, dark-themed dashboard for university IT admins to monitor campus-wide threat cycles without seeing student data. Accessible with any campus ID (e.g., `?campus=stanford`, `?campus=iit-bombay`).

---

## 🛠️ Stack
- **Frontend**: TypeScript (Chrome Extension MV3), HTML5, Vanilla CSS
- **Backend**: FastAPI (Python), Pydantic, Uvicorn
- **Deployment**: GitHub Pages (Dashboard), Render (API)

---

## 💡 The "Why"
Most students ignore security warnings because they are technical and scary. **Student Cyber Guardian** bridges this gap by being your "smartest friend online," protecting you through the power of your community.
