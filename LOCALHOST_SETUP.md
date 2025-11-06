# PhishGuard - Localhost Setup Guide

## ✅ All Files Updated for Localhost

The following files have been configured to run on localhost:

### 1. **server.js** (Node.js Backend)
- Port: `3000`
- Host: `localhost`
- Flask URL: `http://localhost:7000`
- MongoDB: `mongodb://localhost:27017/phishguard`
- Cookie secure: `false` (for localhost)

### 2. **app.py** (Flask AI Service)
- Port: `7000`
- Host: `localhost`
- CORS: `http://localhost:3000`
- Debug mode: `True`

### 3. **passport.js** (Authentication)
- Google OAuth callback: `http://localhost:3000/auth/google/callback`

### 4. **phishing.html** (Enhanced)
- Real-time feature scanning progress display
- 10 feature trackers with visual indicators
- Animated progress updates

### 5. **.env.example** (Configuration Template)
- Localhost defaults configured
- Render deployment settings commented out

---

## 🚀 How to Run Locally

### Prerequisites
- Node.js installed
- Python 3.x installed
- MongoDB installed and running

### Step 1: Install Dependencies

```bash
# Install Node.js dependencies
npm install

# Install Python dependencies
pip install -r requirements.txt
```

### Step 2: Setup Environment Variables

Copy `.env.example` to `.env` (or use the default localhost values):

```bash
cp .env.example .env
```

**Optional:** If using Google OAuth, add your credentials to `.env`:
```
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
```

### Step 3: Start MongoDB

```bash
# Start MongoDB service
mongod
```

Or if using MongoDB as a service, ensure it's running on `mongodb://localhost:27017`

### Step 4: Start Flask AI Service

```bash
# In one terminal
python app.py
```

This will start the Flask server on `http://localhost:7000`

### Step 5: Start Node.js Server

```bash
# In another terminal
node server.js
```

This will start the Node.js server on `http://localhost:3000`

### Step 6: Access the Application

Open your browser and navigate to:
```
http://localhost:3000
```

---

## 🎯 Features

### Enhanced Phishing Scanner
The phishing page now shows real-time progress of feature extraction:

1. **IP Address Check** - Verifies if URL uses IP instead of domain
2. **Subdomain Analysis** - Analyzes subdomain structure
3. **SSL Certificate** - Checks HTTPS and SSL validity
4. **Domain Registration** - Verifies registration length
5. **External Resources** - Analyzes external resource requests
6. **Anchor URLs** - Examines anchor link patterns
7. **Meta Tags & Links** - Checks links in meta tags
8. **Form Handlers** - Analyzes server form handlers
9. **Domain Age** - Checks domain age
10. **DNS Records** - Verifies DNS record existence

Each feature displays:
- 🔍 Scanning (animated)
- ✅ Completed (green)
- ⚠️ Suspicious (orange)
- 🚨 Risk Detected (red)

---

## 🔄 Switching to Render Deployment

When ready to deploy to Render:

1. **Uncomment Render configurations** in:
   - `server.js` (lines with RENDER DEPLOYMENT CONFIGURATION)
   - `app.py` (lines with RENDER DEPLOYMENT CONFIGURATION)
   - `passport.js` (Google OAuth callback URL)

2. **Comment out localhost configurations**

3. **Set environment variables on Render**:
   - `MONGODB_URI` (MongoDB Atlas connection string)
   - `FLASK_URL` (Your Flask service URL on Render)
   - `GOOGLE_CLIENT_ID` (if using Google OAuth)
   - `GOOGLE_CLIENT_SECRET` (if using Google OAuth)
   - `GOOGLE_CALLBACK_URL` (Your production callback URL)
   - `SESSION_SECRET` (Strong random string)
   - `ALLOWED_ORIGINS` (Your frontend URLs)

---

## 📝 Notes

- All Render-specific code is commented with `===== RENDER DEPLOYMENT CONFIGURATION =====`
- All localhost code is marked with `===== LOCALHOST CONFIGURATION =====`
- MongoDB connection will fail gracefully if not available
- Flask service connection will show warnings if not available
- Google OAuth is optional for local development

---

## 🐛 Troubleshooting

### MongoDB Connection Failed
- Ensure MongoDB is running: `mongod`
- Check if MongoDB is on port 27017
- Verify connection string in `.env`

### Flask Service Unavailable
- Ensure Flask is running: `python app.py`
- Check if Flask is on port 7000
- Verify FLASK_URL in `.env` or server.js

### Google OAuth Not Working
- Add credentials to `.env`
- Configure callback URL in Google Cloud Console
- Ensure callback URL matches: `http://localhost:3000/auth/google/callback`

---

## 📦 Project Structure

```
Mini-project-III/
├── server.js              # Node.js backend (localhost configured)
├── app.py                 # Flask AI service (localhost configured)
├── passport.js            # Authentication (localhost configured)
├── phishing.html          # Enhanced with real-time progress
├── dashboard.html         # Dashboard page
├── homepage.html          # Landing page
├── login.html             # Login page
├── signup.html            # Signup page
├── .env.example           # Environment variables template
├── models/                # Database models
├── datasets/              # Training data
└── requirements.txt       # Python dependencies
```

---

**Happy Coding! 🚀**
