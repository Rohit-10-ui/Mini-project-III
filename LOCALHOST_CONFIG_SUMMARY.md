# 🏠 Localhost Configuration Summary

## ✅ All Files Have Been Converted to Localhost!

Your project is now fully configured for **localhost development**. All Render deployment configurations have been **commented out** and marked with `// RENDER DEPLOYMENT` or `# RENDER DEPLOYMENT`.

---

## 📋 Configuration Status

### ✅ **server.js** (Node.js/Express Server)
- **Port**: `3000` (localhost)
- **Flask URL**: `http://localhost:7000` (hardcoded)
- **MongoDB**: `mongodb://localhost:27017/phishguard` (with fallback)
- **Trust Proxy**: Disabled (commented out)
- **Cookie Secure**: `false` (HTTP mode)
- **Listen**: `localhost` only (not `0.0.0.0`)
- **Deployment configs**: All commented with `// RENDER DEPLOYMENT`

### ✅ **app.py** (Flask AI Service)
- **Port**: `7000` (localhost)
- **Host**: `127.0.0.1` (localhost only, not `0.0.0.0`)
- **Debug Mode**: `true` (enabled for development)
- **CORS**: Allows `http://localhost:3000` and `http://127.0.0.1:3000`
- **MongoDB**: `mongodb://localhost:27017/phishguard` (with fallback)
- **Deployment configs**: All commented with `# RENDER DEPLOYMENT`

### ✅ **passport.js** (Google OAuth)
- **Callback URL**: `http://localhost:3000/auth/google/callback` (hardcoded)
- **Deployment config**: Commented with `// RENDER DEPLOYMENT`

### ✅ **.env.example**
- **Localhost configs**: Active at the top
- **Render configs**: Commented out at the bottom
- Clear separation with section headers

---

## 🚀 How to Run Locally

### 1. **Start MongoDB**
```bash
# Make sure MongoDB is running on localhost:27017
mongod
```

### 2. **Start Flask AI Service** (Terminal 1)
```bash
python app.py
# Runs on: http://localhost:7000
```

### 3. **Start Node.js Server** (Terminal 2)
```bash
node server.js
# Runs on: http://localhost:3000
```

### 4. **Access the Application**
- Homepage: `http://localhost:3000`
- Login: `http://localhost:3000/login`
- Phishing Detector: `http://localhost:3000/phishing`
- Dashboard: `http://localhost:3000/dashboard`

---

## 🔧 Environment Variables (.env file)

Create a `.env` file with these localhost settings:

```bash
# MongoDB
MONGODB_URI=mongodb://localhost:27017/phishguard

# Flask Service
FLASK_URL=http://localhost:7000

# Session
SESSION_SECRET=supersecret-change-in-production

# Google OAuth (optional)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# Development mode
NODE_ENV=development
```

---

## 🔄 Switching to Render Deployment (When Ready)

To deploy to Render later, you just need to:

### **server.js**
Uncomment these lines and comment the localhost versions:
```javascript
// Line 6: FLASK_URL
const FLASK_URL = process.env.FLASK_URL || process.env.FLASK_SERVICE_URL; // RENDER

// Line 33: Trust proxy
app.set('trust proxy', 1); // RENDER

// Line 43: Cookie secure
secure: process.env.NODE_ENV === 'production', // RENDER

// Line 69: Exit on DB failure
process.exit(1); // RENDER

// Line 385: Listen on all interfaces
app.listen(port, '0.0.0.0', () => { // RENDER
```

### **app.py**
Uncomment these lines:
```python
# Line 59: CORS
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",") # RENDER

# Line 64: MongoDB
MONGODB_URI = os.getenv("MONGODB_URI") # RENDER

# Line 275: Host
app.run(debug=False, host="0.0.0.0", port=port) # RENDER
```

### **passport.js**
Uncomment line 30:
```javascript
callbackURL: process.env.GOOGLE_CALLBACK_URL || "http://localhost:3000/auth/google/callback", // RENDER
```

---

## 📝 Key Differences: Localhost vs Render

| Feature | Localhost | Render Deployment |
|---------|-----------|-------------------|
| **Port** | Hardcoded (3000, 7000) | From `process.env.PORT` |
| **Host** | `localhost`/`127.0.0.1` | `0.0.0.0` (all interfaces) |
| **FLASK_URL** | `http://localhost:7000` | From environment variable |
| **MongoDB** | `mongodb://localhost:27017` | MongoDB Atlas URI |
| **CORS** | `localhost:3000` only | Multiple origins |
| **Debug** | `true` (Flask) | `false` |
| **Cookie Secure** | `false` (HTTP) | `true` (HTTPS) |
| **Trust Proxy** | Disabled | Enabled |
| **Error Exit** | Continue without DB | Exit on failure |

---

## ✅ Testing Checklist

- [ ] MongoDB is running locally
- [ ] Flask service starts on port 7000
- [ ] Node.js server starts on port 3000
- [ ] Can access homepage at `http://localhost:3000`
- [ ] Can signup/login with email
- [ ] Can scan URLs in phishing detector
- [ ] Dashboard shows scan history
- [ ] No CORS errors in browser console

---

## 🎯 Next Steps for Development

1. **Test all features locally** before adding new ones
2. **Keep Render configs commented** until ready to deploy
3. **Use separate `.env` files** for local and production
4. **Run both services** (Flask + Node) simultaneously
5. **Check MongoDB** is populated with data

---

## 🆘 Common Issues

### "Cannot connect to MongoDB"
- Make sure MongoDB is running: `mongod`
- Check if port 27017 is in use: `netstat -an | findstr 27017`

### "Flask service not available"
- Verify Flask is running on port 7000
- Check `http://localhost:7000/health`

### "CORS error"
- Verify Flask `ALLOWED_ORIGINS` includes `http://localhost:3000`
- Check browser console for exact error

### "Google OAuth not working"
- Update Google Console redirect URI to `http://localhost:3000/auth/google/callback`
- Verify `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in `.env`

---

## 📁 Modified Files Summary

✅ **server.js** - Localhost on port 3000, Render configs commented  
✅ **app.py** - Localhost on port 7000, Render configs commented  
✅ **passport.js** - Localhost callback URL, Render config commented  
✅ **.env.example** - Localhost configs active, Render configs commented  

---

**All files are now ready for localhost development! 🎉**

Just start MongoDB, then Flask, then Node.js, and you're good to go!
