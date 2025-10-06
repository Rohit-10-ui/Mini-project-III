require("dotenv").config();

// Flask service URL - MUST be set as environment variable on Render
const FLASK_URL = process.env.FLASK_URL || process.env.FLASK_SERVICE_URL;

if (!FLASK_URL) {
  console.error("⚠️ WARNING: FLASK_URL not set! AI features will not work.");
  console.error("Set FLASK_URL to your Flask service URL on Render");
}

const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("./passport");
const path = require("path");
const bcrypt = require("bcryptjs");
const axios = require("axios");
const User = require("./models/Users");
const UrlCheck = require("./models/UrlCheck");

const app = express();
// Render provides PORT environment variable
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "supersecret-change-in-production",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 24 * 60 * 60 * 1000,
      secure: process.env.NODE_ENV === 'production', // HTTPS only in production
      httpOnly: true
    }
  })
);

app.use(passport.initialize());
app.use(passport.session());

// MongoDB connection - REQUIRED on Render
const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  console.error("❌ FATAL: MONGODB_URI not set!");
  console.error("Please set MONGODB_URI environment variable on Render");
  process.exit(1);
}

mongoose
  .connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✓ MongoDB connected"))
  .catch((err) => {
    console.error("❌ MongoDB connection failed:", err.message);
    process.exit(1);
  });

app.get("/", (req, res) => {
  if (req.isAuthenticated()) {
    res.send(`
      <html>
        <head><title>PHISHGUARD - Home</title></head>
        <body style="font-family: Arial, sans-serif; text-align: center; margin-top: 50px;">
          <h1>Welcome, ${req.user.name || req.user.email.split("@")[0]} 👋</h1>
          <p>You are now inside PHISHGUARD.</p>
          <div style="margin-top: 30px;">
            <a href="/phishing" style="display:inline-block; margin:10px; padding:15px 30px; background:#2e7d32; color:white; text-decoration:none; border-radius:5px;">🛡️ Scan URLs</a>
            <a href="/dashboard" style="display:inline-block; margin:10px; padding:15px 30px; background:#1976d2; color:white; text-decoration:none; border-radius:5px;">📊 Dashboard</a>
            <a href="/logout" style="display:inline-block; margin:10px; padding:15px 30px; background:#c62828; color:white; text-decoration:none; border-radius:5px;">Logout</a>
          </div>
        </body>
      </html>
    `);
  } else {
    res.sendFile(path.join(__dirname, "homepage.html"));
  }
});

app.get("/homepage", (req, res) => res.sendFile(path.join(__dirname, "homepage.html")));
app.get("/signup", (req, res) => res.sendFile(path.join(__dirname, "signup.html")));
app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "login.html")));
app.get("/phishing", (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/login");
  }
  res.sendFile(path.join(__dirname, "phishing.html"));
});
app.get("/dashboard", (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/login");
  }
  res.sendFile(path.join(__dirname, "dashboard.html"));
});

app.post("/api/signup", async (req, res) => {
  const { email, password, name } = req.body;
  try {
    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ message: "Email already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ email, password: hashedPassword, name });
    await newUser.save();

    res.status(201).json({ message: "Signup success" });
  } catch (err) {
    res.status(500).json({ message: "Signup error", error: err.message });
  }
});

app.post("/api/login", passport.authenticate("local"), (req, res) => {
  res.status(200).json({
    message: "Login success",
    username: req.user.name || req.user.email.split("@")[0],
  });
});

app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => res.redirect("/")
);

app.get("/api/current_user", (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ 
      loggedIn: true, 
      username: req.user.name || req.user.email.split("@")[0],
      email: req.user.email
    });
  } else {
    res.json({ loggedIn: false });
  }
});

app.post("/api/scan-url", async (req, res) => {
  try {
    const { url } = req.body;
    
    if (!url) {
      return res.status(400).json({ message: "URL is required" });
    }

    if (!FLASK_URL) {
      return res.status(503).json({
        message: "AI service is not configured. Please contact administrator.",
        error: "FLASK_SERVICE_NOT_CONFIGURED"
      });
    }

    console.log(`Scanning URL: ${url}`);
    console.log(`Flask service: ${FLASK_URL}`);

    const flaskResponse = await axios.post(`${FLASK_URL}/predict`, {
      url: url,
      user: req.isAuthenticated() ? req.user._id.toString() : 'anonymous'
    }, {
      timeout: 30000, // 30 second timeout
      headers: {
        'Content-Type': 'application/json'
      }
    });

    const result = flaskResponse.data;
    console.log(`Flask result: ${result.prediction} (${result.confidence}%)`);

    if (req.isAuthenticated()) {
      try {
        const newCheck = new UrlCheck({
          userId: req.user._id,
          type: 'url',
          text: url,  
          url: url,   
          user: req.user._id,  
          prediction: result.prediction,
          confidence: result.confidence,
          date: new Date()
        });

        await newCheck.save();
        console.log(`✓ Saved to database`);
      } catch (dbError) {
        console.error(`DB save error:`, dbError.message);
      }
    }

    res.json({
      url: url,
      prediction: result.prediction,
      confidence: result.confidence,
      timestamp: new Date().toISOString(),
      message: result.prediction === 'phishing' ? 
        'Potential phishing site detected!' : 
        'URL appears to be legitimate.'
    });

  } catch (error) {
    console.error("Scan error:", error.message);

    if (error.code === 'ECONNREFUSED' || error.code === 'ETIMEDOUT') {
      return res.status(503).json({
        message: "AI service is currently unavailable. Please try again later.",
        error: "SERVICE_UNAVAILABLE"
      });
    }

    if (error.response?.status >= 500) {
      return res.status(503).json({
        message: "AI service encountered an error. Please try again.",
        error: "SERVICE_ERROR"
      });
    }

    res.status(500).json({
      message: "Scan failed: " + error.message,
      error: "SCAN_FAILED"
    });
  }
});

app.get("/api/recent-scans", async (req, res) => {
  try {
    if (!req.isAuthenticated()) {
      return res.json({ scans: [], message: "Login to see scan history", total: 0 });
    }

    const recentScans = await UrlCheck.find({ user: req.user._id })  
      .sort({ checkedAt: -1 })  
      .limit(10)
      .select('url prediction confidence checkedAt');

    const totalScans = await UrlCheck.countDocuments({ userId: req.user._id });
    const phishingCount = await UrlCheck.countDocuments({ 
      userId: req.user._id, 
      prediction: 'phishing' 
    });

    res.json({ 
      scans: recentScans,
      total: totalScans,
      phishingFound: phishingCount,
      legitimateFound: totalScans - phishingCount
    });

  } catch (error) {
    console.error("Error fetching scans:", error);
    res.status(500).json({ message: "Error fetching scan history" });
  }
});

app.get("/api/all-scans", async (req, res) => {
  try {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    console.log("Fetching scans for user:", req.user._id);

    const allScans = await UrlCheck.find({ user: req.user._id })  
      .sort({ checkedAt: -1 })  
      .limit(20);

    console.log("Found scans:", allScans.length);

    res.json({
      scans: allScans,
      pagination: {
        totalItems: allScans.length
      }
    });

  } catch (error) {
    console.error("Error fetching all scans:", error);
    res.status(500).json({ message: "Error fetching scan history" });
  }
});

app.delete("/api/delete-scan/:scanId", async (req, res) => {
  try {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const { scanId } = req.params;
    
    const result = await UrlCheck.findOneAndDelete({
      _id: scanId,
      userId: req.user._id 
    });

    if (!result) {
      return res.status(404).json({ message: "Scan not found or unauthorized" });
    }

    res.json({ message: "Scan deleted successfully" });

  } catch (error) {
    console.error("Error deleting scan:", error);
    res.status(500).json({ message: "Error deleting scan" });
  }
});

app.post("/api/save-check", async (req, res) => {
  try {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const { type, text, prediction, confidence } = req.body;

    const newCheck = new UrlCheck({
      userId: req.user._id,
      type,
      text,
      prediction,
      confidence,
      date: new Date(),
    });

    await newCheck.save();

    res.status(201).json({ message: "Check saved", check: newCheck });
  } catch (err) {
    console.error("Error saving check:", err);
    res.status(500).json({ message: "Error saving check", error: err.message });
  }
});

app.get("/api/health", async (req, res) => {
  try {
    let flaskStatus = 'offline';
    let flaskError = null;
    
    if (FLASK_URL) {
      try {
        const flaskResponse = await axios.get(`${FLASK_URL}/health`, { timeout: 5000 });
        flaskStatus = flaskResponse.status === 200 ? 'online' : 'offline';
      } catch (error) {
        flaskStatus = 'offline';
        flaskError = error.message;
      }
    }

    const mongoStatus = mongoose.connection.readyState === 1 ? 'online' : 'offline';

    res.json({
      status: 'online',
      services: {
        nodejs: 'online',
        mongodb: mongoStatus,
        flask_ai: flaskStatus
      },
      flaskUrl: FLASK_URL || 'not configured',
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    res.status(500).json({
      status: 'error',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

app.get("/logout", (req, res) => {
  req.logout(() => {
    res.redirect("/");
  });
});

app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
  });
});

app.use((req, res) => {
  res.status(404).json({ message: 'Page not found' });
});

app.listen(port, '0.0.0.0', () => {
  console.log("\n" + "=".repeat(60));
  console.log("PHISHGUARD SERVER");
  console.log("=".repeat(60));
  console.log(`Server running on port ${port}`);
  console.log(`MongoDB: ${mongoose.connection.readyState === 1 ? '✓ Connected' : '✗ Disconnected'}`);
  console.log(`Flask AI: ${FLASK_URL ? '✓ Configured' : '✗ Not configured'}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log("=".repeat(60) + "\n");
});
