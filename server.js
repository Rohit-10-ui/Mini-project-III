require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("./passport"); 
const path = require("path");
const bcrypt = require("bcryptjs");
const User = require("./models/Users"); // make sure filename matches exactly

const app = express();
const PORT = 3019;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "supersecret",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

// MongoDB connection
mongoose
  .connect("mongodb://localhost:27017/mydb", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB error:", err));

// -------- ROUTES --------

// Dynamic homepage: shows username if logged in
app.get("/", (req, res) => {
  if (req.isAuthenticated()) {
    res.send(`
      <html>
        <head><title>PHISHGUARD - Home</title></head>
        <body style="font-family: Arial, sans-serif; text-align: center; margin-top: 50px;">
          <h1>Welcome, ${req.user.name || req.user.email.split("@")[0]} 👋</h1>
          <p>You are now inside PHISHGUARD.</p>
          <a href="/logout" style="display:inline-block; margin-top:20px; padding:10px 20px; background:#c62828; color:white; text-decoration:none; border-radius:5px;">Logout</a>
        </body>
      </html>
    `);
  } else {
    res.sendFile(path.join(__dirname, "homepage.html"));
  }
});

// Keep /homepage route (optional)
app.get("/homepage", (req, res) => {
  res.redirect("/"); // just redirect to main homepage
});

// Auth pages
app.get("/signup", (req, res) => res.sendFile(path.join(__dirname, "signup.html")));
app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "login.html")));
app.get("/phishing", (req, res) => res.sendFile(path.join(__dirname, "phishing.html")));

// Signup API
app.post("/api/signup", async (req, res) => {
  const { email, password } = req.body;
  try {
    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ message: "Email already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: "Signup success" });
  } catch (err) {
    res.status(500).json({ message: "Signup error", error: err.message });
  }
});

// Login API
app.post("/api/login", passport.authenticate("local"), (req, res) => {
  res.status(200).json({ 
    message: "Login success", 
    username: req.user.name || req.user.email.split("@")[0] 
  });
});

// Google OAuth
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => res.redirect("/")
);

// Return currently logged-in user
app.get("/api/current_user", (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ loggedIn: true, username: req.user.name || req.user.email.split("@")[0] });
  } else {
    res.json({ loggedIn: false });
  }
});


// Logout
app.get("/logout", (req, res) => {
  req.logout(() => {
    res.redirect("/");
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
