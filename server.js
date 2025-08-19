const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const path = require('path');
const app = express();
const PORT = 3019;
app.use(express.static(__dirname));
mongoose.connect('mongodb://localhost:27017/phishguard', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});
const db = mongoose.connection;
db.once('open', () => console.log("✅ MongoDB connected"));
const userSchema = new mongoose.Schema({
  email: String,
  password: String
});
const User = mongoose.model('User', userSchema);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.get('/', (req, res) =>
  res.sendFile(path.join(__dirname, 'homepage.html'))
);

app.get('/signup', (req, res) =>
  res.sendFile(path.join(__dirname, 'signup.html'))
);

app.get('/login', (req, res) =>
  res.sendFile(path.join(__dirname, 'login.html'))
);
app.post('/api/signup', async (req, res) => {
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
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: "Invalid password" });

    const username = email.split('@')[0];
    res.status(200).json({ message: "Login success", username });
  } catch (err) {
    res.status(500).json({ message: "Login error", error: err.message });
  }
});
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
