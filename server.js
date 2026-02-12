require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");

const app = express();

const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const User = require("./models/User");

const JWT_SECRET = "asoka_secret_key";

app.use(cors());
app.use(express.json());

/* ---------- MongoDB Connection ---------- */
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.log(err));

/* ---------- Schema ---------- */
const patientSchema = new mongoose.Schema({
  name: String,
  phone: String,
  healthHistory: String,
});

const Patient = mongoose.model("Patient", patientSchema);

/* ---------- Routes ---------- */

// Get all patients
app.get("/patients", auth, async (req, res) => {
  const patients = await Patient.find();
  res.json(patients);
});

// Add patient
app.post("/patients", async (req, res) => {
  const newPatient = new Patient(req.body);
  await newPatient.save();
  res.json(newPatient);
});

// Update patient
app.put("/patients/:id", async (req, res) => {
  const updated = await Patient.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
  });
  res.json(updated);
});

// Delete patient
app.delete("/patients/:id", async (req, res) => {
  await Patient.findByIdAndDelete(req.params.id);
  res.json({ success: true });
});

/* ---------- Server ---------- */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  const hashed = await bcrypt.hash(password, 10);

  const user = new User({ username, password: hashed });
  await user.save();

  res.json({ message: "User created" });
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username });
  if (!user) return res.status(400).json({ message: "User not found" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ message: "Wrong password" });

  const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "1d" });

  res.json({ token });
});

function auth(req, res, next) {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ message: "No token" });

  try {
    jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
}