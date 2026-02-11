require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");

const app = express();

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
app.get("/patients", async (req, res) => {
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
const PORT = 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
