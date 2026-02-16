require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const PDFDocument = require("pdfkit");

const app = express();

const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const User = require("./models/User");

const JWT_SECRET = "asoka_secret_key";

app.use(cors());
app.use(express.json());

const uploadsRoot = path.join(__dirname, "uploads");
const labsUploadDir = path.join(uploadsRoot, "labs");
const signaturesUploadDir = path.join(uploadsRoot, "signatures");

function ensureUploadDirs() {
  [uploadsRoot, labsUploadDir, signaturesUploadDir].forEach((dirPath) => {
    if (!fs.existsSync(dirPath)) {
      fs.mkdirSync(dirPath, { recursive: true });
    }
  });
}

ensureUploadDirs();
app.use("/uploads", express.static(uploadsRoot));

function createUploader(destination, allowedMimeTypes) {
  const storage = multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, destination),
    filename: (_req, file, cb) => {
      const safeOriginalName = file.originalname
        .toLowerCase()
        .replace(/[^a-z0-9.\-_]/g, "_")
        .slice(-80);
      cb(null, `${Date.now()}-${safeOriginalName}`);
    },
  });

  return multer({
    storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
    fileFilter: (_req, file, cb) => {
      if (!allowedMimeTypes.includes(file.mimetype)) {
        return cb(new Error("Unsupported file type"));
      }
      cb(null, true);
    },
  });
}

const uploadLabFile = createUploader(labsUploadDir, [
  "application/pdf",
  "image/png",
  "image/jpeg",
  "image/webp",
]);

const uploadSignatureFile = createUploader(signaturesUploadDir, [
  "image/png",
  "image/jpeg",
  "image/webp",
]);

function buildPublicFileUrl(req, folder, filename) {
  return `${req.protocol}://${req.get("host")}/uploads/${folder}/${filename}`;
}

function safeText(value) {
  if (value === undefined || value === null) return "-";
  const str = String(value).trim();
  return str || "-";
}

function drawLabelValue(doc, label, value, x, y, labelWidth = 110, lineHeight = 16) {
  doc.font("Helvetica-Bold").fontSize(10).text(`${label}:`, x, y, {
    width: labelWidth,
  });
  doc.font("Helvetica").fontSize(10).text(safeText(value), x + labelWidth, y, {
    width: 440 - labelWidth,
  });
  return y + lineHeight;
}

function ensurePageSpace(doc, y, requiredHeight = 80) {
  if (y + requiredHeight <= doc.page.height - 50) {
    return y;
  }

  doc.addPage();
  return 50;
}

function mapPublicUrlToLocalPath(fileUrl) {
  if (!fileUrl) return null;

  try {
    const parsed = new URL(fileUrl);
    if (!parsed.pathname.startsWith("/uploads/")) return null;

    const cleanedRelative = parsed.pathname.replace(/^\/uploads\//, "");
    const normalized = path.normalize(cleanedRelative);

    if (normalized.includes("..")) return null;

    return path.join(uploadsRoot, normalized);
  } catch {
    return null;
  }
}

function tryDrawSignature(doc, signatureUrl, x, y) {
  const signaturePath = mapPublicUrlToLocalPath(signatureUrl);
  if (!signaturePath || !fs.existsSync(signaturePath)) {
    doc.font("Helvetica").fontSize(10).text("Doctor signature: Not available", x, y);
    return y + 18;
  }

  try {
    doc.font("Helvetica").fontSize(10).text("Doctor Signature:", x, y);
    doc.image(signaturePath, x, y + 12, {
      fit: [180, 70],
      align: "left",
      valign: "top",
    });
    return y + 90;
  } catch {
    doc.font("Helvetica").fontSize(10).text("Doctor signature: Unable to render", x, y);
    return y + 18;
  }
}

function drawVisitsTable(doc, visits, startY) {
  let y = startY;
  const x = 50;

  const headers = [
    { key: "date", label: "Date", width: 70 },
    { key: "vitals", label: "Vitals", width: 150 },
    { key: "symptoms", label: "Symptoms", width: 110 },
    { key: "prescription", label: "Prescription", width: 110 },
    { key: "fee", label: "Fee", width: 40 },
  ];

  const drawHeader = () => {
    let colX = x;
    doc.font("Helvetica-Bold").fontSize(9);
    headers.forEach((h) => {
      doc.rect(colX, y, h.width, 20).stroke("#d1d5db");
      doc.text(h.label, colX + 4, y + 6, { width: h.width - 8 });
      colX += h.width;
    });
    y += 20;
  };

  drawHeader();

  if (!Array.isArray(visits) || visits.length === 0) {
    doc.font("Helvetica").fontSize(10).text("No visits recorded.", x, y + 6);
    return y + 24;
  }

  visits.forEach((visit) => {
    y = ensurePageSpace(doc, y, 55);
    if (y === 50) {
      drawHeader();
    }

    const vitalsText = `H:${safeText(visit?.vitals?.height)} W:${safeText(
      visit?.vitals?.weight
    )} P:${safeText(visit?.vitals?.pulse)} BP:${safeText(visit?.vitals?.bp)} T:${safeText(
      visit?.vitals?.temp
    )} SpO2:${safeText(visit?.vitals?.spo2)}`;

    const rowData = [
      safeText(visit?.date),
      vitalsText,
      safeText(visit?.symptoms),
      safeText(visit?.prescription),
      safeText(visit?.fee),
    ];

    const rowHeight = 50;
    let colX = x;
    doc.font("Helvetica").fontSize(8);

    headers.forEach((h, idx) => {
      doc.rect(colX, y, h.width, rowHeight).stroke("#e5e7eb");
      doc.text(rowData[idx], colX + 4, y + 4, {
        width: h.width - 8,
        height: rowHeight - 8,
      });
      colX += h.width;
    });

    y += rowHeight;
  });

  return y;
}

function isVisitMeaningful(visit) {
  if (!visit || typeof visit !== "object") return false;

  const fieldsToCheck = [
    visit.date,
    visit.symptoms,
    visit.prescription,
    visit.fee,
    visit.labReportUrl,
    visit.doctorSignUrl,
    visit.height,
    visit.weight,
    visit.pulse,
    visit.bp,
    visit.temp,
    visit.spo2,
    visit.vitals?.height,
    visit.vitals?.weight,
    visit.vitals?.pulse,
    visit.vitals?.bp,
    visit.vitals?.temp,
    visit.vitals?.spo2,
  ];

  return fieldsToCheck.some(
    (value) => value !== undefined && value !== null && String(value).trim() !== ""
  );
}

function normalizeVisit(visit = {}) {
  return {
    date: visit.date || "",
    vitals: {
      height: visit.vitals?.height ?? visit.height ?? "",
      weight: visit.vitals?.weight ?? visit.weight ?? "",
      pulse: visit.vitals?.pulse ?? visit.pulse ?? "",
      bp: visit.vitals?.bp ?? visit.bp ?? "",
      temp: visit.vitals?.temp ?? visit.temp ?? "",
      spo2: visit.vitals?.spo2 ?? visit.spo2 ?? "",
    },
    symptoms: visit.symptoms || "",
    prescription: visit.prescription || "",
    fee: visit.fee || "",
    labReportUrl: visit.labReportUrl || "",
    doctorSignUrl: visit.doctorSignUrl || "",
  };
}

async function migrateLegacyFirstVisit() {
  const patientsCollection = mongoose.connection.collection("patients");

  const migrationResult = await patientsCollection.updateMany(
    {
      firstVisit: { $exists: true },
      $or: [{ visits: { $exists: false } }, { visits: { $size: 0 } }],
    },
    [
      {
        $set: {
          visits: {
            $cond: [
              {
                $and: [
                  { $ne: ["$firstVisit", null] },
                  {
                    $or: [
                      { $ne: [{ $ifNull: ["$firstVisit.date", ""] }, ""] },
                      { $ne: [{ $ifNull: ["$firstVisit.height", ""] }, ""] },
                      { $ne: [{ $ifNull: ["$firstVisit.weight", ""] }, ""] },
                      { $ne: [{ $ifNull: ["$firstVisit.pulse", ""] }, ""] },
                      { $ne: [{ $ifNull: ["$firstVisit.bp", ""] }, ""] },
                      { $ne: [{ $ifNull: ["$firstVisit.temp", ""] }, ""] },
                      { $ne: [{ $ifNull: ["$firstVisit.spo2", ""] }, ""] },
                      { $ne: [{ $ifNull: ["$firstVisit.symptoms", ""] }, ""] },
                      { $ne: [{ $ifNull: ["$firstVisit.prescription", ""] }, ""] },
                      { $ne: [{ $ifNull: ["$firstVisit.fee", ""] }, ""] },
                    ],
                  },
                ],
              },
              [
                {
                  date: { $ifNull: ["$firstVisit.date", ""] },
                  vitals: {
                    height: { $ifNull: ["$firstVisit.height", ""] },
                    weight: { $ifNull: ["$firstVisit.weight", ""] },
                    pulse: { $ifNull: ["$firstVisit.pulse", ""] },
                    bp: { $ifNull: ["$firstVisit.bp", ""] },
                    temp: { $ifNull: ["$firstVisit.temp", ""] },
                    spo2: { $ifNull: ["$firstVisit.spo2", ""] },
                  },
                  symptoms: { $ifNull: ["$firstVisit.symptoms", ""] },
                  prescription: { $ifNull: ["$firstVisit.prescription", ""] },
                  fee: { $ifNull: ["$firstVisit.fee", ""] },
                  labReportUrl: "",
                  doctorSignUrl: "",
                },
              ],
              [],
            ],
          },
        },
      },
      { $unset: "firstVisit" },
    ]
  );

  if (migrationResult.modifiedCount > 0) {
    console.log(`Migrated ${migrationResult.modifiedCount} patient(s) from firstVisit to visits[]`);
  }
}

/* ---------- MongoDB Connection ---------- */
mongoose
  .connect(process.env.MONGO_URI)
  .then(async () => {
    console.log("MongoDB connected");
    await migrateLegacyFirstVisit();
  })
  .catch((err) => console.log(err));

/* ---------- Schema ---------- */
const patientSchema = new mongoose.Schema({
  name: String,
  age: String,
  sex: String,
  dob: String,
  address: String,
  mobile: String,
  email: String,
  refId: String,
  guardianName: String,
  idProof: String,
  occupation: String,

  diagnosis: String,
  provisionalDiagnosis: String,
  clinicalHistory: String,
  familyHistory: String,

  visits: [
    {
      date: String,
      vitals: {
        height: String,
        weight: String,
        pulse: String,
        bp: String,
        temp: String,
        spo2: String,
      },
      symptoms: String,
      prescription: String,
      fee: String,
      labReportUrl: String,
      doctorSignUrl: String,
    },
  ],
});

const Patient = mongoose.model("Patient", patientSchema);

/* ---------- Routes ---------- */

// Get all patients
app.get("/patients", auth, async (req, res) => {
  const patients = await Patient.find();
  res.json(patients);
});

app.get("/patients/:id/print", auth, async (req, res) => {
  const patient = await Patient.findById(req.params.id);
  if (!patient) return res.status(404).json({ message: "Patient not found" });

  const doc = new PDFDocument({
    size: "A4",
    margins: { top: 50, bottom: 50, left: 50, right: 50 },
  });

  const safeName = (patient.name || "patient").replace(/[^a-z0-9]/gi, "_").toLowerCase();
  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", `inline; filename="case_sheet_${safeName}.pdf"`);

  doc.pipe(res);

  doc.font("Helvetica-Bold").fontSize(16).text("Asoka Homoeo Clinic", { align: "center" });
  doc.moveDown(0.2);
  doc.font("Helvetica").fontSize(10).text("Patient Case Sheet", { align: "center" });
  doc.moveDown(0.8);

  let y = 100;

  doc.font("Helvetica-Bold").fontSize(12).text("Preliminary Details", 50, y);
  y += 18;
  y = drawLabelValue(doc, "Name", patient.name, 50, y);
  y = drawLabelValue(doc, "Age", patient.age, 50, y);
  y = drawLabelValue(doc, "Sex", patient.sex, 50, y);
  y = drawLabelValue(doc, "DOB", patient.dob, 50, y);
  y = drawLabelValue(doc, "Mobile", patient.mobile, 50, y);
  y = drawLabelValue(doc, "Email", patient.email, 50, y);
  y = drawLabelValue(doc, "Ref ID", patient.refId, 50, y);
  y = drawLabelValue(doc, "Guardian", patient.guardianName, 50, y);
  y = drawLabelValue(doc, "Occupation", patient.occupation, 50, y);
  y = drawLabelValue(doc, "Address", patient.address, 50, y, 110, 20);
  y += 8;

  y = ensurePageSpace(doc, y, 140);
  doc.font("Helvetica-Bold").fontSize(12).text("Diagnosis & Histories", 50, y);
  y += 18;
  y = drawLabelValue(doc, "Diagnosis", patient.diagnosis, 50, y, 110, 20);
  y = drawLabelValue(doc, "Provisional", patient.provisionalDiagnosis, 50, y, 110, 20);
  y = drawLabelValue(doc, "Clinical History", patient.clinicalHistory, 50, y, 110, 20);
  y = drawLabelValue(doc, "Family History", patient.familyHistory, 50, y, 110, 20);
  y += 8;

  y = ensurePageSpace(doc, y, 120);
  doc.font("Helvetica-Bold").fontSize(12).text("Visit History", 50, y);
  y += 18;
  y = drawVisitsTable(doc, patient.visits || [], y);
  y += 10;

  const lastVisit = (patient.visits || [])[Math.max((patient.visits || []).length - 1, 0)] || {};
  y = ensurePageSpace(doc, y, 120);
  doc.font("Helvetica-Bold").fontSize(12).text("Latest Prescription & Fee", 50, y);
  y += 18;
  y = drawLabelValue(doc, "Prescription", lastVisit.prescription, 50, y, 110, 20);
  y = drawLabelValue(doc, "Fee", lastVisit.fee, 50, y);
  y += 6;
  y = tryDrawSignature(doc, lastVisit.doctorSignUrl, 50, y);

  doc.end();
});

app.post("/upload/lab", auth, (req, res) => {
  uploadLabFile.single("file")(req, res, (err) => {
    if (err) {
      return res.status(400).json({ message: err.message || "Lab upload failed" });
    }

    if (!req.file) {
      return res.status(400).json({ message: "No file uploaded" });
    }

    res.json({
      url: buildPublicFileUrl(req, "labs", req.file.filename),
    });
  });
});

app.post("/upload/signature", auth, (req, res) => {
  uploadSignatureFile.single("file")(req, res, (err) => {
    if (err) {
      return res
        .status(400)
        .json({ message: err.message || "Signature upload failed" });
    }

    if (!req.file) {
      return res.status(400).json({ message: "No file uploaded" });
    }

    res.json({
      url: buildPublicFileUrl(req, "signatures", req.file.filename),
    });
  });
});

// Add patient
app.post("/patients", auth, async (req, res) => {
  const payload = { ...req.body };

  if (Array.isArray(payload.visits)) {
    payload.visits = payload.visits.filter(isVisitMeaningful).map(normalizeVisit);
  } else if (isVisitMeaningful(payload.firstVisit)) {
    payload.visits = [normalizeVisit(payload.firstVisit)];
  } else {
    payload.visits = [];
  }

  delete payload.firstVisit;

  const newPatient = new Patient(payload);
  await newPatient.save();
  res.json(newPatient);
});

// Update patient
app.put("/patients/:id", auth, async (req, res) => {
  const payload = { ...req.body };

  if (Array.isArray(payload.visits)) {
    payload.visits = payload.visits.filter(isVisitMeaningful).map(normalizeVisit);
  } else if (isVisitMeaningful(payload.firstVisit)) {
    payload.visits = [normalizeVisit(payload.firstVisit)];
  }

  delete payload.firstVisit;

  const updated = await Patient.findByIdAndUpdate(req.params.id, payload, {
    new: true,
  });
  res.json(updated);
});

// Delete patient
app.delete("/patients/:id", auth, async (req, res) => {
  await Patient.findByIdAndDelete(req.params.id);
  res.json({ success: true });
});

// Add visit
app.post("/patients/:id/visits", auth, async (req, res) => {
  const patient = await Patient.findById(req.params.id);
  if (!patient) return res.status(404).json({ message: "Patient not found" });

  const visit = normalizeVisit(req.body);
  patient.visits = patient.visits || [];
  patient.visits.push(visit);
  await patient.save();

  res.json(patient);
});

// Edit visit
app.put("/patients/:id/visits/:visitId", auth, async (req, res) => {
  const patient = await Patient.findById(req.params.id);
  if (!patient) return res.status(404).json({ message: "Patient not found" });

  const visit = patient.visits.id(req.params.visitId);
  if (!visit) return res.status(404).json({ message: "Visit not found" });

  const normalizedVisit = normalizeVisit(req.body);
  visit.set(normalizedVisit);
  await patient.save();

  res.json(patient);
});

// Delete visit
app.delete("/patients/:id/visits/:visitId", auth, async (req, res) => {
  const patient = await Patient.findById(req.params.id);
  if (!patient) return res.status(404).json({ message: "Patient not found" });

  const visit = patient.visits.id(req.params.visitId);
  if (!visit) return res.status(404).json({ message: "Visit not found" });

  visit.deleteOne();
  await patient.save();

  res.json(patient);
});

/* ---------- Server ---------- */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

app.post("/register", auth, requireAdmin, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required" });
  }

  const existingUser = await User.findOne({ username });
  if (existingUser) {
    return res.status(409).json({ message: "Username already exists" });
  }

  const hashed = await bcrypt.hash(password, 10);

  const user = new User({ username, password: hashed, role: "doctor" });
  await user.save();

  res.json({ message: "Doctor account created", userId: user._id, role: user.role });
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username });
  if (!user) return res.status(400).json({ message: "User not found" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ message: "Wrong password" });

  const resolvedRole = user.role || (user.username === "admin" ? "admin" : "doctor");

  if (!user.role) {
    user.role = resolvedRole;
    await user.save();
  }

  const token = jwt.sign(
    { id: user._id, role: resolvedRole, username: user.username },
    JWT_SECRET,
    { expiresIn: "1d" }
  );

  res.json({ token, role: resolvedRole });
});

function auth(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith("Bearer ")
    ? authHeader.slice(7)
    : authHeader;

  if (!token) return res.status(401).json({ message: "No token" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== "admin") {
    return res.status(403).json({ message: "Admin access required" });
  }

  next();
}