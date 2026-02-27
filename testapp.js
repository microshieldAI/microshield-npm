const express = require("express");
const MicroShield = require("./index");

const app = express();

/* ---------- MIDDLEWARE ---------- */
app.use(express.json());

app.use(MicroShield({
  aiUrl: "http://127.0.0.1:8000/predict",
  mode: "protect",
  failOpen: true,
  sampleRate: 1
}));


/* ---------- ROUTES ---------- */
app.post("/login", (req, res) => {
  res.json({ message: "Login successful" });
});

app.get("/", (req, res) => {
  res.send("MicroShield Test App Running");
});

/* ---------- SERVER ---------- */
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`🚀 Test app running on http://localhost:${PORT}`);
});
