const express = require("express");
const MicroShield = require("./index");

const app = express();
app.use(express.json());

app.use(MicroShield({ aiUrl: "http://localhost:5000/predict" }));

app.post("/login", (req, res) => {
  res.send("Logged in!");
});

app.listen(3000, () => console.log("Running at 3000"));
