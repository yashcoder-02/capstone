const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect("mongodb://mongo:27017/authDB")
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log(err));

const User = mongoose.model("User", {
  email: String,
  password: String,
});

app.get("/", (req, res) => {
  res.send("Backend Running");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const newUser = new User({ email, password });
  await newUser.save();

  res.json({ message: "User saved successfully" });
});

app.listen(5000, () => console.log("Server running on port 5000"));