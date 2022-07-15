require("dotenv").config();

// express
const express = require("express");
const app = express();

// encryption
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

// path
const path = require("path");

// database
const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  password: { type: String, required: true },
  secu_key: { type: String, required: true },
  messages: [{ type: String }],
});

const User = mongoose.model("TBCH", userSchema);

mongoose.connect(process.env.DB).then((d) => {
  console.log(`Connected to DB : ${d.connections[0].host}`.bold.yellow);

  app.use(express.json());
  app.use(express.static(path.join(__dirname, "../frontend/build")));

  app.get("*", (req, res) => {
    res.sendFile(path.join(__dirname, "../frontend/build/index.html"));
  });

  app.post("/_tbch-api/forget-password", (req, res) => {
    const { name, password, secu_key } = req.body;

    if (!name || !password || !secu_key)
      return res.json({ message: "Important fields missing.", success: false });

    User.findOne({ name: name }, async (err, data) => {
      if (err) return res.json({ message: "Error occured!", success: false });
      if (!data)
        return res.json({ message: "User doesn't exist!", success: false });

      const secu_keyC = await bcrypt.compare(secu_key, data.secu_key);

      if (secu_keyC) {
        const hash = await bcrypt.hash(password, 12);
        data.password = hash;

        data.save().then((d) => {
          return res.json({
            message: "Password successfully changed.",
            success: true,
          });
        });
      } else {
        return res.json({
          message: "Wrong Secu-Key®.",
          success: false,
        });
      }
    });
  });

  app.post("/_tbch-api/get-messages", (req, res) => {
    const { name } = req.body;

    if (!name)
      return res.json({ message: "Important fields missing.", success: false });

    User.findOne({ name: name }, (err, data) => {
      if (err) return res.json({ message: "Error occured!", success: false });
      if (!data)
        return res.json({ message: "User doesn't exist!", success: false });

      return res.json({
        message: data.messages,
        success: true,
      });
    });
  });

  app.post("/_tbch-api/send", (req, res) => {
    const { name, message } = req.body;

    if (!name || !message)
      return res.json({ message: "Important fields missing.", success: false });

    User.findOne({ name: name }, (err, data) => {
      if (err) return res.json({ message: "Error occured!", success: false });
      if (!data)
        return res.json({ message: "User doesn't exist!", success: false });

      data.messages.push(message);

      data.save().then((d) => {
        return res.json({
          message: "Message sent!",
          success: true,
        });
      });
    });
  });

  app.post("/_tbch-api/search", (req, res) => {
    const { name } = req.body;

    if (!name)
      return res.json({ message: "Important fields missing.", success: false });

    User.findOne({ name: name }, (err, data) => {
      if (err) return res.json({ message: "Error occured!", success: false });
      if (!data)
        return res.json({ message: "User doesn't exist!", success: false });

      return res.json({
        message: data.name,
        success: true,
      });
    });
  });

  app.post("/_tbch-api/verify", (req, res) => {
    try {
      const verify = jwt.verify(
        req.header("auth-token"),
        process.env.JWT_SECRET
      );
      res.json(verify);
    } catch (e) {
      res.json(false);
    }
  });

  app.post("/_tbch-api/login", (req, res) => {
    console.log(req.body);
    const { email, password } = req.body;

    if (!email || !password)
      return res.json({ message: "Important fields missing.", success: false });

    User.findOne({ email: email }, async (err, data) => {
      if (err) {
        return res.json({
          message: "Error occured.",
          success: false,
        });
      }
      if (!data) {
        return res.json({
          message: "User doesn't exist.",
          success: false,
        });
      }

      const compare = await bcrypt.compare(password, data.password);

      if (compare) {
        const jwt_hash = jwt.sign(
          { _id: data._id, name: data.name },
          process.env.JWT_SECRET
        );
        return res.json({
          message: "Logged in.",
          success: true,
          jwt: jwt_hash,
        });
      } else {
        return res.json({
          message: "Wrong password.",
          success: false,
        });
      }
    });
  });

  app.post("/_tbch-api/register", (req, res) => {
    const { name, email, password, secu_key } = req.body;

    if (!name || !email || !password || !secu_key)
      return res.json({ message: "Important fields missing.", success: false });

    if (name.length > 15) {
      return;
    }

    User.findOne({ name: name }, async (err, data) => {
      if (err)
        return res.json({
          message: `Error occured.`,
          success: false,
        });
      if (data)
        return res.json({
          message: `Username in use.`,
          success: false,
        });

      User.findOne({ email: email }, async (errx, datax) => {
        if (errx)
          return res.json({
            message: `Error occured.`,
            success: false,
          });
        if (datax)
          return res.json({
            message: `Email in use.`,
            success: false,
          });

        const hash_passKey = await bcrypt.hash(password, 12);
        const hash_secuKey = await bcrypt.hash(secu_key, 12);

        const newUser = new User({
          name: name,
          email: email,
          password: hash_passKey,
          secu_key: hash_secuKey,
        });

        newUser.save().then((d) => {
          return res.json({
            message: `${d.name} has been registered!`,
            success: true,
          });
        });
      });
    });
  });

  
}).catch(e => {
    console.log(e)
    app.get("*", (req, res) => {
        res.send("Can't connect to server. Please contact @charliecatxph about this issue." + e);
    })
});


// ui/ux
const colors = require("colors");

// ports
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Listening on PORT ${PORT}`.blue.bold);
});