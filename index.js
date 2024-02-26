const express = require("express");
const bodyParser = require("body-parser");
const mysql = require("mysql");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const argon2 = require("argon2");

const app = express();

// Middleware to parse request body
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Create MySQL connection
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "login_system",
  port: 3306,
});

// Connect to MySQL
db.connect((err) => {
  if (err) {
    console.error("Error connecting to MySQL:", err);
    return;
  }
  console.log("Connected to MySQL database");
});

// Route to handle form submission
app.post("/signup", async (req, res) => {
  try {
    const { Name, Password } = req.body;
    console.log(Name, Password);

    // Check if the data already exists in the database
    const checkQuery = "SELECT * FROM users WHERE Name = ?";
    db.query(checkQuery, [Name], async (checkErr, checkResult) => {
      if (checkErr) {
        console.error("Error checking data in MySQL:", checkErr);
        return res.status(500).send("Error checking data in MySQL");
      }

      // If data already exists, send a response indicating it
      if (checkResult.length > 0) {
        const user = checkResult[0];
        return res.status(200).send(`${user.Name} already exists. Try another username. Use digit and Special character`);
      }

      try {
        // If user doesn't exist, hash the password
        const hashedPassword = await argon2.hash(Password);

        // Insert the user into MySQL
        const insertQuery = "INSERT INTO users (Name, Password) VALUES (?, ?)";
        db.query(
          insertQuery,
          [Name, hashedPassword],
          (insertErr, insertResult) => {
            if (insertErr) {
              console.error("Error inserting data into MySQL:", insertErr);
              return res.status(500).send("Error inserting data into MySQL");
            }
            console.log("Data inserted into MySQL:", insertResult);
            return res.status(200).send("Data inserted successfully");
          }
        );
      } catch (hashError) {
        console.error("Error hashing password:", hashError);
        return res.status(500).send("Error hashing password");
      }
    });
  } catch (error) {
    console.error("Error:", error);
    return res.status(500).send("Internal Server Error");
  }
});

//Route to login from
app.post('/login', async (req, res) => {
    try {
      const { Name, Password } = req.body;
      console.log(Name, Password);
  
      // Check if the user exists in the database
      const checkQuery = "SELECT * FROM users WHERE Name = ?";
      db.query(checkQuery, [Name], async (checkErr, checkResult) => {
        if (checkErr) {
          console.error("Error checking data in MySQL:", checkErr);
          return res.status(500).send("Error checking data in MySQL");
        }
  
        // If user doesn't exist, send an error response
        if (checkResult.length === 0) {
          return res.status(401).send("Invalid username or password");
        }
  
        // User exists, compare the hashed password
        const user = checkResult[0];
        const isPasswordValid = await argon2.verify(user.Password, Password);
        if (!isPasswordValid) {
          return res.status(401).send("Invalid username or password");
        }
  
        // Password is valid, generate and send token
        const token = jwt.sign({ id: user.id, Name: user.Name }, "secret_key");
        return res.status(200).json({ status:"Login Successfull",token });
      });
    } catch (error) {
      console.error("Error:", error);
      return res.status(500).send("Internal Server Error");
    }
  });
  

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
