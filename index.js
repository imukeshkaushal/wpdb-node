const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const app = express();

app.use(bodyParser.json());


const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'spring'
});


db.connect((err) => {
  if (err) throw err;
  console.log('MySQL connected');
});


app.get('/', (req,res) => {
    res.send("Welcome to Node Js With Wordpress");
})

// Registration 
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const checkUserQuery = 'SELECT * FROM wp_users WHERE user_login = ?';
    const existingUser = await queryDB(checkUserQuery, [username]);
    if (existingUser.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);

    const insertUserQuery = 'INSERT INTO wp_users (user_login, user_pass, user_email) VALUES (?, ?, ?)';
    await queryDB(insertUserQuery, [username, hashedPassword, email]);
    
    const getUserDetailsQuery = 'SELECT * FROM wp_users WHERE user_login = ?';
    const newUser = await queryDB(getUserDetailsQuery, [username]);

    const user = {
      id: newUser[0].ID,
      username: newUser[0].user_login,
      email: newUser[0].user_email,

    };
    const token = await loginUser(user);

    return res.status(200).json({ message: 'User registered successfully', token, user });
  } catch (error) {
    console.error('Error registering user:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});
  
  // Login function
  async function loginUser(user) {
    const secretKey = crypto.randomBytes(32).toString('hex');
    try {
      const token = jwt.sign({
        id: user.ID,
        username: user.user_login,
        email: user.user_email,
      }, secretKey, { expiresIn: '1h' });
  
      return token;
    } catch (error) {
      console.error('Error logging in user:', error);
      throw error;
    }
}

// Login endpoint
app.post('/login', async (req, res) => {
    const { username, password } = req.body; 
    try {
      const getUserQuery = 'SELECT * FROM wp_users WHERE user_login = ?';
      const user = await queryDB(getUserQuery, [username]);
      if (user.length === 0) {
        return res.status(401).json({ error: 'Invalid username or password' });
      }
  
      const hashedPassword = user[0].user_pass;
      const passwordMatch = await bcrypt.compare(password, hashedPassword);
      if (!passwordMatch) {
        return res.status(401).json({ error: 'Invalid username or password' });
      }
  
      const secretKey = crypto.randomBytes(32).toString('hex');
  
      const token = jwt.sign({
        id: user[0].ID,
        username: user[0].user_login,
        email: user[0].user_email,
      }, secretKey, { expiresIn: '1h' });
  
      return res.status(200).json({ message: 'Login successful', token, user: user[0] });
    } catch (error) {
      console.error('Error logging in:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }
});

  // Function to execute MySQL queries
function queryDB(sql, args) {
    return new Promise((resolve, reject) => {
      db.query(sql, args, (err, rows) => {
        if (err) return reject(err);
        resolve(rows);
      });
    });
  }


const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
