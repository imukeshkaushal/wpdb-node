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
// Update user endpoint using PATCH method
app.patch('/users/update/:id', async (req, res) => {
  const userId = req.params.id;
  const { username, email, password } = req.body;

  try {
    const getUserQuery = 'SELECT * FROM wp_users WHERE ID = ?';
    const existingUser = await queryDB(getUserQuery, [userId]);
    if (existingUser.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const updateFields = {};
    if (username) updateFields.user_login = username;
    if (email) updateFields.user_email = email;
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      updateFields.user_pass = hashedPassword;
    }
    console.log("updated fields", updateFields);

    const updateUserQuery = 'UPDATE wp_users SET ? WHERE ID = ?';
    await queryDB(updateUserQuery, [updateFields, userId]);
    
    const updatedUser = await queryDB(getUserQuery, [userId]);
      console.log("Updated User",updatedUser)
    const user = {
      id: updatedUser[0].ID,
      username: updatedUser[0].user_login,
      email: updatedUser[0].user_email,
    };

    return res.status(200).json({ message: 'User updated successfully', user });
  } catch (error) {
    console.error('Error updating user:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all users endpoint
app.get('/users', async (req, res) => {
  try {
      const getAllUsersQuery = 'SELECT * FROM wp_users';
      const users = await queryDB(getAllUsersQuery);
      const usersArray = users.map(user => ({
          id: user.ID,
          username: user.user_login,
          email: user.user_email,
      }));
      return res.status(200).json(usersArray);
  } catch (error) {
      console.error('Error retrieving users:', error);
      return res.status(500).json({ error: 'Internal server error' });
  }
});

// Get single user endpoint
app.get('/users/:id', async (req, res) => {
  const userId = req.params.id;

  try {
      const getUserQuery = 'SELECT * FROM wp_users WHERE ID = ?';
      const [user] = await queryDB(getUserQuery, [userId]);

      if (!user) {
          return res.status(404).json({ error: 'User not found' });
      }
      const userDetails = {
          id: user.ID,
          username: user.user_login,
          email: user.user_email,
      };
      return res.status(200).json(userDetails);
  } catch (error) {
      console.error('Error retrieving user:', error);
      return res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete user endpoint
app.delete('/users/delete/:id', async (req, res) => {
  const userId = req.params.id;

  try {
      const getUserQuery = 'SELECT * FROM wp_users WHERE ID = ?';
      const [user] = await queryDB(getUserQuery, [userId]);
      if (!user) {
          return res.status(404).json({ error: 'User not found' });
      }
      const deleteUserQuery = 'DELETE FROM wp_users WHERE ID = ?';
      await queryDB(deleteUserQuery, [userId]);
      return res.status(200).json({ message: 'User deleted successfully' });
  } catch (error) {
      console.error('Error deleting user:', error);
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
