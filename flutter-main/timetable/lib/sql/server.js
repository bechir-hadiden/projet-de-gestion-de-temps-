const express = require('express');
const cors = require('cors'); // Import cors
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const db = require('./db');

const app = express();
const PORT = 3050;

// const cors = require('cors');
// app.use(cors());  


// Middleware
app.use(bodyParser.json());
app.use(cors()); // Enable CORS

// Secret key for JWT
const JWT_SECRET = 'your_secret_key'; // Replace with a strong secret key

// Register route
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).send('Email and password are required');
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.query(
      'INSERT INTO users (email, password) VALUES (?, ?)',
      [email, hashedPassword],
      (err) => {
        if (err) {
          if (err.code === 'ER_DUP_ENTRY') {
            return res.status(400).send('User already exists');
          }
          return res.status(500).send('Database error');
        }
        res.status(201).send('User registered successfully');
      }
    );
  } catch (err) {
    res.status(500).send('Server error');
  }
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).send('Email and password are required');
  }
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) return res.status(500).send('Database error');
    if (results.length === 0) return res.status(401).send('Invalid email or password');
    const user = results[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).send('Invalid email or password');
    }
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  });
});



// app.post('/login', (req, res) => {
//   const { email, password } = req.body;

//   // Vérifiez si les données sont valides
//   if (!email || !password) {
//     return res.status(400).send('Email and password are required');
//   }

//   // Requête pour trouver l'utilisateur
//   db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
//     if (err) {
//       console.error('Database error:', err);
//       return res.status(500).send('Database error');
//     }

//     // Vérifiez si un utilisateur a été trouvé
//     if (results.length === 0) {
//       return res.status(401).send('Invalid email or password');
//     }

//     const user = results[0];

//     // Vérifiez si le champ `password` est valide
//     if (!user.password) {
//       console.error('Password is undefined for user:', user);
//       return res.status(500).send('Server error');
//     }

//     // Comparez les mots de passe
//     try {
//       const isPasswordValid = await bcrypt.compare(password, user.password);

//       if (!isPasswordValid) {
//         return res.status(401).send('Invalid email or password');
//       }

//       // Génération du token
//       const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
//       res.json({ token });
//     } catch (compareError) {
//       console.error('Error comparing passwords:', compareError);
//       res.status(500).send('Server error');
//     }
//   });
// });


// Start the server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});