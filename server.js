import express from 'express';
import env from 'dotenv';
import pkg from 'pg';
const { Pool } = pkg;
import cors from 'cors';
import admin from 'firebase-admin';
import bcrypt from 'bcrypt';
import { encrypt, decrypt } from './utils/cryptoUtils.js';
// import { pool } from '../db/db.js'; // or wherever your pool is initialized


env.config();
const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

const db = new Pool({
  user: process.env.PG_USER,
  password: process.env.PG_PASSWORD,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  port: process.env.PG_PORT,
  ssl: process.env.PG_SSL === 'true' ? { rejectUnauthorized: false } : false,
})

db.connect();

// Firebase
import serviceAccount from './serviceAccountKey.json' assert { type: 'json' };

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});


app.post('/api/auth/firebase-login', async (req, res) => {
    const { token } = req.body;
  
    try {
      const decoded = await admin.auth().verifyIdToken(token);
  
      const {
        name,
        email,
        picture: photo,
        user_id: uid,
        firebase: { sign_in_provider: provider },
      } = decoded;
  
      const fallbackEmail = email || `${uid}@firebaseuser.local`;
      const fallbackName = name || 'Anonymous';
  
      const encryptedEmail = encrypt(fallbackEmail);
      const encryptedName = encrypt(fallbackName);
  
      // 🔁 UPSERT user (login or signup in one)
      const result = await db.query(
        `
        INSERT INTO users (userid, name, email, photo, provider)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (userid) DO UPDATE
        SET name = EXCLUDED.name,
            email = EXCLUDED.email,
            photo = EXCLUDED.photo,
            provider = EXCLUDED.provider
        RETURNING *;
        `,
        [uid, encryptedName, encryptedEmail, photo, provider]
      );
  
      // 🧠 Optional: decrypt before sending back
      const user = result.rows[0];
      const decryptedUser = {
        ...user,
        name: decrypt(user.name),
        email: decrypt(user.email),
      };
  
      res.status(200).json({
        message: 'User logged in successfully',
        user: decryptedUser,
      });
  
    } catch (error) {
      console.error('❌ Firebase token verification failed:', error);
      res.status(401).json({ error: 'Invalid token' });
    }
  });


  // Get users for Dashboard
  app.get('/api/users', async (req, res) => {
    try {
      const result = await db.query('SELECT * FROM users');

      const decryptedUsers = result.rows.map(user => ({
        ...user,
        name: user.name ? decrypt(user.name) : null,
        email: user.email ? decrypt(user.email) : null,
      }));
  
      res.json(decryptedUsers);
    } catch (error) {
      console.error('Error fetching users:', error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });

  app.post('/api/admin/login', async (req, res) => {
    const { email, password } = req.body;
  
    try { 
      const result = await db.query('SELECT * FROM admins WHERE email = $1', [email]);
      const admin = result.rows[0];
  
      if (!admin) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }
  
      const match = await bcrypt.compare(password, admin.password);
      if (!match) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }
  
      res.status(200).json({
        message: 'success',
        admin: {
          id: admin.adminid,
          email: admin.email,
          name: admin.name
        }
      });
  
    } catch (err) {
      console.error('Admin login error:', err);
      res.status(500).json({ message: 'Server error' });
    }
  });

  app.post('/api/admin-chat', async (req, res) => {
    const { user_id, sender, message, username } = req.body;
  
    try {

      await db.query(
        `INSERT INTO admin_chat (user_id, sender, message, username)
        VALUES ($1, $2, $3, $4)`,
        [user_id, sender, message, username]
      );

  
      res.status(201).json({ success: true, message: 'Message sent' });
    } catch (err) {
      console.error('Error sending message:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  app.get('/api/admin-chat/:user_id', async (req, res) => {
    const { user_id } = req.params;
  
    try {
      const result = await db.query(
        `SELECT * FROM admin_chat
         WHERE user_id = $1
         ORDER BY created_at ASC`,
        [user_id]
      );
  
      res.json(result.rows);
    } catch (err) {
      console.error('Error fetching chat:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  app.get('/api/admin-chat', async (req, res) => {
    try {
      const result = await db.query(
        `SELECT * FROM admin_chat ORDER BY created_at ASC`
      );
  
      res.json(result.rows);
    } catch (err) {
      console.error('Error fetching all chats:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  app.post('/api/drivers', async (req, res) => {
    const {
      firstName,
      lastName,
      phoneNumber,
      email,
      city,
      zipCode,
      state,
      about,
      consentCalls,
      consentTexts
    } = req.body;
  
    try {
      await db.query(
        `INSERT INTO drivers (
          first_name,
          last_name,
          phone_number,
          email,
          city,
          zip_code,
          state,
          about,
          consent_calls,
          consent_texts
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [
          firstName,
          lastName,
          phoneNumber,
          email,
          city,
          zipCode,
          state,
          about,
          consentCalls,
          consentTexts
        ]
      );
  
      res.status(201).json({ message: "Driver application submitted successfully!" });
    } catch (err) {
      console.error("❌ Error submitting driver form:", err);
      res.status(500).json({ message: "Server error. Could not submit application." });
    }
  });
  
  // Assuming you already have `express` and `pg` set up
app.get('/api/drivers', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM drivers ORDER BY submitted_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching drivers:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Brokers
app.post('/api/brokers', async (req, res) => {
  const {
    full_name,
    company_name,
    email,
    phone,
    mc_dot_number,
    insurance_info,
    preferred_routes,
    comments,
    consent_calls,
    consent_texts
  } = req.body;

  try {
    await db.query(
      `INSERT INTO brokers (
        full_name, company_name, email, phone, mc_dot_number,
        insurance_info, preferred_routes, comments,
        consent_calls, consent_texts
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [
        full_name, company_name, email, phone, mc_dot_number,
        insurance_info, preferred_routes, comments,
        consent_calls, consent_texts
      ]
    );

    res.status(201).json({ message: 'Broker application submitted successfully' });
  } catch (err) {
    console.error('Error inserting broker data:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/brokers', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM brokers ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching brokers:', err);
    res.status(500).json({ error: 'Failed to fetch broker applications' });
  }
});


// contact form
app.post('/api/contact', async (req, res) => {
  const { name, email, phone, city, message } = req.body;

  try {
    await db.query(
      `INSERT INTO contact_messages (name, email, phone, city, message)
       VALUES ($1, $2, $3, $4, $5)`,
      [name, email, phone, city, message]
    );

    res.status(201).json({ success: true, message: "Message stored!" });
  } catch (error) {
    console.error("❌ Failed to save message:", error);
    res.status(500).json({ success: false, error: "Failed to save message." });
  }
});


app.get('/api/contact', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM contact_messages ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching contact messages:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
})
