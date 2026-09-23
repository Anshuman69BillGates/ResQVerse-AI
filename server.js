require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-this-secret';
const COOKIE_SECURE = String(process.env.COOKIE_SECURE || 'false').toLowerCase() === 'true';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '';
const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-3.6-flash';
const GEMINI_API_KEY = String(process.env.GEMINI_API_KEY || '').trim();

app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));
app.use(cookieParser());
app.use(express.json({ limit: '100kb' }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: true, legacyHeaders: false }));

const memory = { users: new Map(), profiles: new Map(), contacts: new Map() };
let mongoReady = false;

function validEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }
function id() { return crypto.randomUUID(); }
function resqId() { return `RQ-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`; }
function encryptionKey() {
  if (!ENCRYPTION_KEY) return null;
  return crypto.createHash('sha256').update(ENCRYPTION_KEY).digest();
}
function encrypt(value) {
  const key = encryptionKey();
  if (!key) return JSON.stringify(value);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
  return [iv.toString('base64url'), cipher.getAuthTag().toString('base64url'), data.toString('base64url')].join('.');
}
function decrypt(value) {
  if (!value) return null;
  const key = encryptionKey();
  if (!key) { try { return JSON.parse(value); } catch { return null; } }
  try {
    const [ivB64, tagB64, dataB64] = value.split('.');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivB64, 'base64url'));
    decipher.setAuthTag(Buffer.from(tagB64, 'base64url'));
    return JSON.parse(Buffer.concat([decipher.update(Buffer.from(dataB64, 'base64url')), decipher.final()]).toString('utf8'));
  } catch { return null; }
}

const User = mongoose.model('User', new mongoose.Schema({
  email: { type: String, unique: true, index: true },
  passwordHash: String,
  displayName: String,
  createdAt: { type: Date, default: Date.now }
}));
const Profile = mongoose.model('Profile', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, unique: true, index: true },
  resqId: { type: String, unique: true, index: true },
  encryptedData: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}));
const Contact = mongoose.model('Contact', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, index: true },
  name: String,
  phone: String,
  relationship: String,
  createdAt: { type: Date, default: Date.now }
}));

async function connectMongo() {
  if (!process.env.MONGODB_URI) {
    console.warn('MONGODB_URI is not configured; using temporary local memory storage.');
    return;
  }

  mongoose.connection.on('connected', () => {
    mongoReady = true;
    console.log('MongoDB connected.');
  });

  mongoose.connection.on('disconnected', () => {
    mongoReady = false;
    console.warn('MongoDB disconnected. Waiting for reconnection...');
  });

  mongoose.connection.on('reconnected', () => {
    mongoReady = true;
    console.log('MongoDB reconnected.');
  });

  mongoose.connection.on('error', (err) => {
    console.error('MongoDB connection error:', err.message);
  });

  const maxAttempts = 5;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      await mongoose.connect(process.env.MONGODB_URI, {
        serverSelectionTimeoutMS: 8000,
        connectTimeoutMS: 8000,
        socketTimeoutMS: 45000,
        maxPoolSize: 10,
      });

      mongoReady = true;
      console.log('MongoDB connection established.');
      return;

    } catch (error) {
      mongoReady = false;

      console.warn(
        `MongoDB connection attempt ${attempt}/${maxAttempts} failed:`,
        error.message
      );

      if (attempt === maxAttempts) {
        console.warn(
          'MongoDB unavailable after multiple attempts; using temporary local memory storage.'
        );
        return;
      }

      const delay = Math.min(2000 * (2 ** (attempt - 1)), 15000);

      console.log(`Retrying MongoDB connection in ${delay / 1000}s...`);

      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}
function sign(user) { return jwt.sign({ sub: String(user._id || user.id), email: user.email }, JWT_SECRET, { expiresIn: '7d' }); }
function setAuthCookie(res, token) {
  res.cookie('resq_token', token, { httpOnly: true, sameSite: 'lax', secure: COOKIE_SECURE, maxAge: 7 * 24 * 60 * 60 * 1000, path: '/' });
}
async function auth(req, res, next) {
  const token = req.cookies.resq_token;
  if (!token) return res.status(401).json({ ok: false, message: 'Please sign in to continue.' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ ok: false, message: 'Your session has expired. Please sign in again.' }); }
}
function userId(req) { return req.user.sub; }
function safeProfile(p) {
  if (!p) return null;
  return { ...p };
}

app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'ResQVerse AI API', version: 'final-v1', database: mongoReady ? 'mongodb' : 'local-memory', timestamp: new Date().toISOString() }));

app.post('/api/auth/signup', async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  const displayName = String(req.body?.displayName || '').trim().slice(0, 80);
  if (!validEmail(email)) return res.status(400).json({ ok: false, message: 'Enter a valid email address.' });
  if (password.length < 8) return res.status(400).json({ ok: false, message: 'Password must be at least 8 characters.' });
  try {
    if (mongoReady) {
      if (await User.exists({ email })) return res.status(409).json({ ok: false, message: 'An account with this email already exists.' });
      const user = await User.create({ email, passwordHash: await bcrypt.hash(password, 12), displayName });
      setAuthCookie(res, sign(user));
      return res.status(201).json({ ok: true, user: { email, displayName } });
    }
    if (memory.users.has(email)) return res.status(409).json({ ok: false, message: 'An account with this email already exists.' });
    const user = { id: id(), email, passwordHash: await bcrypt.hash(password, 12), displayName };
    memory.users.set(email, user);
    setAuthCookie(res, sign(user));
    return res.status(201).json({ ok: true, user: { email, displayName } });
  } catch (e) { console.error(e); res.status(500).json({ ok: false, message: 'Could not create the account.' }); }
});

app.post('/api/auth/login', async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  try {
    let user;
    if (mongoReady) user = await User.findOne({ email }); else user = memory.users.get(email);
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) return res.status(401).json({ ok: false, message: 'Email or password is incorrect.' });
    setAuthCookie(res, sign(user));
    res.json({ ok: true, user: { email: user.email, displayName: user.displayName || '' } });
  } catch (e) { console.error(e); res.status(500).json({ ok: false, message: 'Could not sign in.' }); }
});

app.post('/api/auth/logout', (_req, res) => { res.clearCookie('resq_token', { httpOnly: true, sameSite: 'lax', secure: COOKIE_SECURE, path: '/' }); res.json({ ok: true }); });
app.get('/api/auth/me', auth, async (req, res) => {
  let user;
  if (mongoReady) user = await User.findById(userId(req)).lean();
  else user = [...memory.users.values()].find(u => u.id === userId(req));
  if (!user) return res.status(401).json({ ok: false, message: 'Account not found.' });
  res.json({ ok: true, user: { email: user.email, displayName: user.displayName || '' } });
});

app.post('/api/profile', auth, async (req, res) => {
  const allowed = ['name', 'dob', 'age', 'bloodGroup', 'allergies', 'medicalConditions', 'medications', 'previousMedicalHistory'];
  const profile = {};
  for (const key of allowed) if (req.body?.[key] !== undefined) profile[key] = req.body[key];
  if (!profile.name || !profile.dob || !profile.age || !profile.bloodGroup) return res.status(400).json({ ok: false, message: 'Name, date of birth, age and blood group are required.' });
  profile.age = Number(profile.age);
  if (!Number.isInteger(profile.age) || profile.age < 1 || profile.age > 120) return res.status(400).json({ ok: false, message: 'Enter a valid age.' });
  try {
    if (mongoReady) {
      let existing = await Profile.findOne({ userId: userId(req) });
      if (!existing) existing = await Profile.create({ userId: userId(req), resqId: resqId(), encryptedData: encrypt(profile) });
      else { existing.encryptedData = encrypt(profile); existing.updatedAt = new Date(); await existing.save(); }
      return res.status(201).json({ ok: true, profile: { ...profile, resqId: existing.resqId, updatedAt: existing.updatedAt } });
    }
    let existing = memory.profiles.get(userId(req));
    const rid = existing?.resqId || resqId();
    const saved = { ...profile, resqId: rid, updatedAt: new Date().toISOString() };
    memory.profiles.set(userId(req), { ...saved, encryptedData: encrypt(profile) });
    res.status(201).json({ ok: true, profile: saved });
  } catch (e) { console.error(e); res.status(500).json({ ok: false, message: 'Could not save the medical profile.' }); }
});

app.get('/api/profile', auth, async (req, res) => {
  try {
    if (mongoReady) {
      const p = await Profile.findOne({ userId: userId(req) }).lean();
      if (!p) return res.json({ ok: true, profile: null });
      return res.json({ ok: true, profile: { ...decrypt(p.encryptedData), resqId: p.resqId, updatedAt: p.updatedAt } });
    }
    const p = memory.profiles.get(userId(req));
    res.json({ ok: true, profile: p ? { ...decrypt(p.encryptedData), resqId: p.resqId, updatedAt: p.updatedAt } : null });
  } catch (e) { console.error(e); res.status(500).json({ ok: false, message: 'Could not load your profile.' }); }
});

app.get('/api/contacts', auth, async (req, res) => {
  if (mongoReady) return res.json({ ok: true, contacts: await Contact.find({ userId: userId(req) }).sort({ createdAt: 1 }).lean() });
  res.json({ ok: true, contacts: memory.contacts.get(userId(req)) || [] });
});
app.post('/api/contacts', auth, async (req, res) => {
  const name = String(req.body?.name || '').trim().slice(0, 80);
  const phone = String(req.body?.phone || '').trim().slice(0, 30);
  const relationship = String(req.body?.relationship || '').trim().slice(0, 50);
  if (!name || !phone) return res.status(400).json({ ok: false, message: 'Name and phone are required.' });
  if (mongoReady) return res.status(201).json({ ok: true, contact: await Contact.create({ userId: userId(req), name, phone, relationship }) });
  const arr = memory.contacts.get(userId(req)) || []; const contact = { id: id(), name, phone, relationship }; arr.push(contact); memory.contacts.set(userId(req), arr); res.status(201).json({ ok: true, contact });
});
app.delete('/api/contacts/:contactId', auth, async (req, res) => {
  if (mongoReady) { await Contact.deleteOne({ _id: req.params.contactId, userId: userId(req) }); return res.json({ ok: true }); }
  const arr = memory.contacts.get(userId(req)) || []; memory.contacts.set(userId(req), arr.filter(c => c.id !== req.params.contactId)); res.json({ ok: true });
});



const aiLimiter = rateLimit({ windowMs: 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false, message: { ok: false, message: 'Too many AI requests. Please wait a moment and try again.' } });
app.post('/api/ai/chat', aiLimiter, async (req, res) => {
  const message = String(req.body?.message || '').trim().slice(0, 4000);
  if (!message) return res.status(400).json({ ok: false, message: 'Message is required.' });
  const key = process.env.GEMINI_API_KEY;
  if (!key) return res.status(503).json({ ok: false, message: 'ResQ AI is not configured on this server yet.' });
  const history = Array.isArray(req.body?.history) ? req.body.history.slice(-10).map(x => ({ role: x.role === 'assistant' ? 'model' : 'user', parts: [{ text: String(x.content || '').slice(0, 2000) }] })) : [];
  const system = `You are ResQ AI, a student-built emergency and healthcare companion. Give general, cautious health information and practical next steps. Do not diagnose, prescribe, or claim to replace a clinician. If the user describes an immediate emergency such as trouble breathing, severe bleeding, loss of consciousness, suspected stroke or heart attack, tell them to contact local emergency services immediately and use the app's SOS feature. You can also help with study, coding, projects, career and everyday questions. Be concise and clear.`;
  try {
  let r;
let data;

for (let attempt = 0; attempt < 3; attempt++) {
  r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(GEMINI_MODEL)}:generateContent`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-goog-api-key': key
    },
    body: JSON.stringify({
      systemInstruction: { parts: [{ text: system }] },
      contents: [
        ...history,
        { role: 'user', parts: [{ text: message }] }
      ],
      generationConfig: {
        temperature: 0.3,
        maxOutputTokens: 1600
      }
    })
  });

  data = await r.json();

  if (r.ok) break;

  if (![429, 503].includes(r.status) || attempt === 2) break;

  await new Promise(resolve =>
    setTimeout(resolve, 1000 * (2 ** attempt))
  );
}
   if (!r.ok) {
  console.error('Gemini API error:', r.status, JSON.stringify(data, null, 2));

  return res.status(502).json({
    ok: false,
    message: 'AI provider request failed.',
    providerStatus: r.status,
    providerError: data?.error?.message || 'Unknown Gemini API error'
  });
}
    const reply = data?.candidates?.[0]?.content?.parts?.map(p => p.text || '').join('').trim();
    if (!reply) return res.status(502).json({ ok: false, message: 'AI provider returned no response.' });
    res.json({ ok: true, reply, model: GEMINI_MODEL });
  } catch (e) { console.error(e); res.status(502).json({ ok: false, message: 'Could not reach the AI provider.' }); }
});
app.post('/api/medicine-search', aiLimiter, async (req, res) => {
  const medicine = String(req.body?.medicine || '').trim().slice(0, 120);

  if (!medicine) {
    return res.status(400).json({
      ok: false,
      message: 'Medicine name is required.'
    });
  }

  const key = process.env.GEMINI_API_KEY;

  if (!key) {
    return res.status(503).json({
      ok: false,
      message: 'Medicine search is not configured on this server.'
    });
  }

  const system = `
You are the ResQVerse AI medicine information search assistant.

Search the current web before answering.

For medicine-related information:
- Prefer authoritative Indian sources such as NPPA, Government of India,
  official regulatory sources, and official manufacturer information.
- Do not invent prices, availability, dosage, prescription status, or medical claims.
- If a current price cannot be verified, say "Price not verified".
- Clearly distinguish MRP/reference price from a pharmacy's actual selling price.
- Give concise informational results only.
- Do not recommend that the user take a medicine for a symptom.
- Do not provide personalised dosage or treatment instructions.
- Mention the source for important factual information.
- If reliable information cannot be found, say so.

Return a concise answer suitable for displaying inside a pharmacy-search UI.
`;

  try {
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(GEMINI_MODEL)}:generateContent`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-goog-api-key': key
        },
        body: JSON.stringify({
          systemInstruction: {
            parts: [{ text: system }]
          },
          contents: [
            {
              role: 'user',
              parts: [{
                text: `Search for verified current information about this medicine: "${medicine}"`
              }]
            }
          ],
          tools: [
            {
              google_search: {}
            }
          ],
          generationConfig: {
            temperature: 0.1,
            maxOutputTokens: 900
          }
        })
      }
    );

    const data = await response.json();

    if (!response.ok) {
      console.error('Medicine search Gemini error:', response.status, data);
      return res.status(502).json({
        ok: false,
        message: 'Medicine search provider request failed.'
      });
    }

    const reply = data?.candidates?.[0]?.content?.parts
      ?.map(p => p.text || '')
      .join('')
      .trim();

    if (!reply) {
      return res.status(502).json({
        ok: false,
        message: 'No verified medicine information was returned.'
      });
    }

    const sources = (data?.groundingMetadata?.groundingChunks || [])
      .map(chunk => ({
        title: chunk?.web?.title || '',
        url: chunk?.web?.uri || ''
      }))
      .filter(source => source.url);

    res.json({
      ok: true,
      medicine,
      reply,
      sources
    });

  } catch (error) {
    console.error('Medicine search error:', error);

    res.status(502).json({
      ok: false,
      message: 'Could not reach the medicine information provider.'
    });
  }
});
app.get('/api/pharmacies', async (req, res) => {
  const lat = Number(req.query.lat);
  const lon = Number(req.query.lon);

  if (!Number.isFinite(lat) || !Number.isFinite(lon)) {
    return res.status(400).json({
      ok: false,
      message: 'Valid latitude and longitude are required.'
    });
  }

  const query = `
    [out:json][timeout:20];
    (
      node["amenity"="pharmacy"](around:5000,${lat},${lon});
      way["amenity"="pharmacy"](around:5000,${lat},${lon});
    );
    out center;
  `;

  const providers = [
    'https://overpass-api.de/api/interpreter',
    'https://overpass.private.coffee/api/interpreter'
  ];

  let data = null;
  let lastError = null;

  for (const provider of providers) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 15000);

      const response = await fetch(provider, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'ResQVerse-AI/1.0'
        },
        body: `data=${encodeURIComponent(query)}`,
        signal: controller.signal
      });

      clearTimeout(timeout);

      if (!response.ok) {
        throw new Error(`Provider returned ${response.status}`);
      }

      data = await response.json();
      break;
    } catch (error) {
      lastError = error;
    }
  }

  if (!data) {
    console.error('Pharmacy provider error:', lastError?.message);
    return res.status(502).json({
      ok: false,
      message: 'Pharmacy data provider is temporarily unavailable.'
    });
  }

  const pharmacies = data.elements
    .map(el => {
      const pLat = el.lat ?? el.center?.lat;
      const pLon = el.lon ?? el.center?.lon;

      return {
        name: el.tags?.name || 'Unnamed pharmacy',
        phone: el.tags?.phone || el.tags?.['contact:phone'] || null,
        lat: Number(pLat),
        lon: Number(pLon)
      };
    })
    .filter(p => Number.isFinite(p.lat) && Number.isFinite(p.lon));

  res.json({
    ok: true,
    pharmacies
  });
});
app.get('/api/hospitals', async (req, res) => {
  const lat = Number(req.query.lat);
  const lon = Number(req.query.lon);

  if (!Number.isFinite(lat) || !Number.isFinite(lon)) {
    return res.status(400).json({
      ok: false,
      message: 'Valid latitude and longitude are required.'
    });
  }

  const delta = 0.07;

  const left = lon - delta;
  const right = lon + delta;
  const top = lat + delta;
  const bottom = lat - delta;

  const params = new URLSearchParams({
    format: 'jsonv2',
    q: '[hospital]',
    viewbox: `${left},${top},${right},${bottom}`,
    bounded: '1',
    limit: '20',
    addressdetails: '1',
    extratags: '1'
  });

  try {
    const r = await fetch(
      `https://nominatim.openstreetmap.org/search?${params.toString()}`,
      {
        headers: {
          'User-Agent': 'ResQVerse-AI/1.0 (student healthcare prototype)'
        }
      }
    );

    if (!r.ok) {
      console.error('Nominatim error:', r.status);
      return res.status(502).json({
        ok: false,
        message: 'Hospital data provider is temporarily unavailable.'
      });
    }

    const data = await r.json();

    const hospitals = data
      .map(item => ({
        name: item.display_name?.split(',')[0] || 'Unnamed hospital',
        lat: Number(item.lat),
        lon: Number(item.lon),
        phone:
          item.extratags?.phone ||
          item.extratags?.['contact:phone'] ||
          null
      }))
      .filter(h =>
        Number.isFinite(h.lat) &&
        Number.isFinite(h.lon)
      );

    res.json({
      ok: true,
      hospitals
    });

  } catch (error) {
    console.error('Hospital provider error:', error.message);

    res.status(502).json({
      ok: false,
      message: 'Could not reach the hospital data provider.'
    });
  }
});
app.use(express.static(path.join(__dirname, 'public')));
app.use((req, res) => { if (req.path.startsWith('/api/')) return res.status(404).json({ ok: false, message: 'API route not found' }); res.sendFile(path.join(__dirname, 'public', 'index.html')); });

connectMongo().finally(() => app.listen(PORT, () => {
  console.log(`ResQVerse AI running at http://localhost:${PORT}`);
  if (!GEMINI_API_KEY) console.warn("ResQ AI: GEMINI_API_KEY is not configured. Add it to .env locally or your hosting provider's environment variables.");
}));
