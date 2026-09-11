// Minimal E2EE relay. Server stores ONLY ciphertext.
// Room identity = SHA-256 hex of the user code (computed client-side).
// The code itself is kept in the URL hash (#c=...) so it never hits server logs.
// No accounts, no message plaintext, no IP persistence (in-memory rate limit only).

const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'rooms.json');
const MAX_MSG_PER_ROOM = 1000;
const MAX_BODY_BYTES = 12 * 1024;

fs.mkdirSync(DATA_DIR, { recursive: true });

let db = { rooms: {} };
try {
  if (fs.existsSync(DATA_FILE)) {
    db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    if (!db.rooms) db.rooms = {};
  }
} catch (e) {
  console.error('load db failed, starting empty:', e.message);
}

let saveTimer = null;
function save() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    try {
      const tmp = DATA_FILE + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify(db));
      fs.renameSync(tmp, DATA_FILE);
    } catch (e) {
      console.error('save failed:', e.message);
    }
  }, 500);
}

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '32kb' }));

// Security headers, CSP allows only self (no analytics/trackers)
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
  );
  next();
});

// In-memory rate limit only (never written to disk)
const hits = new Map();
function rateLimit(req, res, next) {
  const now = Date.now();
  const key = req.ip || 'x';
  const arr = (hits.get(key) || []).filter((t) => now - t < 60_000);
  arr.push(now);
  hits.set(key, arr);
  if (arr.length > 90) return res.status(429).json({ error: 'slow down' });
  next();
}
app.use('/api/', rateLimit);

const ROOM_RE = /^[0-9a-f]{64}$/;
function checkRoom(req, res, next) {
  if (!ROOM_RE.test(req.params.roomId)) return res.status(400).json({ error: 'bad room' });
  next();
}
function isB64(s, maxLen) {
  if (typeof s !== 'string' || s.length === 0 || s.length > maxLen) return false;
  if (!/^[A-Za-z0-9+/=_-]+$/.test(s)) return false;
  try {
    const b = Buffer.from(s, 'base64');
    return b.length > 0 && b.length <= MAX_BODY_BYTES;
  } catch {
    return false;
  }
}

// Create room (idempotent)
app.post('/api/rooms', (req, res) => {
  const { roomId } = req.body || {};
  if (!ROOM_RE.test(roomId || '')) return res.status(400).json({ error: 'bad roomId' });
  if (!db.rooms[roomId]) {
    db.rooms[roomId] = { createdAt: Date.now(), messages: [] };
    save();
  }
  res.json({ ok: true });
});

// Fetch messages
app.get('/api/rooms/:roomId/messages', checkRoom, (req, res) => {
  const room = db.rooms[req.params.roomId];
  if (!room) return res.json({ messages: [] });
  const since = Number(req.query.since || 0);
  const msgs = since
    ? room.messages.filter((m) => m.ts > since)
    : room.messages.slice(-200);
  res.json({ messages: msgs.slice(-200) });
});

// Post ciphertext message {iv, data} — both base64, data = AES-GCM of JSON
app.post('/api/rooms/:roomId/messages', checkRoom, (req, res) => {
  const { iv, data } = req.body || {};
  if (!isB64(iv, 64) || !isB64(data, 16000)) {
    return res.status(400).json({ error: 'bad payload' });
  }
  let room = db.rooms[req.params.roomId];
  if (!room) {
    room = db.rooms[req.params.roomId] = { createdAt: Date.now(), messages: [] };
  }
  const msg = {
    id: crypto.randomBytes(8).toString('hex'),
    iv,
    data,
    ts: Date.now(),
  };
  room.messages.push(msg);
  if (room.messages.length > MAX_MSG_PER_ROOM) {
    room.messages = room.messages.slice(-MAX_MSG_PER_ROOM);
  }
  save();
  res.json({ ok: true, id: msg.id, ts: msg.ts });
});

// Permanent delete
app.delete('/api/rooms/:roomId', checkRoom, (req, res) => {
  delete db.rooms[req.params.roomId];
  save();
  res.json({ ok: true });
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1h' }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log('chat on :' + PORT + ' data=' + DATA_DIR));
