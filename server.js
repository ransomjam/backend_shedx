
import 'dotenv/config';
import express from 'express';
import http from 'http';
import cors from 'cors';
import morgan from 'morgan';
import jwt from 'jsonwebtoken';
import { Server as SocketIOServer } from 'socket.io';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';

const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: {
    origin: (process.env.SOCKET_ORIGIN || '*').split(','),
    methods: ['GET','POST','PUT','DELETE','PATCH','OPTIONS'],
    credentials: true,
  },
});

app.use(cors({
  origin: (process.env.CORS_ORIGIN || '*').split(','),
  credentials: true,
}));
app.use(express.json());
app.use(morgan('dev'));

// --- In-memory data (mock) ---
const products = [
  { id: 'p1', title: 'Granite (20mm)', price: 25000, image: 'https://picsum.photos/seed/rock1/400', sellerId: 'u1' },
  { id: 'p2', title: 'Sand (Sharp)', price: 15000, image: 'https://picsum.photos/seed/sand2/400', sellerId: 'u2' },
  { id: 'p3', title: 'Cement (50kg)', price: 7800, image: 'https://picsum.photos/seed/cement3/400', sellerId: 'u3' },
];
const users = []; // { id, name, email, passwordHash }
const messages = {}; // chatId -> [{ id, from, to, text, ts }]

// --- Helpers ---
function sign(user) {
  return jwt.sign({ id: user.id, name: user.name, email: user.email }, process.env.JWT_SECRET || 'dev_secret', { expiresIn: '7d' });
}

function auth(req, res, next) {
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'dev_secret');
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// --- Health ---
app.get('/api/health', (_req, res) => res.json({ ok: true }));

// --- Products ---
app.get('/api/products', (_req, res) => res.json(products));
app.post('/api/products', auth, (req, res) => {
  const { title, price, image } = req.body;
  const p = { id: uuidv4(), title, price, image: image || '', sellerId: req.user.id };
  products.push(p);
  res.status(201).json(p);
});

// --- Auth ---
import crypto from 'crypto';
function hash(pw) { return bcrypt.hashSync(pw, 10); }
function compare(pw, hash) { return bcrypt.compareSync(pw, hash); }

app.post('/api/auth/register', (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });
  if (users.find(u => u.email === email)) return res.status(409).json({ error: 'Email exists' });
  const user = { id: uuidv4(), name, email, passwordHash: hash(password) };
  users.push(user);
  const token = sign(user);
  res.json({ token, user: { id: user.id, name, email } });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  const user = users.find(u => u.email === email);
  if (!user || !compare(password, user.passwordHash)) return res.status(401).json({ error: 'Invalid credentials' });
  const token = sign(user);
  res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
});

app.get('/api/auth/me', auth, (req, res) => {
  res.json({ id: req.user.id, name: req.user.name, email: req.user.email });
});

// --- Orders (mock checkout) ---
app.post('/api/orders/checkout', auth, (req, res) => {
  const { items, amount } = req.body || {};
  // pretend to process payment
  res.json({ status: 'ok', ref: uuidv4(), amount, items });
});

// --- Messaging (mock) ---
app.get('/api/messages/:chatId', auth, (req, res) => {
  const chatId = req.params.chatId;
  res.json(messages[chatId] || []);
});

io.on('connection', (socket) => {
  socket.on('join', (room) => {
    socket.join(room);
  });
  socket.on('message', ({ chatId, from, to, text }) => {
    const msg = { id: uuidv4(), from, to, text, ts: Date.now() };
    messages[chatId] = messages[chatId] || [];
    messages[chatId].push(msg);
    io.to(chatId).emit('message', msg);
  });
});

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
  console.log(`Mock API running on :${PORT}`);
});
