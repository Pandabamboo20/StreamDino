const express = require('express');
const { WebSocketServer, WebSocket } = require('ws');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const http = require('http');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// ── IN-MEMORY STATE ──
// rooms[roomName] = { passHash, streamer: ws|null, viewers: Map<id, ws> }
const rooms = new Map();

// ── REST: crear / verificar sala ──

// POST /api/rooms — crear sala (streamer se registra)
app.post('/api/rooms', async (req, res) => {
  const { room, password } = req.body;
  if (!room || !password)
    return res.status(400).json({ error: 'room y password requeridos' });
  if (!/^[a-zA-Z0-9_-]{2,32}$/.test(room))
    return res.status(400).json({ error: 'Nombre de sala inválido (2-32 chars, sin espacios)' });
  if (rooms.has(room))
    return res.status(409).json({ error: 'Sala ya existe' });
  if (password.length < 4)
    return res.status(400).json({ error: 'Contraseña mínimo 4 caracteres' });

  const passHash = await bcrypt.hash(password, 8);
  rooms.set(room, { passHash, streamer: null, viewers: new Map() });
  res.status(201).json({ ok: true, room });
});

// POST /api/rooms/:room/auth — login de streamer
app.post('/api/rooms/:room/auth', async (req, res) => {
  const { password } = req.body;
  const roomData = rooms.get(req.params.room);
  if (!roomData) return res.status(404).json({ error: 'Sala no encontrada' });

  const ok = await bcrypt.compare(password, roomData.passHash);
  if (!ok) return res.status(401).json({ error: 'Contraseña incorrecta' });

  // Token simple — solo para que el WS sepa que es streamer
  const token = Buffer.from(`${req.params.room}:${Date.now()}`).toString('base64');
  res.json({ ok: true, token });
});

// GET /api/rooms/:room — ¿existe la sala?
app.get('/api/rooms/:room', (req, res) => {
  const exists = rooms.has(req.params.room);
  res.json({ exists, hasStreamer: exists && rooms.get(req.params.room).streamer !== null });
});

// Servir el frontend para cualquier ruta no-API
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── WEBSOCKET ──
wss.on('connection', (ws, req) => {
  ws.id = uuidv4();
  ws.room = null;
  ws.role = null; // 'streamer' | 'viewer'

  ws.sendJSON = (obj) => {
    if (ws.readyState === WebSocket.OPEN)
      ws.send(JSON.stringify(obj));
  };

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    switch (msg.type) {

      // ── VIEWER entra a sala ──
      case 'viewer:join': {
        const { room } = msg;
        const roomData = rooms.get(room);
        if (!roomData) return ws.sendJSON({ type: 'error', code: 'NO_ROOM' });

        ws.room = room;
        ws.role = 'viewer';
        roomData.viewers.set(ws.id, ws);

        ws.sendJSON({ type: 'viewer:joined', viewerId: ws.id });

        // Avisar al streamer que entró un viewer
        if (roomData.streamer) {
          roomData.streamer.sendJSON({ type: 'viewer:connected', viewerId: ws.id });
        }
        break;
      }

      // ── STREAMER entra a sala ──
      case 'streamer:join': {
        const { room, token } = msg;
        const roomData = rooms.get(room);
        if (!roomData) return ws.sendJSON({ type: 'error', code: 'NO_ROOM' });

        // Verificar token (contiene el nombre de la sala)
        try {
          const decoded = Buffer.from(token, 'base64').toString();
          if (!decoded.startsWith(room + ':')) throw new Error();
        } catch {
          return ws.sendJSON({ type: 'error', code: 'BAD_TOKEN' });
        }

        // Desconectar streamer anterior si lo hay
        if (roomData.streamer && roomData.streamer !== ws) {
          roomData.streamer.sendJSON({ type: 'error', code: 'REPLACED' });
          roomData.streamer.close();
        }

        ws.room = room;
        ws.role = 'streamer';
        roomData.streamer = ws;

        ws.sendJSON({ type: 'streamer:joined', viewerCount: roomData.viewers.size });
        break;
      }

      // ── VIEWER envía metadata de video ──
      case 'viewer:video': {
        const roomData = rooms.get(ws.room);
        if (!roomData || ws.role !== 'viewer') return;
        if (!roomData.streamer) return ws.sendJSON({ type: 'error', code: 'NO_STREAMER' });

        // Relay al streamer: metadata + id del viewer (para el relay de blob)
        roomData.streamer.sendJSON({
          type: 'video:queued',
          viewerId: ws.id,
          name: String(msg.name).slice(0, 200),
          duration: Number(msg.duration) || 0,
        });
        break;
      }

      // ── STREAMER pide el blob a un viewer específico ──
      case 'streamer:request_blob': {
        const roomData = rooms.get(ws.room);
        if (!roomData || ws.role !== 'streamer') return;

        const viewer = roomData.viewers.get(msg.viewerId);
        if (!viewer) return ws.sendJSON({ type: 'error', code: 'VIEWER_GONE', viewerId: msg.viewerId });

        viewer.sendJSON({ type: 'viewer:send_blob', requestId: msg.requestId });
        break;
      }

      // ── VIEWER envía el blob (como base64 chunk) ──
      case 'viewer:blob_chunk': {
        const roomData = rooms.get(ws.room);
        if (!roomData || ws.role !== 'viewer') return;
        if (!roomData.streamer) return;

        // Relay del chunk al streamer
        roomData.streamer.sendJSON({
          type: 'blob:chunk',
          viewerId: ws.id,
          requestId: msg.requestId,
          chunk: msg.chunk,       // base64 string
          index: msg.index,
          total: msg.total,
        });
        break;
      }

      // ── STREAMER → broadcast estado a todos los viewers ──
      case 'streamer:state': {
        const roomData = rooms.get(ws.room);
        if (!roomData || ws.role !== 'streamer') return;

        const payload = { type: 'room:state', ...msg.state };
        roomData.viewers.forEach(v => v.sendJSON(payload));
        break;
      }

      // ── VIEWER vota ──
      case 'viewer:vote': {
        const roomData = rooms.get(ws.room);
        if (!roomData || ws.role !== 'viewer') return;
        if (!roomData.streamer) return;

        roomData.streamer.sendJSON({
          type: 'vote:received',
          viewerId: ws.id,
          vote: msg.vote, // 'like' | 'dislike'
        });
        break;
      }
    }
  });

  ws.on('close', () => {
    if (!ws.room) return;
    const roomData = rooms.get(ws.room);
    if (!roomData) return;

    if (ws.role === 'streamer') {
      roomData.streamer = null;
      // Avisar a viewers que el streamer se fue
      roomData.viewers.forEach(v => v.sendJSON({ type: 'streamer:offline' }));
    } else if (ws.role === 'viewer') {
      roomData.viewers.delete(ws.id);
      if (roomData.streamer) {
        roomData.streamer.sendJSON({ type: 'viewer:disconnected', viewerId: ws.id });
      }
    }
  });

  ws.on('error', () => {});
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`StreamDino server on :${PORT}`));
