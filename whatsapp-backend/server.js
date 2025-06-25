require('dotenv').config();
const Keys = require('./models/Keys');
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const User = require('./models/User');
const Message = require('./models/Message');
const Conversation = require('./models/Conversation'); 

const http = require('http');
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*", 
    methods: ["GET", "POST"]
  }
});

const port = process.env.PORT || 9000;

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log('MongoDB conectado exitosamente'))
  .catch(err => console.error('Error de conexión a MongoDB:', err));


app.use(express.json());
app.use(cors());

const protect = (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    try {
      token = req.headers.authorization.split(' ')[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded.id; 
      next();
    } catch (error) {
      console.error('Token inválido:', error);
      res.status(401).json({ message: 'No autorizado, token fallido' });
    }
  }
  if (!token) {
    res.status(401).json({ message: 'No autorizado, no hay token' });
  }
};

app.get("/", (req, res) => res.status(200).send("hola mundo"));

app.post('/api/v1/auth/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: 'Por favor, ingresa un nombre de usuario y una contraseña.' });
  try {
    const userExists = await User.findOne({ username });
    if (userExists) return res.status(409).json({ message: 'El nombre de usuario ya está en uso.' });
    const user = await User.create({ username, password });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.status(201).json({ message: 'Usuario registrado exitosamente', _id: user._id, username: user.username, token: token });
  } catch (error) {
    console.error('Error al registrar usuario:', error);
    res.status(500).json({ message: 'Error interno del servidor al registrar usuario.' });
  }
});

app.post('/api/v1/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: 'Por favor, ingresa tu nombre de usuario y contraseña.' });
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ message: 'Credenciales inválidas (usuario no encontrado).' });
    const isMatch = await user.matchPassword(password);
    if (!isMatch) return res.status(401).json({ message: 'Credenciales inválidas (contraseña incorrecta).' });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.status(200).json({ message: 'Inicio de sesión exitoso', _id: user._id, username: user.username, token: token });
  } catch (error) {
    console.error('Error al iniciar sesión:', error);
    res.status(500).json({ message: 'Error interno del servidor al iniciar sesión.' });
  }
});

app.get('/api/v1/users/search', protect, async (req, res) => {
  const { q } = req.query; 
  if (!q) {
    return res.status(400).json({ message: 'Por favor, proporciona un término de búsqueda.' });
  }
  try {
    const users = await User.find({
      username: { $regex: q, $options: 'i' },
      _id: { $ne: req.user } 
    }).select('username'); 
    
    res.status(200).json(users);
  } catch (error) {
    console.error('Error al buscar usuarios:', error);
    res.status(500).json({ message: 'Error interno del servidor al buscar usuarios.' });
  }
});

app.post('/api/v1/conversations', protect, async (req, res) => {
  const { participantId } = req.body; 
  const currentUserId = req.user; 

  if (!participantId || !mongoose.Types.ObjectId.isValid(participantId)) {
    return res.status(400).json({ message: 'ID de participante inválido.' });
  }

  if (currentUserId.toString() === participantId.toString()) {
      return res.status(400).json({ message: 'No puedes iniciar una conversación contigo mismo.' });
  }

  try {
    let conversation = await Conversation.findOne({
      participants: { $all: [currentUserId, participantId] }
    }).populate('participants', 'username'); 

    if (conversation) {
      return res.status(200).json(conversation);
    } else {
      conversation = await Conversation.create({
        participants: [currentUserId, participantId],
      });
      conversation = await conversation.populate('participants', 'username');
      return res.status(201).json(conversation);
    }
  } catch (error) {
    console.error('Error al crear/obtener conversación:', error);
    res.status(500).json({ message: 'Error interno del servidor al procesar la conversación.' });
  }
});

app.post('/api/v1/keys/upload', protect, async (req, res) => {
  // Ahora solo esperamos una 'publicKey' en el cuerpo de la petición
  const { publicKey } = req.body;
  const currentUserId = req.user;

  if (!publicKey) {
    return res.status(400).json({ message: 'No se proporcionó la clave pública.' });
  }

  try {
    // La clave vendrá del cliente en formato Base64, la guardamos como Buffer
    const keyData = {
      userId: currentUserId,
      publicKey: Buffer.from(publicKey, 'base64'),
    };
    
    // Usamos 'findOneAndUpdate' con 'upsert' para crear o actualizar la clave del usuario.
    await Keys.findOneAndUpdate({ userId: currentUserId }, keyData, { upsert: true, new: true });

    res.status(201).json({ message: 'Clave pública almacenada exitosamente.' });
  } catch (error) {
    console.error('Error al guardar la clave pública:', error);
    res.status(500).json({ message: 'Error interno del servidor al guardar la clave.' });
  }
});

app.get('/api/v1/keys/:userId', protect, async (req, res) => {
  const { userId } = req.params;

  if (!mongoose.Types.ObjectId.isValid(userId)) {
    return res.status(400).json({ message: 'ID de usuario inválido.' });
  }

  try {
    const keyDoc = await Keys.findOne({ userId });

    if (!keyDoc) {
      return res.status(404).json({ message: 'No se encontró la clave para este usuario.' });
    }

    // Devolvemos la clave pública en formato Base64 para que sea fácil de usar en el frontend
    res.status(200).json({
      publicKey: keyDoc.publicKey.toString('base64'),
    });

  } catch (error)
  {
    console.error('Error al obtener la clave pública:', error);
    res.status(500).json({ message: 'Error interno del servidor al obtener la clave.' });
  }
});
app.get('/api/v1/keys/signal/:userId', protect, async (req, res) => {
  const targetUserId = req.params.userId;

  try {
    const keyBundleDocument = await SignalKey.findOne({ userId: targetUserId });

    if (!keyBundleDocument) {
      return res.status(404).json({ message: 'No se encontró el paquete de claves para este usuario.' });
    }

    const oneTimePreKey = keyBundleDocument.oneTimePreKeys.pop();
    
    if (!oneTimePreKey) {
        return res.status(500).json({ message: 'El usuario no tiene más claves de un solo uso disponibles.' });
    }
    
    await keyBundleDocument.save();

    const responseBundle = {
      userId: keyBundleDocument.userId,
      identityKey: keyBundleDocument.identityKey,
      signedPreKey: keyBundleDocument.signedPreKey,
      oneTimePreKey: oneTimePreKey 
    };

    res.status(200).json(responseBundle);

  } catch (error) {
    console.error('Error al obtener el paquete de claves de Signal:', error);
    res.status(500).json({ message: 'Error interno del servidor al obtener las claves.' });
  }
});

app.get('/api/v1/conversations', protect, async (req, res) => {
    try {
        const conversations = await Conversation.find({
            participants: req.user 
        })
        .populate('participants', 'username') 
        .sort({ updatedAt: -1 }); 
        
        const conversationsWithOtherUser = conversations.map(conv => {
            const otherParticipant = conv.participants.find(p => p._id.toString() !== req.user.toString());
            return {
                _id: conv._id,
                otherUser: otherParticipant ? otherParticipant.username : 'Usuario Desconocido', 
                otherUserId: otherParticipant ? otherParticipant._id : null,
                lastMessage: conv.lastMessage,
                lastMessageSender: conv.lastMessageSender,
                updatedAt: conv.updatedAt,
            };
        });

        res.status(200).json(conversationsWithOtherUser);
    } catch (error) {
        console.error('Error al obtener conversaciones:', error);
        res.status(500).json({ message: 'Error interno del servidor al obtener conversaciones.' });
    }
});

app.get("/api/v1/conversations/:conversationId/messages", protect, async (req, res) => {
  const { conversationId } = req.params;
  const currentUserId = req.user;

  try {
    const conversation = await Conversation.findById(conversationId);
    if (!conversation || !conversation.participants.includes(currentUserId)) {
      return res.status(403).json({ message: 'No tienes acceso a esta conversación.' });
    }

    const messages = await Message.find({ conversationId }).sort({ timestamp: 1 }); 
    res.status(200).send(messages);
  } catch (err) {
    console.error("Error al obtener mensajes de conversación:", err);
    res.status(500).send(err);
  }
});

app.post('/api/v1/keys/register-signal', protect, async (req, res) => {
  const currentUserId = req.user;
  
  const { identityKey, signedPreKey, oneTimePreKeys } = req.body;

  if (!identityKey || !signedPreKey || !oneTimePreKeys) {
    return res.status(400).json({ message: 'Faltan datos en el paquete de claves.' });
  }

  try {
    const keyData = {
      userId: currentUserId,
      identityKey: identityKey,
      signedPreKey: signedPreKey,
      oneTimePreKeys: oneTimePreKeys,
    };

    await SignalKey.findOneAndUpdate(
      { userId: currentUserId }, 
      keyData,                  
      { upsert: true, new: true } 
    );

    res.status(201).json({ message: 'Paquete de claves de Signal almacenado exitosamente.' });
  } catch (error) {
    console.error('Error al guardar el paquete de claves de Signal:', error);
    res.status(500).json({ message: 'Error interno del servidor al guardar las claves.' });
  }
});

app.post("/api/v1/conversations/:conversationId/messages/new", protect, async (req, res) => {
  const { conversationId } = req.params;
  const currentUserId = req.user;
  const { message, name, timestamp } = req.body; 

  if (!message || !name || !timestamp) {
      return res.status(400).json({ message: 'Faltan campos requeridos para el mensaje.' });
  }

  try {
    const conversation = await Conversation.findById(conversationId);
    if (!conversation || !conversation.participants.includes(currentUserId)) {
      return res.status(403).json({ message: 'No tienes acceso a esta conversación o la conversación no existe.' });
    }

    const dbMessage = {
      conversationId: conversationId,
      message: message,
      name: name,
      senderId: currentUserId, 
      timestamp: timestamp,
      received: false, 
    };

    const createdMessage = await Message.create(dbMessage);
    io.to(conversationId).emit('message', createdMessage);

    await Conversation.findByIdAndUpdate(conversationId, {
        lastMessage: createdMessage.message,
        lastMessageSender: name,
        updatedAt: new Date(),
    });

    res.status(201).send(createdMessage);
  } catch (err) {
    console.error("Error al guardar mensaje:", err);
    res.status(500).send(err);
  }
});


const db = mongoose.connection;
db.once('open', () => {
  console.log("DB Conectada para Change Stream");

  const convCollection = db.collection('conversations'); 
  const convChangeStream = convCollection.watch();

  convChangeStream.on('change', async (change) => {
      console.log("Cambio detectado en conversaciones:", change);
      if (change.operationType === 'insert' || change.operationType === 'update') {
          const convId = change.documentKey._id;
          const conversation = await Conversation.findById(convId).populate('participants', 'username');
          if (conversation) {
              conversation.participants.forEach(participant => {
                  io.to(participant._id.toString()).emit('conversationUpdate', {
                      _id: conversation._id,
                      otherUser: conversation.participants.find(p => p._id.toString() !== participant._id.toString()).username,
                      otherUserId: conversation.participants.find(p => p._id.toString() !== participant._id.toString())._id,
                      lastMessage: conversation.lastMessage,
                      lastMessageSender: conversation.lastMessageSender,
                      updatedAt: conversation.updatedAt,
                  });
              });
          }
      }
  });
});

io.on('connection', (socket) => {
    console.log('Cliente Socket.IO conectado:', socket.id);

    socket.on('joinRoom', (conversationId) => {
        socket.join(conversationId.toString()); 
        console.log(`Socket ${socket.id} unido a la sala ${conversationId}`);
    });

    socket.on('leaveRoom', (conversationId) => {
        socket.leave(conversationId.toString());
        console.log(`Socket ${socket.id} abandonó la sala ${conversationId}`);
    });

    socket.on('registerUserForNotifications', (userId) => {
        socket.join(userId.toString()); 
        console.log(`Socket ${socket.id} registrado para notificaciones del usuario ${userId}`);
    });

    socket.on('disconnect', () => {
        console.log('Cliente Socket.IO desconectado:', socket.id);
    });
});


server.listen(port, () => console.log(`Listening on localhost:${port}`));