const express = require('express');
const mongoose = require('mongoose');
const http = require('http'); 
const { Server } = require('socket.io'); 
const cors = require('cors'); 

// App config
const app = express();
const port = process.env.PORT || 9000; 
// Mongodb Atlas (la base de datos)
const connection_url = 'mongodb+srv://TacV0WqoHjQkLZtq:contraseñacambiada@whats.pdy6fht.mongodb.net/?retryWrites=true&w=majority&appName=Whats';

app.use(express.json()); // Parsear JSON en las peticiones
app.use(cors()); // Habilita CORS todas las rutas

// DB config
mongoose.connect(connection_url)
    .then(() => console.log("MongoDB connected"))
    .catch(err => console.error("MongoDB connection error:", err));

const messageSchema = new mongoose.Schema({
    message: String,
    name: String,
    timestamp: String,
    received: Boolean
});

const Message = mongoose.model('messagecontents', messageSchema);

app.get('/', (req, res) => res.status(200).send('Funciona'));

app.post('/api/v1/messages/new', (req, res) => {
    const dbMessage = req.body;

    Message.create(dbMessage)
        .then(data => {
            res.status(201).send(data);
        })
        .catch(err => res.status(500).send(err));
});

app.get('/api/v1/messages/sync', (req, res) => {
    Message.find()
        .then(data => res.status(200).send(data))
        .catch(err => res.status(500).send(err));
});


// Configuración Socket.IO

// Servidor HTTP
const server = http.createServer(app); 

// Adjunta Socket.IO al servidor HTTP
const io = new Server(server, {
    cors: {
        origin: "http://localhost:3000", 
        methods: ["GET", "POST"]
    }
});

// Listener de conexión Socket.IO
io.on('connection', (socket) => {
    console.log('Un cliente se ha conectado a Socket.IO. Socket ID:', socket.id);

    // Escuchar un evento 'message' enviado cliente
    socket.on('message', (message) => {
        console.log('Mensaje recibido de Socket.IO:', message);
        
        Message.create(message)
            .then(data => {
                io.emit('message', data); 
            })
            .catch(err => console.error("Error al guardar mensaje:", err));
    });

    // Evento de desconexión
    socket.on('disconnect', () => {
        console.log('Un cliente se ha desconectado de Socket.IO. Socket ID:', socket.id);
    });
});

// Listen 
server.listen(port, () => console.log(`Backend server listening on localhost:${port}`));