import React, { useState, useEffect, useRef } from 'react'; 
import './Chat.css';
import { Avatar, IconButton } from '@mui/material';
import SearchOutlined from '@mui/icons-material/SearchOutlined';
import AttachFileIcon from '@mui/icons-material/AttachFile';
import MoreVertIcon from '@mui/icons-material/MoreVert';
import InsertEmoticonIcon from '@mui/icons-material/InsertEmoticonOutlined';
import MicIcon from '@mui/icons-material/MicOutlined';
import axios from './axios';
import cryptoService from './crypto-service';

function Chat({ messages, socket, userName, chatUser, conversationId, otherUserId }) {
  const [input, setInput] = useState("");
  const messagesEndRef = useRef(null); 

  useEffect(() => {
    if (messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [messages]);

  const sendMessage = async (e) => {
    e.preventDefault();

    if (!input || !conversationId || !otherUserId) {
        console.error("No se puede enviar el mensaje: Faltan datos esenciales (input, conversationId, or otherUserId).");
        return;
    }

    // --- PASO 1: CIFRADO DEL MENSAJE ---
    const encryptedPayload = cryptoService.encrypt(otherUserId, input);

    if (!encryptedPayload) {
      alert("Error: No se pudo cifrar el mensaje. La sesión segura podría no estar establecida.");
      return;
    }

    // El payload que se envía al backend ahora contiene el objeto cifrado
    const messagePayload = {
      message: encryptedPayload, // Ya no es texto plano
      name: userName,
      timestamp: new Date().toISOString(),
    };

    const token = localStorage.getItem('authToken');
    if (!token) {
      console.error('No se encontró el token de autenticación para enviar el mensaje.');
      return;
    }

    // --- PASO 2: ENVÍO DEL PAYLOAD CIFRADO ---
    try {
      await axios.post(`/api/v1/conversations/${conversationId}/messages/new`, messagePayload, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      console.log('Mensaje cifrado enviado al backend.');
    } catch (error) {
        console.error('Error al enviar mensaje cifrado:', error.response?.data || error.message);
        alert(`Error al enviar mensaje: ${error.response?.data?.message || error.message}`);
    }

    setInput("");
  };

  // Un placeholder si no hay ningún chat activo seleccionado
  if (!chatUser || !conversationId) {
    return (
      <div className="chat">
        <div className="chat__placeholder">
          <h1>Bienvenido a WhatsApp Clone</h1>
          <p>Selecciona un chat para empezar a enviar mensajes cifrados.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="chat">
      <div className="chat__header">
        {/* Usamos la inicial del usuario para el Avatar */}
        <Avatar>{chatUser ? chatUser[0].toUpperCase() : '?'}</Avatar>
        <div className="chat__headerInfo">
          <h3>{chatUser}</h3>
          <p>Última conexión...</p>
        </div>
        <div className="chat__headerRight">
          <IconButton>
            <SearchOutlined />
          </IconButton>
          <IconButton>
            <AttachFileIcon />
          </IconButton>
          <IconButton>
            <MoreVertIcon />
          </IconButton>
        </div>
      </div>

      <div className="chat__body">
        {/* Mapeamos y mostramos los mensajes (que ya llegan descifrados desde App.jsx) */}
        {messages.map((message) => (
          <p
            key={message._id}
            className={`chat__message ${message.name === userName ? 'chat__sent' : ''}`}
          >
            <span className="chat__name">{message.name}</span>
            {message.message}
            <span className="chat__timestamp">
              {new Date(message.timestamp).toLocaleString()}
            </span>
          </p>
        ))}
        <div ref={messagesEndRef} />
      </div>

      <div className="chat__footer">
        <InsertEmoticonIcon />
        <form onSubmit={sendMessage}>
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Escribe un mensaje cifrado"
            type="text"
          />
          <button type="submit">
            Enviar mensaje
          </button>
        </form>
        <MicIcon />
      </div>
    </div>
  );
}

export { Chat };