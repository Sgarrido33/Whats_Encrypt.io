import React, { useState, useEffect, useRef } from 'react';
import { Avatar, IconButton } from '@mui/material';
import SearchOutlined from '@mui/icons-material/SearchOutlined';
import AttachFileIcon from '@mui/icons-material/AttachFile';
import MoreVertIcon from '@mui/icons-material/MoreVert';
import InsertEmoticonIcon from '@mui/icons-material/InsertEmoticonOutlined';
import MicIcon from '@mui/icons-material/MicOutlined';
import axios from './axios';
import cryptoService from './crypto-service';
import './Chat.css';

// El componente ahora recibe 'isSessionReady' para controlar el estado del formulario
function Chat({ messages, userName, chatUser, conversationId, otherUserId, isSessionReady }) {
  const [input, setInput] = useState("");
  const messagesEndRef = useRef(null);

  // Efecto para hacer scroll hacia abajo cada vez que llegan mensajes nuevos
  useEffect(() => {
    if (messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [messages]);

  const sendMessage = async (e) => {
    e.preventDefault();

    // Verificamos que haya texto y que la sesión segura esté lista
    if (!input || !isSessionReady) {
        console.error("No se puede enviar el mensaje: El input está vacío o la sesión segura no está lista.");
        return;
    }

    // Ciframos el mensaje usando el ID del otro usuario
    const encryptedPayload = await cryptoService.encrypt(otherUserId, input);

    if (!encryptedPayload) {
      alert("Error: No se pudo cifrar el mensaje.");
      return;
    }

    const messagePayload = {
      message: encryptedPayload,
      name: userName,
      timestamp: new Date().toISOString(),
    };

    const token = localStorage.getItem('authToken');
    if (!token) {
      console.error('No se encontró el token de autenticación.');
      return;
    }

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
        <Avatar>{chatUser ? chatUser[0].toUpperCase() : '?'}</Avatar>
        <div className="chat__headerInfo">
          <h3>{chatUser}</h3>
          <p>Última conexión...</p>
        </div>
        <div className="chat__headerRight">
          <IconButton><SearchOutlined /></IconButton>
          <IconButton><AttachFileIcon /></IconButton>
          <IconButton><MoreVertIcon /></IconButton>
        </div>
      </div>

      <div className="chat__body">
        {messages.map((message, index) => (
          <p
            key={message._id || `msg-${index}`} // Usamos index como fallback por si acaso
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
            // El placeholder y el estado 'disabled' ahora dependen de si la sesión está lista
            placeholder={isSessionReady ? "Escribe un mensaje cifrado" : "Estableciendo conexión segura..."}
            type="text"
            disabled={!isSessionReady}
          />
          <button type="submit" disabled={!isSessionReady}>
            Enviar mensaje
          </button>
        </form>
        <MicIcon />
      </div>
    </div>
  );
}

export { Chat };
