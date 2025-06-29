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

// El componente ahora recibe 'setMessages' para la actualización optimista.
function Chat({ messages, userName, chatUser, conversationId, otherUserId, setMessages }) {
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

    if (!input.trim()) {
        return;
    }

    // --- 1. ACTUALIZACIÓN OPTIMISTA ---
    // Creamos un objeto de mensaje temporal para mostrarlo en la UI al instante.
    const optimisticMessage = {
      _id: `temp_${Date.now()}`, // Usamos un ID temporal para la key de React
      message: input, // ¡Usamos el texto plano!
      name: userName,
      timestamp: new Date().toISOString(),
      senderId: localStorage.getItem('userId'), // Añadimos nuestro propio ID
    };

    // Añadimos el mensaje optimista a la lista de mensajes del componente App.
    setMessages((prevMessages) => [...prevMessages, optimisticMessage]);

    // Guardamos el input y limpiamos el campo de texto de inmediato.
    const messageToSend = input;
    setInput("");

    // --- 2. PROCESO DE FONDO (ENCRYPT & SEND) ---
    // Ciframos y enviamos el mensaje al backend.
    const encryptedPayload = await cryptoService.encryptECIES(otherUserId, messageToSend);

    if (!encryptedPayload) {
      alert("Error: No se pudo cifrar el mensaje. Revisa la consola.");
      // Opcional: podrías implementar una lógica para eliminar el mensaje optimista si falla el cifrado.
      return;
    }

    const messagePayload = {
      message: encryptedPayload,
      name: userName,
      timestamp: optimisticMessage.timestamp, // Usamos el mismo timestamp
    };

    const token = localStorage.getItem('authToken');

    try {
      // Enviamos el mensaje cifrado en segundo plano. El usuario no tiene que esperar.
      await axios.post(`/api/v1/conversations/${conversationId}/messages/new`, messagePayload, {
        headers: { Authorization: `Bearer ${token}` },
      });
    } catch (error) {
        console.error('Error al enviar mensaje cifrado:', error.response?.data || error.message);
        alert(`Error al enviar mensaje: ${error.response?.data?.message || error.message}`);
        // Opcional: Manejar el fallo, ej. mostrando un icono de "no enviado" en el mensaje.
    }
  };

  if (!chatUser || !conversationId) {
    return (
      <div className="chat">
        <div className="chat__placeholder">
          <h1>Bienvenido a tu Chat Cifrado</h1>
          <p>Selecciona una conversación o busca un usuario para empezar.</p>
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