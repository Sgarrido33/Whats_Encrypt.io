import React, { useState, useEffect, useRef } from 'react'; 
import './Chat.css';
import { Avatar, IconButton } from '@mui/material';
import SearchOutlined from '@mui/icons-material/SearchOutlined';
import AttachFileIcon from '@mui/icons-material/AttachFile';
import MoreVertIcon from '@mui/icons-material/MoreVert';
import InsertEmoticonIcon from '@mui/icons-material/InsertEmoticonOutlined';
import MicIcon from '@mui/icons-material/MicOutlined';
import axios from './axios';

function Chat({ messages, socket, userName, chatUser, conversationId }) {
  const [input, setInput] = useState("");
  const messagesEndRef = useRef(null); 

  useEffect(() => {
    if (messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [messages]);

  const sendMessage = (e) => {
    e.preventDefault();

    if (!input || !socket || !chatUser || !conversationId) { 
        console.error("No se pudo enviar el mensaje: Faltan input, socket, chatUser o conversationId.", { input, socket, chatUser, conversationId });
        return;
    }

    const messagePayload = {
      message: input,
      name: userName, 
      timestamp: new Date().toISOString(), 
    };

    const token = localStorage.getItem('authToken');
    if (!token) {
      console.error('No se encontró el token de autenticación para enviar el mensaje.');
      return;
    }

    axios.post(`/api/v1/conversations/${conversationId}/messages/new`, messagePayload, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    })
    .then(response => {
        console.log('Mensaje enviado al backend:', response.data);
    })
    .catch(error => {
        console.error('Error al enviar mensaje:', error.response?.data || error.message);
        alert(`Error al enviar mensaje: ${error.response?.data?.message || error.message}`);
    });

    setInput("");
  };


  if (!chatUser || !conversationId) { 
    return (
      <div className="chat">
        <div className="chat__placeholder">
          <h1>Bienvenido a WhatsApp Clone</h1>
          <p>Selecciona un chat existente o inicia una nueva conversación buscando un usuario.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="chat">
      <div className="chat__header">
        <Avatar src={`https://avatars.dicebear.com/api/human/${chatUser}.svg`} />
        <div className="chat__headerInfo">
          <h3>{chatUser}</h3> 
          <p>Última vez hoy a la 1:30 PM</p> 
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
        <form>
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Type a message"
            type="text"
          />
          <button onClick={sendMessage} type="submit">
            Send a message
          </button>
        </form>
        <MicIcon />
      </div>
    </div>
  );
}

export { Chat };