// src/SidebarChat.jsx

import React from 'react';
import { Avatar } from '@mui/material';
import './SidebarChat.css';

// El componente ahora solo recibe una prop 'onClick' y los datos a mostrar
function SidebarChat({ otherUser, lastMessage, isActive, onClick }) {
  return (
    // Ejecutamos la función onClick que nos pasa el componente padre (Sidebar)
    <div className={`sidebarChat ${isActive ? 'active' : ''}`} onClick={onClick}>
      <Avatar>{otherUser ? otherUser[0].toUpperCase() : '?'}</Avatar>
      <div className="sidebarChat__info">
        <h2>{otherUser}</h2>
        <p>{lastMessage?.ciphertext ? '(Mensaje cifrado)' : lastMessage}</p>
      </div>
    </div>
  );
}

export { SidebarChat };