import React, { useEffect, useState, useRef } from 'react';
import './App.css';
import Sidebar from './Sidebar';
import { Chat } from './Chat';
import SocketIOClient from 'socket.io-client';
import axios from './axios';
import Register from './Register';
import Login from './Login';

const BACKEND_URL = 'http://localhost:9000'; 

function App() {
  const [messages, setMessages] = useState([]);
  const [socket, setSocket] = useState(null);
  const [userName, setUserName] = useState('');
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [showLogin, setShowLogin] = useState(true);
  
  const [activeChatId, setActiveChatId] = useState(null); 
  const [activeChatUser, setActiveChatUser] = useState(null); 
  const currentUserId = useRef(null); 

  useEffect(() => {
    const storedToken = localStorage.getItem('authToken');
    const storedUsername = localStorage.getItem('username');
    const storedUserId = localStorage.getItem('userId'); 
    
    if (storedToken && storedUsername && storedUserId) {
      setIsLoggedIn(true);
      setUserName(storedUsername);
      currentUserId.current = storedUserId; 
      console.log(`Sesión restaurada para el usuario: ${storedUsername} (ID: ${storedUserId})`);
    }
  }, []);

  useEffect(() => {
    if (!isLoggedIn) {
      if (socket) {
        socket.disconnect();
        setSocket(null);
      }
      return; 
    }

    if (isLoggedIn && !socket) {
        console.log("App.js - Conectando Socket.IO...");
        const newSocket = SocketIOClient(BACKEND_URL);
        setSocket(newSocket);

        newSocket.on("connect", () => {
            console.log("App.js - Conectado al servidor de Socket.IO");
            if (currentUserId.current) {
                newSocket.emit('registerUserForNotifications', currentUserId.current);
                console.log(`Socket ${newSocket.id} registrado para notificaciones del usuario ${currentUserId.current}`);
            }
        });

        newSocket.on("message", (newMessage) => {
            console.log("App.js - Nuevo mensaje recibido vía Socket.IO:", newMessage);
            if (activeChatId && newMessage.conversationId && newMessage.conversationId.toString() === activeChatId.toString()) {
                 setMessages((prevMessages) => [...prevMessages, newMessage]);
            } else {
                console.log('Mensaje recibido para otra conversación o sin chat activo. No se actualiza el chat actual.');
            }
        });


        newSocket.on("disconnect", () => {
            console.log("App.js - Desconectado del servidor de Socket.IO");
        });

        return () => {
            if (newSocket) {
                newSocket.disconnect();
            }
        };
    }
  }, [isLoggedIn, socket, activeChatId]); 

  const handleLoginSuccess = (loggedInUsername, loggedInUserId, token) => {
    setIsLoggedIn(true);
    setUserName(loggedInUsername);
    currentUserId.current = loggedInUserId; 
    localStorage.setItem('authToken', token); 
    localStorage.setItem('username', loggedInUsername);
    localStorage.setItem('userId', loggedInUserId); 

    console.log(`Usuario ${loggedInUsername} (ID: ${loggedInUserId}) ha iniciado sesión.`);
    setMessages([]);
    setActiveChatId(null);
    setActiveChatUser(null);

    if (socket) { 
        socket.emit('registerUserForNotifications', loggedInUserId);
        console.log(`Socket registrado para notificaciones del usuario ${loggedInUserId} al iniciar sesión.`);
    }
  };

  const handleRegisterSuccess = () => {
    setShowLogin(true);
  };

  const handleLogout = () => {
    localStorage.removeItem('authToken');
    localStorage.removeItem('username');
    localStorage.removeItem('userId'); 
    setIsLoggedIn(false);
    setUserName('');
    currentUserId.current = null; 
    setShowLogin(true);
    setMessages([]);
    setActiveChatId(null);
    setActiveChatUser(null);
    if (socket) {
      socket.disconnect();
      setSocket(null);
    }
    console.log('Sesión cerrada.');
  };

  const selectChat = async (conversationId, chatUser) => {
      console.log(`Chat seleccionado: ID ${conversationId}, Usuario: ${chatUser}`);
      setActiveChatId(conversationId);
      setActiveChatUser(chatUser);
      setMessages([]); 

      try {
        const token = localStorage.getItem('authToken');
        if (!token) {
            console.error('No se encontró el token de autenticación para cargar mensajes.');
            return;
        }
        const response = await axios.get(`/api/v1/conversations/${conversationId}/messages`, {
            headers: {
                Authorization: `Bearer ${token}`,
            },
        });
        setMessages(response.data);
        console.log(`Mensajes cargados para ${chatUser}:`, response.data);

        if (socket) {
            if (activeChatId) { 
                socket.emit('leaveRoom', activeChatId); 
                console.log(`Dejando sala anterior: ${activeChatId}`);
            }
            socket.emit('joinRoom', conversationId);
            console.log(`Unido a la sala de Socket.IO: ${conversationId}`);
        }

      } catch (error) {
        console.error('Error al cargar mensajes de la conversación:', error.response?.data || error.message);
        setMessages([]); 
      }
  };


  if (!isLoggedIn) {
    return (
      <div className="app">
        {showLogin ? (
          <Login 
            onRegisterClick={() => setShowLogin(false)} 
            onLoginSuccess={(username, userId, token) => handleLoginSuccess(username, userId, token)}
          />
        ) : (
          <Register 
            onLoginClick={() => setShowLogin(true)} 
            onRegisterSuccess={handleRegisterSuccess} 
          />
        )}
      </div>
    );
  }

  return (
    <div className="app">
      <div className="app__body">
        <Sidebar 
          userName={userName} 
          onLogout={handleLogout} 
          selectChat={selectChat} 
          activeChatId={activeChatId} 
          socket={socket} 
        /> 
        {activeChatUser ? (
          <Chat 
            messages={messages} 
            socket={socket} 
            userName={userName} 
            chatUser={activeChatUser} 
            conversationId={activeChatId} 
          />
        ) : (
          <div className="chat__placeholder">
            <h1>Bienvenido a WhatsApp Clone</h1>
            <p>Selecciona un chat existente o inicia una nueva conversación buscando un usuario.</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;