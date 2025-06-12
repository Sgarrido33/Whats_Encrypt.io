import React, { useEffect, useState, useRef } from 'react';
import { io } from "socket.io-client"; // Importación correcta
import Sidebar from './Sidebar';
import { Chat } from './Chat';
import Register from './Register';
import Login from './Login';
import axios from './axios';
import cryptoService from './crypto-service';
import './App.css';

const BACKEND_URL = 'http://localhost:9000';

function App() {
  const [messages, setMessages] = useState([]);
  const [socket, setSocket] = useState(null);
  const [userName, setUserName] = useState('');
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [showLogin, setShowLogin] = useState(true);
  
  const [activeChatId, setActiveChatId] = useState(null);
  const [activeChatUser, setActiveChatUser] = useState(null);
  const [activeChatOtherUserId, setActiveChatOtherUserId] = useState(null);
  
  const currentUserId = useRef(null);

  useEffect(() => {
    const storedToken = localStorage.getItem('authToken');
    const storedUsername = localStorage.getItem('username');
    const storedUserId = localStorage.getItem('userId'); 
    
    if (storedToken && storedUsername && storedUserId) {
      setIsLoggedIn(true);
      setUserName(storedUsername);
      currentUserId.current = storedUserId;
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
        console.log(`[App.js] Intentando conectar Socket.IO a: ${BACKEND_URL}`);
        
        // Conexión explícita y forzada a WebSockets
        const newSocket = io(BACKEND_URL, {
          transports: ['websocket'],
          upgrade: false
        });
        setSocket(newSocket);

        newSocket.on('connect', () => {
            console.log(`[Socket.IO Client] ÉXITO: Conectado al servidor. ID: ${newSocket.id}`);
            if (currentUserId.current) {
                newSocket.emit('registerUserForNotifications', currentUserId.current);
            }
        });

        newSocket.on('connect_error', (err) => {
            console.error(`[Socket.IO Client] ERROR DE CONEXIÓN: ${err.message}`);
        });

        newSocket.on('disconnect', (reason) => {
            console.log(`[Socket.IO Client] Desconectado: ${reason}`);
        });

        newSocket.on("message", (newMessage) => {
            console.log("[App.js] Evento 'message' recibido del servidor:", newMessage);
            if (activeChatId && newMessage.conversationId?.toString() === activeChatId.toString()) {
                 (async () => {
                    const decryptedText = await cryptoService.decrypt(activeChatOtherUserId, newMessage.message);
                    const messageWithDecryptedText = { ...newMessage, message: decryptedText };
                    setMessages((prevMessages) => [...prevMessages, messageWithDecryptedText]);
                 })();
            }
        });

        return () => {
            if (newSocket) newSocket.disconnect();
        };
    }
  }, [isLoggedIn, socket, activeChatId, activeChatOtherUserId]);

  const handleLoginSuccess = async (loggedInUsername, loggedInUserId, token) => {
    setIsLoggedIn(true);
    setUserName(loggedInUsername);
    currentUserId.current = loggedInUserId; 
    localStorage.setItem('authToken', token);
    localStorage.setItem('username', loggedInUsername);
    localStorage.setItem('userId', loggedInUserId);
    await cryptoService.generateAndRegisterKeys(token);
    setMessages([]);
    setActiveChatId(null);
    setActiveChatUser(null);
    setActiveChatOtherUserId(null);
  };

  const handleRegisterSuccess = () => setShowLogin(true);

  const handleLogout = () => {
    localStorage.clear();
    setIsLoggedIn(false);
    setUserName('');
    currentUserId.current = null; 
    setShowLogin(true);
    setMessages([]);
    setActiveChatId(null);
    setActiveChatUser(null);
    setActiveChatOtherUserId(null);
    if (socket) {
      socket.disconnect();
      setSocket(null);
    }
  };

  const selectChat = async (conversationId, chatUser, otherUserId) => {
      setActiveChatId(conversationId);
      setActiveChatUser(chatUser);
      setActiveChatOtherUserId(otherUserId);
      setMessages([]);

      try {
        const token = localStorage.getItem('authToken');
        const theirPublicKey = await cryptoService.getPublicKeyForUser(otherUserId, token);
        if (theirPublicKey) {
          cryptoService.computeAndStoreSharedSecret(otherUserId, theirPublicKey);
        }

        const response = await axios.get(`/api/v1/conversations/${conversationId}/messages`, {
            headers: { Authorization: `Bearer ${token}` },
        });

        const decryptedHistory = await Promise.all(response.data.map(async (msg) => {
            const decryptedText = await cryptoService.decrypt(otherUserId, msg.message);
            return { ...msg, message: decryptedText };
        }));

        setMessages(decryptedHistory);

        if (socket) {
            if (activeChatId) socket.emit('leaveRoom', activeChatId); 
            socket.emit('joinRoom', conversationId);
        }
      } catch (error) {
        console.error('Error al cargar mensajes de la conversación:', error);
        setMessages([]); 
      }
  };

  if (!isLoggedIn) {
    return (
      <div className="app">
        {showLogin ? (
          <Login onRegisterClick={() => setShowLogin(false)} onLoginSuccess={handleLoginSuccess} />
        ) : (
          <Register onLoginClick={() => setShowLogin(true)} onRegisterSuccess={handleRegisterSuccess} />
        )}
      </div>
    );
  }

  return (
    <div className="app">
      <div className="app__body">
        <Sidebar userName={userName} onLogout={handleLogout} selectChat={selectChat} activeChatId={activeChatId} socket={socket} />
        {activeChatId ? (
          <Chat messages={messages} userName={userName} chatUser={activeChatUser} conversationId={activeChatId} otherUserId={activeChatOtherUserId} />
        ) : (
          <div className="chat__placeholder">
            <h1>Bienvenido a tu Chat Cifrado</h1>
            <p>Selecciona una conversación o busca un usuario para empezar.</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;