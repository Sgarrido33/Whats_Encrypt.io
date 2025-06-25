import React, { useEffect, useState, useRef } from 'react';
import { io } from "socket.io-client";
import Sidebar from './Sidebar';
import { Chat } from './Chat';
import Register from './Register';
import Login from './Login';
import axios from './axios';
import cryptoService from './crypto-service';
import { clearAllData } from './db-service';
import './App.css';

const BACKEND_URL = 'http://localhost:9000';

function App() {
  // --- Estados de la aplicación ---
  const [messages, setMessages] = useState([]);
  const [socket, setSocket] = useState(null);
  const [userName, setUserName] = useState('');
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [showLogin, setShowLogin] = useState(true);
  
  // Estados para manejar el chat activo
  const [activeChatId, setActiveChatId] = useState(null);
  const [activeChatUser, setActiveChatUser] = useState(null);
  const [activeChatOtherUserId, setActiveChatOtherUserId] = useState(null);
  
  // NUEVO: Estado para controlar si la sesión segura está lista para enviar mensajes
  const [isSessionReady, setIsSessionReady] = useState(false);
  
  const currentUserId = useRef(null);

  // Efecto para restaurar la sesión del usuario desde localStorage
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

  // --- EFECTO 1: GESTIÓN DE LA CONEXIÓN DEL SOCKET ---
  useEffect(() => {
    if (!isLoggedIn) {
      return;
    }

    console.log(`[App.js] Creando conexión de Socket.IO a: ${BACKEND_URL}`);
    const newSocket = io(BACKEND_URL, {
      transports: ['websocket'],
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

    return () => {
      console.log("[App.js] Desconectando socket...");
      newSocket.disconnect();
    };
  }, [isLoggedIn]);

  // --- EFECTO 2: GESTIÓN DE LOS LISTENERS DE MENSAJES ---
  useEffect(() => {
    if (!socket) {
      return;
    }

    const messageListener = (newMessage) => {
      console.log("[App.js] Evento 'message' recibido del servidor:", newMessage);
      
      if (activeChatId && activeChatOtherUserId && newMessage.conversationId?.toString() === activeChatId.toString()) {
          (async () => {
              const decryptedText = await cryptoService.decrypt(activeChatOtherUserId, newMessage.message);
              const messageWithDecryptedText = { ...newMessage, message: decryptedText };
              setMessages((prevMessages) => [...prevMessages, messageWithDecryptedText]);
          })();
      }
    };

    socket.on('message', messageListener);

    return () => {
      socket.off('message', messageListener);
    };
  }, [socket, activeChatId, activeChatOtherUserId]);

  const handleLoginSuccess = async (loggedInUsername, loggedInUserId, token) => {
    setIsLoggedIn(true);
    setUserName(loggedInUsername);
    currentUserId.current = loggedInUserId; 
    localStorage.setItem('authToken', token);
    localStorage.setItem('username', loggedInUsername);
    localStorage.setItem('userId', loggedInUserId);
    await cryptoService.generateAndRegisterSignalKeys(token);
    setMessages([]);
    setActiveChatId(null);
    setActiveChatUser(null);
    setActiveChatOtherUserId(null);
    setIsSessionReady(false); // Reiniciamos el estado de la sesión
  };

  const handleRegisterSuccess = () => setShowLogin(true);

  const handleLogout = async () => { // <
    try {
      await clearAllData(); // 
      console.log("[App.js] Datos de IndexedDB eliminados exitosamente.");
    } catch (error) {
      console.error("[App.js] Error al limpiar la base de datos al cerrar sesión:", error);
    }

    localStorage.clear();
    setIsLoggedIn(false);
    setUserName('');
    currentUserId.current = null;
    setShowLogin(true);
    setMessages([]);
    setActiveChatId(null);
    setActiveChatUser(null);
    setActiveChatOtherUserId(null);
    setIsSessionReady(false);

    if (socket) {
      socket.disconnect();
    }
  };

  const selectChat = async (conversationId, chatUser, otherUserId) => {
      // 1. Al seleccionar un chat, marcamos la sesión como NO lista
      setIsSessionReady(false);
      
      setActiveChatId(conversationId);
      setActiveChatUser(chatUser);
      setActiveChatOtherUserId(otherUserId);
      setMessages([]);

      try {
        const token = localStorage.getItem('authToken');
        
        const theirPublicKey = await cryptoService.getPublicKeyForUser(otherUserId, token);
        if (theirPublicKey) {
          await cryptoService.computeAndStoreSharedSecret(otherUserId, theirPublicKey);
          
          // 2. Solo después de que se guarda el secreto, marcamos la sesión como LISTA
          setIsSessionReady(true);
          console.log("[App.js] Sesión segura lista para enviar mensajes.");
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
        console.error('Error al cargar la conversación:', error);
        setIsSessionReady(false); 
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
        <Sidebar 
          userName={userName} 
          onLogout={handleLogout} 
          selectChat={selectChat} 
          activeChatId={activeChatId} 
          socket={socket} 
        />
        {activeChatId ? (
          <Chat 
            messages={messages} 
            userName={userName} 
            chatUser={activeChatUser} 
            conversationId={activeChatId} 
            otherUserId={activeChatOtherUserId}
            isSessionReady={isSessionReady}
          />
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