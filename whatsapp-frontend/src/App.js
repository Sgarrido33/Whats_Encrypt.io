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
      
      if (activeChatId && newMessage.conversationId?.toString() === activeChatId.toString() && newMessage.senderId !== currentUserId.current) {
          (async () => {
              console.log('[Socket] Mensaje recibido de OTRA persona. Descifrando...');
              const decryptedText = await cryptoService.decryptECIES(newMessage.message);
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

    if (socket) {
      socket.disconnect();
    }
  };

  const selectChat = async (conversationId, chatUser, otherUserId) => {
    // 1. Establecemos la información del chat activo en el estado de la App
    setActiveChatId(conversationId);
    setActiveChatUser(chatUser);
    setActiveChatOtherUserId(otherUserId);
    setMessages([]); // Limpiamos los mensajes del chat anterior mientras cargan los nuevos

    console.log(`[App.js] Abriendo chat con ${chatUser}. Cargando historial...`);

    try {
      // 2. Obtenemos el historial de mensajes de la API
      const token = localStorage.getItem('authToken');
      const response = await axios.get(`/api/v1/conversations/${conversationId}/messages`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      // 3. Desciframos cada mensaje del historial en paralelo
      const decryptedHistory = await Promise.all(
        response.data.map(async (msg) => {
          // Usamos nuestra nueva función de descifrado ECIES
          const decryptedText = await cryptoService.decryptECIES(msg.message);
          // Devolvemos el mensaje con el texto ya descifrado
          return { ...msg, message: decryptedText };
        })
      );

      // 4. Actualizamos el estado con los mensajes descifrados
      setMessages(decryptedHistory);
      console.log('[App.js] Historial de mensajes cargado y descifrado.');

      // 5. Nos unimos a la sala de Socket.IO para recibir mensajes en tiempo real
      if (socket) {
        // Si estábamos en otra sala, la abandonamos primero
        if (activeChatId) {
            socket.emit('leaveRoom', activeChatId);
        }
        socket.emit('joinRoom', conversationId);
      }
    } catch (error) {
      console.error('Error al cargar la conversación:', error);
      setMessages([]); // En caso de error, dejamos los mensajes vacíos
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
            setMessages={setMessages}
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