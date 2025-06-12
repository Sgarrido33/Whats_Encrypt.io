import React, { useEffect, useState, useRef } from 'react';
import { io } from "socket.io-client"; // Importación correcta y moderna
import Sidebar from './Sidebar';
import { Chat } from './Chat';
import Register from './Register';
import Login from './Login';
import axios from './axios';
import cryptoService from './crypto-service';
import './App.css';

// Constante para la URL del backend
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
  
  // Usamos useRef para el ID del usuario actual para evitar re-renderizados innecesarios
  const currentUserId = useRef(null);

  // Efecto para restaurar la sesión del usuario desde localStorage al cargar la app
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
  // Este efecto solo depende de 'isLoggedIn'. Se ejecuta una vez al iniciar sesión
  // y su función de limpieza se ejecuta solo al cerrar sesión.
  useEffect(() => {
    if (!isLoggedIn) {
      return;
    }

    console.log(`[App.js] Creando conexión de Socket.IO a: ${BACKEND_URL}`);
    const newSocket = io(BACKEND_URL, {
      transports: ['websocket'], // Forzamos el uso de WebSockets para mayor estabilidad
    });

    setSocket(newSocket);

    // Listeners para depurar el estado de la conexión
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

    // Función de limpieza que se ejecuta solo cuando isLoggedIn cambia a false
    return () => {
      console.log("[App.js] Desconectando socket...");
      newSocket.disconnect();
    };
  }, [isLoggedIn]); // <-- Dependencia clave: solo se ejecuta cuando cambia el estado de login

  // --- EFECTO 2: GESTIÓN DE LOS LISTENERS DE MENSAJES ---
  // Este efecto se encarga de que los listeners siempre usen la información más
  // actualizada del chat activo (activeChatId, etc.), sin recrear la conexión.
  useEffect(() => {
    if (!socket) {
      return;
    }

    const messageListener = (newMessage) => {
      console.log("[App.js] Evento 'message' recibido del servidor:", newMessage);
      
      if (activeChatId && activeChatOtherUserId && newMessage.conversationId?.toString() === activeChatId.toString()) {
          // Usamos una función autoejecutable async para poder usar 'await'
          (async () => {
              const decryptedText = await cryptoService.decrypt(activeChatOtherUserId, newMessage.message);
              const messageWithDecryptedText = { ...newMessage, message: decryptedText };
              setMessages((prevMessages) => [...prevMessages, messageWithDecryptedText]);
          })();
      }
    };

    socket.on('message', messageListener);

    // Función de limpieza: removemos el listener anterior para evitar duplicados
    return () => {
      socket.off('message', messageListener);
    };
    
  }, [socket, activeChatId, activeChatOtherUserId]); // <-- Dependencias que afectan al listener

  // Manejador para cuando el login es exitoso
  const handleLoginSuccess = async (loggedInUsername, loggedInUserId, token) => {
    setIsLoggedIn(true);
    setUserName(loggedInUsername);
    currentUserId.current = loggedInUserId; 
    localStorage.setItem('authToken', token);
    localStorage.setItem('username', loggedInUsername);
    localStorage.setItem('userId', loggedInUserId);
    
    // Aseguramos que el usuario tenga sus claves criptográficas
    await cryptoService.generateAndRegisterKeys(token);
    
    // Reseteamos el estado de los chats
    setMessages([]);
    setActiveChatId(null);
    setActiveChatUser(null);
    setActiveChatOtherUserId(null);
  };

  const handleRegisterSuccess = () => setShowLogin(true);

  // Manejador para cerrar sesión
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
    // El useEffect de conexión se encargará de desconectar el socket
  };

  // Manejador para cuando se selecciona un chat
  const selectChat = async (conversationId, chatUser, otherUserId) => {
      setActiveChatId(conversationId);
      setActiveChatUser(chatUser);
      setActiveChatOtherUserId(otherUserId); // Guardamos el ID del otro usuario
      setMessages([]);

      try {
        const token = localStorage.getItem('authToken');
        
        // Establecemos la sesión segura (obtenemos clave pública y calculamos secreto)
        const theirPublicKey = await cryptoService.getPublicKeyForUser(otherUserId, token);
        if (theirPublicKey) {
          await cryptoService.computeAndStoreSharedSecret(otherUserId, theirPublicKey);
        }

        // Cargamos el historial de mensajes
        const response = await axios.get(`/api/v1/conversations/${conversationId}/messages`, {
            headers: { Authorization: `Bearer ${token}` },
        });

        // Desciframos el historial de mensajes
        const decryptedHistory = await Promise.all(response.data.map(async (msg) => {
            const decryptedText = await cryptoService.decrypt(otherUserId, msg.message);
            return { ...msg, message: decryptedText };
        }));

        setMessages(decryptedHistory);

        // Nos unimos a la sala de Socket.IO
        if (socket) {
            if (activeChatId) socket.emit('leaveRoom', activeChatId); 
            socket.emit('joinRoom', conversationId);
        }
      } catch (error) {
        console.error('Error al cargar la conversación:', error);
        setMessages([]); 
      }
  };

  // Renderizado condicional de la app
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