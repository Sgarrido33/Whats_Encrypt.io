import React, { useEffect, useState, useRef } from 'react';
import './App.css';
import Sidebar from './Sidebar';
import { Chat } from './Chat';
import SocketIOClient from 'socket.io-client';
import axios from './axios';
import Register from './Register';
import Login from './Login';
import cryptoService from './crypto-service';

const BACKEND_URL = 'http://localhost:9000'; 

function App() {
  const [messages, setMessages] = useState([]);
  const [socket, setSocket] = useState(null);
  const [userName, setUserName] = useState('');
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [showLogin, setShowLogin] = useState(true);
  
  // Estados para manejar el chat activo
  const [activeChatId, setActiveChatId] = useState(null);
  const [activeChatUser, setActiveChatUser] = useState(null);
  // **NUEVO**: Estado para guardar el ID del otro usuario en el chat activo
  const [activeChatOtherUserId, setActiveChatOtherUserId] = useState(null);
  
  const currentUserId = useRef(null); 

  // Efecto para restaurar la sesión desde localStorage
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

  // Efecto para manejar la conexión de Socket.IO y el descifrado de mensajes
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
            }
        });

        // --- LISTENER DE MENSAJES CON DESCIFRADO ---
        newSocket.on("message", (newMessage) => {
            console.log("App.js - Nuevo mensaje CIFRADO recibido:", newMessage);
            
            if (activeChatId && newMessage.conversationId?.toString() === activeChatId.toString()) {
                 // 1. Desciframos el payload del mensaje usando el ID del remitente
                 const decryptedText = cryptoService.decrypt(newMessage.senderId, newMessage.message);
                 
                 // 2. Creamos un nuevo objeto de mensaje con el texto ya descifrado
                 const messageWithDecryptedText = {
                   ...newMessage,
                   message: decryptedText, // Reemplazamos el objeto cifrado por el texto plano
                 };

                 // 3. Añadimos el mensaje descifrado al estado para mostrarlo en la UI
                 setMessages((prevMessages) => [...prevMessages, messageWithDecryptedText]);
            } else {
                console.log('Mensaje recibido para otra conversación o sin chat activo. No se actualiza el chat actual.');
                // Aquí podrías implementar una notificación de "nuevo mensaje"
            }
        });

        newSocket.on("disconnect", () => {
            console.log("App.js - Desconectado del servidor de Socket.IO");
        });

        return () => {
            if (newSocket) newSocket.disconnect();
        };
    }
  }, [isLoggedIn, socket, activeChatId]); // Dependemos de activeChatId para el descifrado

  // Manejador para cuando el login es exitoso
  const handleLoginSuccess = async (loggedInUsername, loggedInUserId, token) => {
    setIsLoggedIn(true);
    setUserName(loggedInUsername);
    currentUserId.current = loggedInUserId; 
    localStorage.setItem('authToken', token); 
    localStorage.setItem('username', loggedInUsername);
    localStorage.setItem('userId', loggedInUserId); 

    console.log(`Usuario ${loggedInUsername} (ID: ${loggedInUserId}) ha iniciado sesión.`);

    // --- CRIPTOGRAFÍA ---
    // Aseguramos que el usuario tenga sus claves generadas y registradas en el servidor.
    await cryptoService.generateAndRegisterKeys(token);
    
    // Reseteamos el estado de los chats
    setMessages([]);
    setActiveChatId(null);
    setActiveChatUser(null);
    setActiveChatOtherUserId(null);

    if (socket) { 
        socket.emit('registerUserForNotifications', loggedInUserId);
    }
  };

  const handleRegisterSuccess = () => setShowLogin(true);

  // Manejador para cerrar sesión
  const handleLogout = () => {
    localStorage.clear(); // Limpiamos todo el localStorage
    setIsLoggedIn(false);
    setUserName('');
    currentUserId.current = null; 
    setShowLogin(true);
    // Reseteamos todos los estados de chat
    setMessages([]);
    setActiveChatId(null);
    setActiveChatUser(null);
    setActiveChatOtherUserId(null);
    if (socket) {
      socket.disconnect();
      setSocket(null);
    }
    console.log('Sesión cerrada.');
  };

  // Manejador para cuando se selecciona un chat de la lista
  const selectChat = async (conversationId, chatUser, otherUserId) => {
      console.log(`Chat seleccionado: ID ${conversationId}, Usuario: ${chatUser}, OtherUserID: ${otherUserId}`);
      setActiveChatId(conversationId);
      setActiveChatUser(chatUser);
      setActiveChatOtherUserId(otherUserId); // Guardamos el ID del otro usuario
      setMessages([]); 

      try {
        const token = localStorage.getItem('authToken');
        if (!token) {
            console.error('No se encontró el token de autenticación para cargar mensajes.');
            return;
        }

        // --- CRIPTOGRAFÍA ---
        // 1. Obtener la clave pública del otro usuario
        const theirPublicKey = await cryptoService.getPublicKeyForUser(otherUserId, token);
        if (theirPublicKey) {
          // 2. Calcular y guardar el secreto compartido para esta conversación
          cryptoService.computeAndStoreSharedSecret(otherUserId, theirPublicKey);
        }

        // Cargamos el historial de mensajes (que llegarán cifrados)
        const response = await axios.get(`/api/v1/conversations/${conversationId}/messages`, {
            headers: { Authorization: `Bearer ${token}` },
        });

        // Desciframos el historial de mensajes
        const decryptedHistory = response.data.map(msg => {
            const senderId = msg.senderId;
            const decryptedText = cryptoService.decrypt(otherUserId, msg.message);
            return { ...msg, message: decryptedText };
        });

        setMessages(decryptedHistory);
        console.log(`Mensajes descifrados cargados para ${chatUser}:`, decryptedHistory);

        // Nos unimos a la "sala" de socket para recibir mensajes en tiempo real para este chat
        if (socket) {
            if (activeChatId) socket.emit('leaveRoom', activeChatId); 
            socket.emit('joinRoom', conversationId);
        }

      } catch (error) {
        console.error('Error al cargar mensajes de la conversación:', error.response?.data || error.message);
        setMessages([]); 
      }
  };

  // Renderizado condicional: Muestra Login/Register o la app principal
  if (!isLoggedIn) {
    return (
      <div className="app">
        {showLogin ? (
          <Login 
            onRegisterClick={() => setShowLogin(false)} 
            onLoginSuccess={handleLoginSuccess}
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

  // Renderizado de la aplicación principal
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
            otherUserId={activeChatOtherUserId} // Pasamos el ID del otro usuario al componente Chat
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