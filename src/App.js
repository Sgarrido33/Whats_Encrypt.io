import "./App.css";
import Sidebar from "./Sidebar";
import { Chat } from "./Chat"; 
import { useEffect, useState } from "react";
import axios from "./axios";
import io from "socket.io-client";

const socket = io("http://localhost:9000");

function App() {
  const [messages, setMessages] = useState([]);
  const [userName, setUserName] = useState('');

  useEffect(() => {

    let name = prompt("Ingresa nombre de usuario:");
    if (!name || name.trim() === '') {
      name = `Usuario${Math.floor(Math.random() * 1000)}`; 
    }
    setUserName(name);

    axios.get("/api/v1/messages/sync")
      .then((response) => {
        setMessages(response.data);
      })
      .catch((error) => {
        console.error("Error al cargar mensajes:", error);
      });

    // Escucha evento "connect" del socket
    socket.on('connect', () => {
      console.log('Conectado al servidor de Socket.IO');
    });

    // Escucha evento 'message' que el backend emitirá cuando haya un nuevo mensaje
    socket.on('message', (newMessage) => {
      console.log('Nuevo mensaje recibido vía Socket.IO:', newMessage);
      // Actualiza estado de mensajes añadiendo nuevo mensaje
      setMessages((prevMessages) => [...prevMessages, newMessage]);
    });

    // Escucha evento 'disconnect' del socket
    socket.on('disconnect', () => {
      console.log('Desconectado del servidor de Socket.IO');
    });

        return () => {
      socket.off('connect');
      socket.off('message');
      socket.off('disconnect');
    };

  }, []); 

  return (
    <div className="app">
      <div className="app_body">
        <Sidebar />
        <Chat messages={messages} socket={socket} userName={userName} /> 
      </div>
    </div>
  );
}


export default App;