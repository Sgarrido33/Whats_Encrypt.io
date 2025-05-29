import "./App.css";
import Sidebar from "./Sidebar";
import { Chat } from "./Chat"; 
import { useEffect, useState } from "react";
import axios from "./axios";
import io from "socket.io-client";

const socket = io("http://localhost:9000");

function App() {
  const [messages, setMessages] = useState([]);

  useEffect(() => {
    axios.get("/api/v1/messages/sync")
      .then((response) => {
        setMessages(response.data);
      })
      .catch((error) => {
        console.error("Error al cargar mensajes:", error);
      });
  }, []); 

  // Nuevo useEffect para manejar la conexión y recepción de mensajes
  useEffect(() => {
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
        <Chat messages={messages} socket={socket} />
      </div>
    </div>
  );
}


export default App;