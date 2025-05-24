import "./App.css";
import Sidebar from "./Sidebar";
import { Chat } from "./Chat"; 
import { useEffect, useState } from "react";
import axios from "./axios";

function App() {
  const [messages, setMessages] = useState([]);

  useEffect(() => {
    axios.get("/api/v1/messages/sync").then((response) => {
      setMessages(response.data);
    }).catch(error => {
      console.error("Error al cargar mensajes:", error);
    });
  }, []);

  return (
    <div className="app">
      <div className="app_body">
        <Sidebar />
        <Chat messages={messages} />
      </div>
    </div>
  );
}

export default App;