import React, { useState } from "react";
import "./Chat.css";

import AttachFileIcon from '@mui/icons-material/AttachFile';
import SearchOutlinedIcon from '@mui/icons-material/SearchOutlined';
import MoreVertIcon from "@mui/icons-material/MoreVert";
import InsertEmoticonIcon from "@mui/icons-material/InsertEmoticon";
import MicIcon from "@mui/icons-material/Mic";

import { Avatar, IconButton } from "@mui/material"; 

export const Chat = ({ messages, socket, userName }) => {
  const [input, setInput] = useState("");

  const sendMessage = async (event) => {
    event.preventDefault(); 

    if (input.trim() === "") {
      return;
    }

    const messageData = {
      message: input,
      name: userName, 
      timestamp: new Date().toUTCString(),
    };

    if (socket && socket.connected) { 
        socket.emit("message", messageData); 
    } else {
        console.error("Error: Socket.IO no está conectado. No se pudo enviar el mensaje.");
    }

    setInput("");
  };

  return (
    <div className="chat">
      <div className="chat__header">
        <Avatar src="" />
        <div className="chat__headerInfo">
          <h3>{userName || "Cargando nombre..."}</h3> 
          <p>Última vez visto a las ...</p>
        </div>
        <div className="chat__headerRight">
          <IconButton>
            <AttachFileIcon />
          </IconButton>
          <IconButton>
            <SearchOutlinedIcon />
          </IconButton>
          <IconButton>
            <MoreVertIcon />
          </IconButton>
        </div>
      </div>

      <div className="chat__body">
        {messages.map((message, index) => {
          return (
            <p
              key={index}
              className={`chat__message ${
                message.name === userName ? "chat__sent" : "" 
              }`}
            >
              <span className="chat__name">{message.name}</span>
              {message.message}
              <span className="chat__timestamp">
                {message.timestamp}
              </span>
            </p>
          );
        })}
      </div>

      <div className="chat__footer">
        <IconButton>
          <InsertEmoticonIcon />
        </IconButton>
        <form>
          <input
            onChange={(e) => setInput(e.target.value)}
            value={input}
            placeholder="Escribe un mensaje"
            type="text"
          />
          <button onClick={sendMessage} type="submit">
            Enviar
          </button>
        </form>
        <IconButton>
          <MicIcon />
        </IconButton>
      </div>
    </div>
  );
};