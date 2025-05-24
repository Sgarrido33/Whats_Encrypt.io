import React, { useState } from "react";
import "./Chat.css";

import AttachFileIcon from '@mui/icons-material/AttachFile';
import SearchOutlinedIcon from '@mui/icons-material/SearchOutlined';
import MoreVertIcon from "@mui/icons-material/MoreVert";
import InsertEmoticonIcon from "@mui/icons-material/InsertEmoticon";
import MicIcon from "@mui/icons-material/Mic";


import { Avatar, IconButton } from "@mui/material"; 

import axios from "./axios";

export const Chat = ({ messages }) => {
  const [input, setInput] = useState("");

  const sendMessage = async (event) => {
    event.preventDefault();
    await axios.post("/api/v1/messages/new", {
      message: input,
      name: "Faizal Vasaya", 
      timestamp: new Date().toUTCString(), 
      received: false, 
    });

    setInput("");
  };

  return (
    <div className="chat">
      <div className="chat__header">
        <Avatar src="" /> 
        <div className="chat__headerInfo">
          <h3>Room name</h3> 
          <p>Last seen at ...</p> 
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
                message.received ? "chat__receiver" : "" 
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
            placeholder="Type a message"
            type="text"
          />
          <button onClick={sendMessage} type="submit">
            Send a message
          </button>
        </form>
        <IconButton>
          <MicIcon />
        </IconButton>
      </div>
    </div>
  );
};