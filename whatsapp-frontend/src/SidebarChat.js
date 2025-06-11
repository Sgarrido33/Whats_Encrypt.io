import React from 'react';
import './SidebarChat.css';
import { Avatar } from '@mui/material';

function SidebarChat({ conversationId, otherUser, lastMessage, lastMessageSender, updatedAt, selectChat, isActive }) {
  const handleClick = () => {
    selectChat(conversationId, otherUser);
  };

  return (
    <div className={`sidebarChat ${isActive ? 'active' : ''}`} onClick={handleClick}>
      <Avatar src={`https://avatars.dicebear.com/api/human/${otherUser}.svg`} />
      <div className="sidebarChat__info">
        <h2>{otherUser}</h2> 
        {lastMessage && (
            <p>
                {lastMessageSender === localStorage.getItem('username') ? 'Tú: ' : ''}
                {lastMessage}
            </p>
        )}
      </div>
      {updatedAt && (
          <span className="sidebarChat__timestamp">
              {new Date(updatedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
          </span>
      )}
    </div>
  );
}

export { SidebarChat }; 