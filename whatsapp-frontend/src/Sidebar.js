import React, { useState, useEffect } from 'react';
import DonutLargeIcon from '@mui/icons-material/DonutLarge';
import ChatIcon from '@mui/icons-material/Chat';
import MoreVertIcon from '@mui/icons-material/MoreVert';
import { Avatar, IconButton } from '@mui/material';
import SearchOutlined from '@mui/icons-material/SearchOutlined';
import { SidebarChat } from './SidebarChat';
import ExitToAppIcon from '@mui/icons-material/ExitToApp';
import axios from './axios';
import './Sidebar.css';

function Sidebar({ userName, onLogout, selectChat, activeChatId, socket }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [searchResults, setSearchResults] = useState([]);
  const [conversations, setConversations] = useState([]);
  const [showSearchResults, setShowSearchResults] = useState(false);

  const handleSearch = async (e) => {
    e.preventDefault();
    if (!searchTerm.trim()) {
      setSearchResults([]);
      setShowSearchResults(false);
      return;
    }
    try {
      const token = localStorage.getItem('authToken');
      const response = await axios.get(`/api/v1/users/search?q=${searchTerm}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setSearchResults(response.data);
      setShowSearchResults(true);
    } catch (error) {
      console.error('Error al buscar usuarios:', error);
      setSearchResults([]);
      setShowSearchResults(true);
    }
  };

  const handleStartChatWithUser = async (userId, username) => {
    try {
      const token = localStorage.getItem('authToken');
      const response = await axios.post('/api/v1/conversations', {
        participantId: userId,
      }, {
        headers: { Authorization: `Bearer ${token}` },
      });

      const conversation = response.data;
      
      // --- CORRECCIÓN CLAVE ---
      // La respuesta del backend incluye a los participantes. Buscamos al otro usuario.
      const otherUser = conversation.participants.find(p => p._id.toString() !== localStorage.getItem('userId'));
      
      // Llamamos a selectChat con TODOS los datos necesarios, incluyendo el ID del otro usuario.
      if (otherUser) {
        selectChat(conversation._id, otherUser.username, otherUser._id);
      }
      
      setSearchTerm('');
      setSearchResults([]);
      setShowSearchResults(false);
    } catch (error) {
      console.error('Error al iniciar chat con usuario:', error.response?.data || error.message);
    }
  };

  useEffect(() => {
    const fetchConversations = async () => {
      try {
        const token = localStorage.getItem('authToken');
        const response = await axios.get('/api/v1/conversations', {
          headers: { Authorization: `Bearer ${token}` },
        });
        const sortedConversations = response.data.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
        setConversations(sortedConversations);
      } catch (error) {
        console.error('Error al cargar conversaciones:', error);
        setConversations([]);
      }
    };

    if (userName) {
      fetchConversations();
    }
  }, [userName]);

  useEffect(() => {
    if (!socket || !userName) return;

    const handleConversationUpdate = (updatedConversation) => {
      setConversations(prev => {
        const existingIndex = prev.findIndex(c => c._id === updatedConversation._id);
        if (existingIndex > -1) {
          const newConversations = [...prev];
          newConversations[existingIndex] = updatedConversation;
          return newConversations.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
        } else {
          return [...prev, updatedConversation].sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
        }
      });
    };

    socket.on('conversationUpdate', handleConversationUpdate);
    return () => {
      socket.off('conversationUpdate', handleConversationUpdate);
    };
  }, [socket, userName]);

  return (
    <div className='sidebar'>
      <div className="sidebar__header">
        <Avatar>{userName ? userName[0].toUpperCase() : '?'}</Avatar>
        <div className="sidebar__headerRight">
          <h3>{userName}</h3>
          <IconButton onClick={onLogout}><ExitToAppIcon /></IconButton>
        </div>
      </div>

      <div className="sidebar__search">
        <div className="sidebar__searchContainer">
          <SearchOutlined />
          <input
            placeholder="Buscar o empezar un nuevo chat"
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            onKeyUp={handleSearch}
          />
        </div>
      </div>

      <div className="sidebar__chats">
        {showSearchResults && (
          searchResults.map((user) => (
            <div key={user._id} className="search-result-item" onClick={() => handleStartChatWithUser(user._id, user.username)}>
              <Avatar>{user.username ? user.username[0].toUpperCase() : '?'}</Avatar>
              <div className="sidebarChat__info">
                <h2>{user.username}</h2>
              </div>
            </div>
          ))
        )}

        {/* --- ESTA ES LA PARTE CORREGIDA --- */}
        {conversations.map((conv) => (
          <SidebarChat
            key={conv._id}
            // Ahora pasamos la prop 'onClick' con la función correcta y todos sus parámetros
            onClick={() => selectChat(conv._id, conv.otherUser, conv.otherUserId)}
            otherUser={conv.otherUser}
            lastMessage={conv.lastMessage}
            isActive={activeChatId === conv._id}
          />
        ))}
      </div>
    </div>
  );
}

export default Sidebar;