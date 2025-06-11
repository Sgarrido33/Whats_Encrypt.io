import React, { useState, useEffect } from 'react';
import './Sidebar.css';
import DonutLargeIcon from '@mui/icons-material/DonutLarge';
import ChatIcon from '@mui/icons-material/Chat';
import MoreVertIcon from '@mui/icons-material/MoreVert';
import { Avatar, IconButton } from '@mui/material';
import SearchOutlined from '@mui/icons-material/SearchOutlined';
import { SidebarChat } from './SidebarChat';
import ExitToAppIcon from '@mui/icons-material/ExitToApp';
import axios from './axios';

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
      if (!token) {
        console.error('No se encontró el token de autenticación.');
        return;
      }

      const response = await axios.get(`/api/v1/users/search?q=${searchTerm}`, {
        headers: {
          Authorization: `Bearer ${token}`, 
        },
      });
      setSearchResults(response.data);
      setShowSearchResults(true); 
    } catch (error) {
      console.error('Error al buscar usuarios:', error.response?.data || error.message);
      setSearchResults([]);
      setShowSearchResults(true); 
    }
  };

  const handleStartChatWithUser = async (userId, username) => {
    try {
      const token = localStorage.getItem('authToken');
      if (!token) {
        console.error('No se encontró el token de autenticación.');
        return;
      }

      const response = await axios.post('/api/v1/conversations', {
        participantId: userId,
      }, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      const conversation = response.data;
      
      selectChat(conversation._id, username); 
      setSearchTerm(''); 
      setSearchResults([]); 
      setShowSearchResults(false); 

    } catch (error) {
      console.error('Error al iniciar chat con usuario:', error.response?.data || error.message);
      alert(`Error al iniciar chat: ${error.response?.data?.message || error.message}`);
    }
  };

  const fetchConversations = async () => {
    try {
      const token = localStorage.getItem('authToken');
      if (!token) {
        console.error('No se encontró el token de autenticación para cargar conversaciones.');
        setConversations([]); 
        return;
      }

      const response = await axios.get('/api/v1/conversations', {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      const sortedConversations = response.data.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
      setConversations(sortedConversations);
      console.log('Conversaciones cargadas:', response.data);
    } catch (error) {
      console.error('Error al cargar conversaciones:', error.response?.data || error.message);
      setConversations([]);
    }
  };

  useEffect(() => {
    if (userName) {
        fetchConversations();
    } else {
        setConversations([]); 
    }
  }, [userName]); 

  useEffect(() => {
    if (!socket || !userName) { 
      return;
    }

    const handleConversationUpdate = (updatedConversation) => {
      console.log('Sidebar - Actualización de conversación recibida:', updatedConversation);
      setConversations(prevConversations => {
        const existingIndex = prevConversations.findIndex(
          (conv) => conv._id === updatedConversation._id
        );

        if (existingIndex > -1) {
          const newConversations = [...prevConversations];
          newConversations[existingIndex] = updatedConversation;
          return newConversations.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
        } else {
          const newConversations = [...prevConversations, updatedConversation];
          return newConversations.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
        }
      });
    };

    socket.on('conversationUpdate', handleConversationUpdate);

    return () => {
      if (socket) {
        socket.off('conversationUpdate', handleConversationUpdate);
      }
    };
  }, [socket, userName]); 

  return (
    <div className='sidebar'>
      <div className="sidebar__header">
        <Avatar src={`https://avatars.dicebear.com/api/human/${userName || 'guest'}.svg`} />
        <div className="sidebar__headerRight">
          <h3 className="sidebar__userName">{userName}</h3> 
          <IconButton onClick={onLogout}>
            <ExitToAppIcon />
          </IconButton>
          <IconButton>
            <DonutLargeIcon />
          </IconButton>
          <IconButton>
            <ChatIcon />
          </IconButton>
          <IconButton>
            <MoreVertIcon />
          </IconButton>
        </div>
      </div>

      <div className="sidebar__search">
        <div className="sidebar__searchContainer">
          <SearchOutlined />
          <input
            placeholder="Search or start new chat"
            type="text"
            value={searchTerm}
            onChange={(e) => {
                setSearchTerm(e.target.value);
                if (e.target.value === '') {
                    setSearchResults([]);
                    setShowSearchResults(false);
                }
            }}
            onKeyUp={handleSearch} 
          />
        </div>
      </div>

      <div className="sidebar__chats">
        {showSearchResults && searchResults.length > 0 && (
          <div className="search-results">
            <h4>Usuarios Encontrados:</h4>
            {searchResults.map((user) => (
              <div 
                key={user._id} 
                className="search-result-item" 
                onClick={() => handleStartChatWithUser(user._id, user.username)}
              >
                <Avatar src={`https://avatars.dicebear.com/api/human/${user.username}.svg`} />
                <span>{user.username}</span>
              </div>
            ))}
          </div>
        )}
        {showSearchResults && searchResults.length === 0 && searchTerm !== '' && (
            <p className="no-results">No se encontraron usuarios para "{searchTerm}".</p>
        )}

        {showSearchResults && <hr className="sidebar__separator" />}


        <h4>Tus Conversaciones:</h4>
        {conversations.length === 0 && !showSearchResults && (
            <p className="no-conversations">Aún no tienes conversaciones. ¡Busca un usuario para empezar!</p>
        )}
        {conversations.map((conv) => (
          <SidebarChat 
            key={conv._id} 
            conversationId={conv._id} 
            otherUser={conv.otherUser} 
            lastMessage={conv.lastMessage}
            lastMessageSender={conv.lastMessageSender}
            updatedAt={conv.updatedAt}
            selectChat={selectChat}
            isActive={activeChatId === conv._id} 
          />
        ))}
      </div>
    </div>
  );
}

export default Sidebar;