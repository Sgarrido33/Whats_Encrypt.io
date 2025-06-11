import React, { useState } from 'react';
import './Login.css';
import axios from './axios';

function Login({ onRegisterClick, onLoginSuccess }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');

  const handleLogin = async (e) => {
    e.preventDefault();
    setMessage('');

    if (!username || !password) {
      setMessage('Por favor, ingresa tu nombre de usuario y contraseña.');
      return;
    }

    try {
      const response = await axios.post('/api/v1/auth/login', {
        username,
        password,
      });

      if (response.status === 200) {
        const { username: loggedInUsername, _id: loggedInUserId, token } = response.data; 
        
        onLoginSuccess(loggedInUsername, loggedInUserId, token); 
      } else {
        setMessage(response.data.message || 'Error al iniciar sesión. Inténtalo de nuevo.');
      }

    } catch (error) {
      console.error('Error durante el inicio de sesión:', error.response?.data || error.message);
      setMessage(error.response?.data?.message || 'Nombre de usuario o contraseña incorrectos. Inténtalo de nuevo.');
    }
  };

  return (
    <div className="login-container">
      <div className="login-card">
        <h2>Iniciar Sesión</h2>
        <form onSubmit={handleLogin}>
          <div className="form-group">
            <label htmlFor="username">Nombre de Usuario:</label>
            <input
              type="text"
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </div>
          <div className="form-group">
            <label htmlFor="password">Contraseña:</label>
            <input
              type="password"
              id="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
          <button type="submit" className="login-button">Iniciar Sesión</button>
        </form>
        {message && <p className={`message ${message.includes('exitoso') ? 'success' : 'error'}`}>{message}</p>}
        <p className="switch-form">
          ¿No tienes una cuenta?{' '}
          <span onClick={onRegisterClick}>Regístrate aquí.</span>
        </p>
      </div>
    </div>
  );
}

export default Login;