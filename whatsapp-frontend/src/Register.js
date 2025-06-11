import React, { useState } from 'react';
import './Register.css';
import axios from './axios'; 

function Register({ onLoginClick, onRegisterSuccess }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');

  const handleRegister = async (e) => {
    e.preventDefault();
    setMessage('');

    if (!username || !password) {
      setMessage('Por favor, ingresa un nombre de usuario y una contraseña.');
      return;
    }

    try {
      const response = await axios.post('/api/v1/auth/register', {
        username,
        password,
      });

      if (response.status === 201) {
        setMessage('¡Cuenta creada con éxito! Ahora puedes iniciar sesión.');
        setUsername('');
        setPassword('');
        onRegisterSuccess(); 
      } else {
        setMessage(response.data.message || 'Error al registrar la cuenta. Inténtalo de nuevo.');
      }
    } catch (error) {
      console.error('Error durante el registro:', error.response?.data || error.message);
      setMessage(error.response?.data?.message || 'Error al intentar registrar la cuenta. Inténtalo de nuevo.');
    }
  };

  return (
    <div className="register-container">
      <div className="register-card">
        <h2>Crear Cuenta</h2>
        <form onSubmit={handleRegister}>
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
          <button type="submit" className="register-button">Registrarse</button>
        </form>
        {message && <p className={`message ${message.includes('éxito') ? 'success' : 'error'}`}>{message}</p>}
        <p className="switch-form">
          ¿Ya tienes una cuenta?{' '}
          <span onClick={onLoginClick}>Inicia Sesión aquí.</span>
        </p>
      </div>
    </div>
  );
}

export default Register;