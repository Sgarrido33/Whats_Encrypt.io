# Proyecto - Ética y Seguridad de datos
- Juan Aquino
- Rodrigo Castro

## Primer entrega
En el presente proyecto se desarrollado una solución de seguridad orientada a la mensajeria instantánea ecriptada. Se tiene una aplicación web que permite la comunicación directa entre usuarios mediante un chat que asegura la privacidad mediante un cifrado de extremo a extremo (E2EE)-

  <img width="828" alt="image" src="https://github.com/user-attachments/assets/73b0766d-b722-44b6-b8e9-cf302da9f1cf" />


### Objetivos
Sobre seguridad con criptografía
<ul>
  <li>Se plantea tener un cifrado de extremo a extremo de los mensajes para garantizar la confiablidad absoluta de los usuarios
  </li>
  <li>Se va implementar un sistema de distribución de llaves para autenticación(Protocolo Signal) y otorgar permisos en la aplicación
  </li>
  <li>Permitir la comunicación asíncrona
  </li>
  <li>Añadir autenticación fuera de banda
</ul>
Sobre el esquema y medidas de seguridad para tener altos estándares de seguridad
<ol>
  <li> Se autentifica a los usuarios que ingresan a la web mediante el registro de usuario - contraseña, usando tokens JWT para asegurar la identidad y seguridad de las cuentas de los usuarios.
  </li>
  <li> Se registra los logs de las transmision y conexiones de los usuarios para monitorear y realizar auditorias ante posibles vulnerabilidades.
  </li>
  <li> Se tendrá un backup de los mensajes del servidor, que almacena solo mensajes asíncronos que aún no se ha enviar a un usuario desconectado (todos encriptados).
  </li>
  <li> Se tendrá autenticación adicional mediante certificados de seguridad, para garantizar la autenticidad de los usuarios que deseen comunicarse con usuarios no regitrados.
  </li>
</ol>
Sobre el diseño y funcionalidades (con especificaciones de seguridad)

![Etica y Seguridad de datos - diseño whatsapp drawio](https://github.com/user-attachments/assets/e674b7ed-5cd9-4015-866d-bf7b5cde64c1)

La aplicación tiene los siguientes flujos:
### Registro de usuarios
<ol>
  <li> Cliente A -> Servidor: Petición POST con username/password se registra en la aplicación. 
  </li>
  <li> Servidor -> Cliente A: El servidor recibe la solicitud y genera tanto un token de autenticidad, registra al usuario y devuelve una respuesta con un token JWT si las credenciales son válidas. 
  </li>
  <li> Cliente A -> Servidor: Genera las llaves para identificarse a largo plazo al usuario, la llave de identidad IK, la llave de session presignedkey SPK y llaves de autenticación por canal de comunicación one-time key OPK, y se suben al servidor.
  </li>
  <li> Servidor: Guarda las llaves públicas del usuario y dispone las llaves para conectar la comunicación con otros usuarios.
</ol>



### Comunicación instantánea
<ol>
  <li> Cliente A -> Servidor: Petición POST con username/password inicia sesión en la aplicación. 
  </li>
  <li> Servidor -> Cliente A: El servidor recibe la solicitud y genera tanto un token de autenticidad, registra al usuario y devuelve una respuesta con un token JWT si las credenciales son válidas. 
  </li>
  <li> Cliente A -> Servidor: Al registrarse se sube su clave pública.
  </li>
  <li> Cliente A -> Servidor: Petición GET para solicitar la clave pública de Cliente B.
  </li>
  <li> Servidor -> Cliente A: Devuelve la clave pública de Cliente B.
  </li>
  <li> Cliente A: Cliente A usa su clave privada y la clave pública de B para calcular un secreto compartido.
  </li>
  <li> Cliente A: Cifra el mensaje usando el Secreto Compartido.
  </li>
  <li> Cliente A -> Servidor: Petición POST con el mensaje ya cifrado.
  </li>
  <li> Servidor: Guarda el mensaje cifrado en MongoDB Atlas y emite el mensaje cifrado por Socket.IO.
  </li>
  <li> Servidor: Servidor -> Cliente B (y Cliente A): Envío del mensaje cifrado a través del canal WebSocket.
  </li>
  <li> Servidor: (Local en los Clientes): Descifran el mensaje con el Secreto Compartido para mostrarlo en la UI.
  </li>
</ol>




