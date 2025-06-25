# Proyecto - Ética y Seguridad de datos
- Juan Aquino
- Rodrigo Castro

## Primera entrega
En el presente proyecto se desarrollado una solución de seguridad orientada a la mensajeria instantánea ecriptada. Se tiene una aplicación web que permite la comunicación directa entre usuarios mediante un chat que asegura la privacidad mediante un cifrado de extremo a extremo (E2EE)-

## Motivación del Proyecto: Restableciendo la Privacidad en la Mensajería

En la mensajería instantánea actual, existe un problema fundamental: la **falta de privacidad y la dependencia total en la confianza del proveedor de servicio**. Los mensajes pueden ser interceptados o leídos por terceros, incluyendo a las propias empresas detrás de las aplicaciones. Esta vulnerabilidad es una constante amenaza para la confidencialidad de nuestras comunicaciones.

Nuestra solución aborda esto directamente mediante el **cifrado de extremo a extremo (E2EE)**. Esto significa que los mensajes se cifran en el dispositivo del remitente y solo se descifran en el del receptor. El servidor solo actúa como un intermediario que retransmite datos cifrados, sin la capacidad de leer el contenido original.

Con el E2EE, no solo protegemos tu información de accesos no autorizados, sino que te devolvemos el **control absoluto sobre tu privacidad**. La seguridad de tus conversaciones no depende de una promesa, sino de la **garantía matemática de la criptografía**. Este proyecto busca asegurar que tus palabras, y solo tus palabras, permanezcan confidenciales.

## Interfaz del cliente

<img width="828" alt="image" src="https://github.com/user-attachments/assets/73b0766d-b722-44b6-b8e9-cf302da9f1cf" />

## Objetivos

### Sobre seguridad con criptografía
- Se plantea tener un cifrado de extremo a extremo de los mensajes para garantizar la confiablidad absoluta de los usuarios.
- Se va implementar un sistema de distribución de llaves para autenticación(Protocolo Signal) y otorgar permisos en la aplicación.
- Permitir la comunicación asíncrona.
- Añadir autenticación fuera de banda.

### Sobre el esquema y medidas de seguridad para tener altos estándares de seguridad
1. Se autentifica a los usuarios que ingresan a la web mediante el registro de usuario - contraseña, usando tokens JWT para asegurar la identidad y seguridad de las cuentas de los usuarios.
2. Se registra los logs de las transmision y conexiones de los usuarios para monitorear y realizar auditorias ante posibles vulnerabilidades.
3. Se tendrá un backup de los mensajes del servidor, que almacena solo mensajes asíncronos que aún no se ha enviar a un usuario desconectado (todos encriptados).
4. Se tendrá autenticación adicional mediante certificados de seguridad, para garantizar la autenticidad de los usuarios que deseen comunicarse con usuarios no regitrados.

### Sobre el diseño y funcionalidades (con especificaciones de seguridad)

**Arquitectura**

![Etica y Seguridad de datos - diseño whatsapp drawio (1)](https://github.com/user-attachments/assets/c5097393-d042-4208-81a3-127424303bcc)

La aplicación tiene los siguientes flujos:

### Registro de usuarios
- Cliente A -> Servidor: Petición POST con username/password se registra en la aplicación.
- Servidor -> Cliente A: El servidor recibe la solicitud y genera tanto un token de autenticidad, registra al usuario y devuelve una respuesta con un token JWT si las credenciales son válidas.
- Cliente A -> Servidor: Genera las llaves para identificarse a largo plazo al usuario, la llave de identidad IK, la llave de session presignedkey SPK y llaves de autenticación por canal de comunicación one-time key OPK, y se suben al servidor.
- Servidor: Guarda las llaves públicas del usuario y dispone las llaves para conectar la comunicación con otros usuarios.

<img width="276" alt="image" src="https://github.com/user-attachments/assets/8c83376a-0fed-4168-bf1a-b99efb5fda1d" />

### Comunicación instantánea
1. Cliente A -> Servidor: Petición POST con username/password inicia sesión en la aplicación.
2. Servidor -> Cliente A: El servidor recibe la solicitud y genera tanto un token de autenticidad, registra al usuario y devuelve una respuesta con un token JWT si las credenciales son válidas.
3. Cliente A -> Servidor: Al registrarse se sube su clave pública.
4. Cliente A -> Servidor: Petición GET para solicitar la clave pública de Cliente B.
5. Servidor -> Cliente A: Devuelve la clave pública de Cliente B.
6. Cliente A: Cliente A usa su clave privada y la clave pública de B para calcular un secreto compartido.
7. Cliente A: Cifra el mensaje usando el Secreto Compartido.
8. Cliente A -> Servidor: Petición POST con el mensaje ya cifrado.
9. Servidor: Guarda el mensaje cifrado en MongoDB Atlas y emite el mensaje cifrado por Socket.IO.
10. Servidor: Servidor -> Cliente B (y Cliente A): Envío del mensaje cifrado a través del canal WebSocket.
11. Servidor: (Local en los Clientes): Descifran el mensaje con el Secreto Compartido para mostrarlo en la UI.

<img width="281" alt="image" src="https://github.com/user-attachments/assets/158ec3c0-837e-493f-ad3f-76a507e75b6e" />

<img width="590" alt="image" src="https://github.com/user-attachments/assets/7cefde76-88f4-4fd3-99c2-4f480ff3b6c5" />

## 1. Requerimientos de Funcionalidad

Basado en la descripción de la primera entrega, estos son los requerimientos de funcionalidad:

- **Comunicación de Mensajería Instantánea Segura:**
    - Permitir el envío y recepción de mensajes de texto entre usuarios registrados.
    - Implementar cifrado de extremo a extremo (E2EE) para todos los mensajes intercambiados en tiempo real.
    - Soportar comunicación asíncrona (mensajes enviados a usuarios desconectados se almacenan y se entregan al reconectarse).

- **Gestión de Usuarios:**
    - Registro de nuevos usuarios mediante nombre de usuario y contraseña.
    - Inicio de sesión de usuarios existentes mediante nombre de usuario y contraseña.
    - Autenticación de usuarios mediante JSON Web Tokens (JWT) para mantener la sesión y los permisos.

- **Gestión de Claves Criptográficas (Protocolo Signal):**
    - Manejo de llaves públicas y privadas.
    - Almacenamiento seguro de las claves públicas de los usuarios en el servidor para su distribución.
    - Solicitud de claves públicas de otros usuarios al servidor.

- **Funcionalidad de Chat:**
    - Interfaz de usuario para el envío y recepción de mensajes.
    - Visualización de mensajes descifrados en la interfaz del cliente.

- **Las medidas de seguridad implementadas deben permitir al usuario hacer uso de su data, y usar la aplicación con el fin especificado**:
    Las funcionalidades de registro, inicio de sesión, y comunicación con E2EE permiten a los usuarios interactuar con la aplicación de forma segura, sabiendo que sus conversaciones están protegidas. La gestión de claves está integrada en el flujo de uso, de modo que el cifrado es transparente para el usuario final, quien solo necesita iniciar sesión y chatear.

- **Base de datos (MongoDB Atlas)**: La elección de MongoDB Atlas ya implica que el proveedor maneja copias de seguridad automáticas, replicación para alta disponibilidad y recuperación ante desastres. Esto asegura la persistencia de mensajes asíncronos y claves públicas.

- **Código**: El código fuente se gestionaría en un sistema de control de versiones (ej. Git/GitHub) que permite la recuperación de versiones anteriores y actúa como un backup del código base.

- **Configuración de Servidores**: Implementación de prácticas de infraestructura como código (IaC) para la rápida reconstrucción de entornos en caso de fallo, con backups de configuración.

## 2. Requerimientos de Seguridad

Medidas de protección de datos en reposo y transporte:

- **Encriptación**:
    - Mensajes en tránsito: Cifrado de extremo a extremo (E2EE). Los mensajes son cifrados por el cliente remitente y solo pueden ser descifrados por el cliente receptor. El servidor solo ve datos cifrados.
    - Mensajes en reposo (servidor): Los mensajes asíncronos (los que esperan por un usuario desconectado) se almacenan en MongoDB Atlas ya encriptados por el E2EE, lo que significa que el servidor no tiene acceso al texto plano.
    - Contraseñas de usuario: Las contraseñas de usuario se almacenan como hashes criptográficos seguros (con salt) en la base de datos, nunca en texto plano.
    - Claves privadas: Las claves privadas de los usuarios no se almacenan en el servidor. Permanecen exclusivamente en el dispositivo del usuario, reforzando el E2EE.

- **Hashing**: Se utilizará hashing criptográfico (bcrypt) para el almacenamiento seguro de las contraseñas de los usuarios.

- **Gestión de accesos**:
    - Autenticación de usuario: Mediante combinación username/password y tokens JWT.
    - Autorización basada en JWT: Una vez autenticado, el JWT se utiliza para verificar la identidad del usuario en solicitudes posteriores, asegurando que solo los usuarios autenticados puedan acceder a las funcionalidades de la aplicación (ej. solicitar claves de otros usuarios, enviar mensajes).
    - Control de acceso a claves públicas: El servidor solo entrega claves públicas a usuarios que han iniciado sesión correctamente.

- **Registros de auditoría (logs)**:
    - Registro de logs de transmisiones y conexiones de usuarios en el servidor.
    - Los logs incluirán metadatos (quién se conectó, cuándo, a qué ruta, etc.), pero no el contenido de los mensajes cifrados. Esto permite monitorear actividades anómalas o intentos de acceso no autorizado sin comprometer la privacidad del contenido.

- **Políticas y Procedimientos**:
    - Política de Almacenamiento de Claves: Prohibir explícitamente el almacenamiento de claves privadas de usuario en el servidor.
    - Política de Retención de Mensajes: Definir un período de retención para mensajes asíncronos una vez entregados, o incluso eliminarlos inmediatamente después de la entrega exitosa.
    - Procedimientos de Autenticación: Establecer que toda interacción que requiera identificación de usuario debe pasar por el flujo de JWT.

- **Concientización (Awareness) y Formación del Equipo**:
    - Capacitación del equipo de desarrollo sobre la importancia del E2EE.
    - Énfasis en la seguridad del código (ej. prevención de inyección SQL, XSS, etc., aunque no directamente relacionados con el E2EE, son cruciales para la seguridad general).
    - Concientización sobre la importancia de la gestión de credenciales y la seguridad de los entornos de desarrollo.

- **Uso de herramientas para análisis de implementación**:
    - **Análisis Estático con SonarQube:**
        - Es una plataforma de **Análisis Estático de Código (SAST - Static Application Security Testing)** y gestión de calidad de código.
        - Nos permite analizar el código fuente sin ejecutarlo.
        - Detecta **bugs, code smells (malas prácticas de código), y vulnerabilidades de seguridad** en tiempo real.
        - Es conveniente si se quiere integrar funcionalidades implementadas en otros lenguajes ya que soporta múltiples lenguajes de programación (Java, C#, JavaScript, Python, PHP, etc.).
        - Proporciona un dashboard centralizado para visualizar los resultados, tendencias y deuda técnica, permitiendo asegurar la eficiencia y escalabilidad sinc comprometer la seguridad del servidor.

    - **Análisis Dinámico de Aplicaciones (DAST)**: Herramientas como OWASP ZAP o Burp Suite podrían utilizarse para realizar pruebas de penetración automatizadas contra la aplicación web desplegada, buscando vulnerabilidades como inyecciones, problemas de autenticación/autorización, o fallos en la configuración de la API.
    - **Auditoría de dependencias**: Herramientas como npm audit o Snyk se usarían para escanear las dependencias del proyecto en busca de vulnerabilidades conocidas.

- **Identificación de riesgos asociados a la data**:
    - **Brecha de datos de credenciales (username/password):**
        - Entidades afligidas: Usuarios (cuentas comprometidas), la reputación de la aplicación.
        - Impacto: Robo de identidad, acceso no autorizado a la cuenta, uso malintencionado de la cuenta.

    - **Compromiso de claves públicas almacenadas en el servidor:**
        - Entidades afligidas: Usuarios.
        - Impacto: Interceptación del primer mensaje (antes de que el Double Ratchet entre en pleno efecto), ataques de suplantación de identidad (si no hay autenticación fuera de banda robusta).

    - **Acceso no autorizado a mensajes asíncronos en MongoDB Atlas:**
        - Entidades afligidas: Usuarios cuya comunicación estaba pendiente.
        - Impacto: Divulgación de metadatos del mensaje (quién envió, cuándo), pero no del contenido (debido al E2EE). Podría revelar patrones de comunicación.

    - **Fuga de JWT (token de autenticación):**
        - Entidades afligidas: Usuarios.
        - Impacto: Suplantación de identidad hasta que el token expire o sea revocado.

    - **Compromiso de logs de auditoría:**
        - Entidades afligidas: Usuarios, administradores.
        - Impacto: Revelación de patrones de comunicación y metadatos, dificultando futuras auditorías.

- **Plan de respuesta ante incidentes de seguridad**:
    - **Detección y Notificación:**
        - Monitoreo constante de logs y alertas de seguridad.
        - Establecimiento de un canal de notificación para usuarios (ej. correo electrónico) y un sistema de alerta interno para el equipo.
    - **Contención:**
        - Aislamiento de sistemas comprometidos.
        - Revocación inmediata de tokens JWT comprometidos.
        - Restablecimiento forzado de contraseñas de usuarios afectados.
        - Deshabilitación temporal de funcionalidades vulnerables.
    - **Erradicación:**
        - Identificación y parcheo de la vulnerabilidad raíz.
        - Limpieza de cualquier artefacto malicioso.
        - Rotación de claves de API y credenciales de acceso a la base de datos.
    - **Recuperación:**
        - Restauración de sistemas desde backups limpios (si aplica).
        - Verificación de la integridad de los datos.
        - Reanudación gradual de los servicios.
    - **Análisis Post-Incidente:**
        - Revisión de los logs y análisis forense para entender la causa raíz y el alcance del incidente.
        - Actualización de políticas y procedimientos de seguridad.
        - Comunicación transparente con los usuarios afectados (si es necesario y apropiado, de acuerdo a la legislación).

- **Recomendaciones de protección de datos futura**:
    - **Autenticación Multifactor (MFA)**: Implementar MFA (ej. TOTP, SMS) para el inicio de sesión de los usuarios, añadiendo una capa extra de seguridad más allá de la contraseña.
    - **Rotación Automática de Claves (Signed Prekey, OPK)**: Automatizar la regeneración y subida de Signed Prekeys y One-Time Prekeys en el cliente a intervalos regulares, incluso si no han sido explícitamente "consumidas" por otro usuario (para mejorar la "freshness" de las claves).
    - **Certificados de Seguridad para usuarios no registrados (Autenticación fuera de banda)**: Implementar un sistema de intercambio de certificados autofirmados (o de una CA propia, como mencionaste) para usuarios que se comunican con no registrados, fortaleciendo la autenticidad fuera del flujo de registro tradicional. Esto también podría extenderse a usuarios registrados para una verificación adicional.
    - **Soporte de Forward Secrecy y Future Secrecy avanzado**: Asegurar que la implementación del Double Ratchet sea impecable para garantizar que una clave de sesión comprometida no revele comunicaciones pasadas (Forward Secrecy) ni futuras (Future Secrecy).
    - **Manejo de estados de sesión persistentes**: Para evitar la dependencia excesiva de OPKs en cada interacción, una gestión robusta del estado de la sesión Diffie-Hellman en el cliente (y potencialmente con un identificador de sesión en el servidor) puede mejorar la eficiencia y robustez.
    - **Auditorías de Seguridad Periódicas**: Contratar a terceros para realizar auditorías de seguridad y pruebas de penetración regulares del sistema para identificar y corregir vulnerabilidades.
    - **Monitorización de Comportamiento Anómalo**: Implementar sistemas que detecten patrones de acceso inusuales o comportamientos sospechosos en la red o en las cuentas de usuario.
    - **Controles de acceso basados en roles (RBAC)**: Si la aplicación crece para incluir roles administrativos, implementar RBAC para limitar el acceso a funcionalidades sensibles.

## 3. Otros Requerimientos Técnicos

- **Arquitectura Cliente-Servidor**:
    - Backend: Desarrollado con Node.js y Express (o similar), para la gestión de API REST y comunicación en tiempo real.
    - Frontend: Aplicación web (podría ser React, Angular, Vue o HTML/CSS/JS plano) para la interfaz de usuario.
- **Comunicación en Tiempo Real**:
    Uso de WebSockets (Socket.IO) para la comunicación bidireccional en tiempo real entre el servidor y los clientes para el envío instantáneo de mensajes.
- **Base de Datos**:
    - MongoDB Atlas: Como base de datos NoSQL para el almacenamiento de claves públicas de usuarios y mensajes asíncronos.
- **Gestión de Entorno**:
    Variables de entorno (.env) para la configuración sensible (URLs de base de datos, puertos, secretos JWT).
- **Uso de certificados digitales (Autofirmados o con una CA propia)**:
    - **Transporte seguro (HTTPS/WSS)**: Implementación de SSL/TLS para asegurar la comunicación entre el cliente y el servidor (API REST y WebSockets). Aunque para la primera entrega se están usando certificados autofirmados en desarrollo, para la segunda entrega se usará una CA de confianza (certificación real).
    - **Autenticación adicional mediante certificados de seguridad**: Como se menciona en los objetivos, para autenticar a usuarios que deseen comunicarse con usuarios no registrados, se puede implementar un mecanismo donde el cliente genere un par de claves y un certificado autofirmado (o emitido por una CA privada). Este certificado podría intercambiarse fuera de banda y usarse para verificar la identidad del cliente en el protocolo de establecimiento de sesión (más allá de JWT).

### Implementación propuesta y lograda:

**El proyecto engloba especificamente las siguientes tareas:**
- Creación de un framework para el usuario de mensajería instantánea.
- Implementar un sistema de distribución de llaves de altos estándares de seguridad por medio del protocolo de Signal.
- Encriptación de mensajes en el cliente, envió al servidor para transmisión E2EE.
- Permitir la transmición de mensajes asíncronos.
- Implementa autenticación fuera de banda.

**Para la primera entrega del proyecto se plantearon las siguientes tareas:**
- Implementar la interfaz tanto del usuario y en el backend para la mensajería instantánea, registro e inicio de sesión de usuarios.
- Implementar el sistema de gestión de llaves, tanto la autenticación por JWT, y de llave pública y privada.
- Implementar el sistema de cifrado de mensajes E2EE.
- Configuración del almacenamiento de mensajes y contraseñas con los respectivos backups(Mongodb-Atlas).

**Se culminaron todas**

### Lecciones aprendidas y retrospectiva.

**Conceptos nuevos**
- **Comunicación en Tiempo Real con WebSockets**: Descubrimos que la mensajería instantánea demanda una comunicación bidireccional y persistente entre el backend y el frontend. Para lograr esto de manera eficiente, fue esencial implementar WebSockets. Esta tecnología nos permitió enviar mensajes en tiempo real desde el servidor a los clientes sin necesidad de consultar constantemente (polling) nuevos endpoints, lo que optimizó el rendimiento y la fluidez de la experiencia de chat.
- **Gestión de Backups en la Nube (MongoDB Atlas)**: Implementar un sistema de respaldo robusto para nuestra base de datos resultó sorprendentemente eficiente gracias a los servicios SaaS de almacenamiento como MongoDB Atlas. Sus configuraciones de Cloud Backup están altamente optimizadas, permitiéndonos establecer políticas de snapshots continuos y recuperación puntual de forma rápida. Esto nos liberó de la compleja tarea de gestionar la infraestructura de backups manualmente, permitiéndonos concentrarnos en otros componentes críticos del proyecto.

**Desafios**
- **Implementación del Protocolo Signal**: El mayor desafío ha sido y sigue siendo la correcta implementación del Protocolo Signal para el cifrado de extremo a extremo. Esto iba mucho más allá de simplemente "cifrar mensajes", implicaba comprender y manejar la compleja derivación de claves criptográficas (KDF Chain y Double Ratchet) para cada mensaje. El objetivo es asegurar que cada mensaje se cifre con una clave única y efímera, aunque si se completo la gestión de llaves del protocolo X3ECDH(IK, SPK, OPK y EPK). Queda pendiente completar la derivación de llaves para la siguiente entrega.
