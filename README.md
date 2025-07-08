# Proyecto - Ética y Seguridad de datos
- Juan Aquino
- Rodrigo Castro

## Resumen del Proyecto
En el presente proyecto se ha desarrollado una solución de seguridad orientada a la mensajería instantánea. Se tiene una aplicación web que permite la comunicación directa entre usuarios mediante un chat que asegura la privacidad y confidencialidad a través de un cifrado de extremo a extremo (E2EE) robusto.

## Motivación del Proyecto: Restableciendo la Privacidad en la Mensajería

En la mensajería instantánea actual, existe un problema fundamental: la **falta de privacidad y la dependencia total en la confianza del proveedor de servicio**. Los mensajes pueden ser interceptados o leídos por terceros, incluyendo a las propias empresas detrás de las aplicaciones. Esta vulnerabilidad es una constante amenaza para la confidencialidad de nuestras comunicaciones.

Nuestra solución aborda esto directamente mediante el **cifrado de extremo a extremo (E2EE)**. Esto significa que los mensajes se cifran en el dispositivo del remitente y solo se descifran en el del receptor. El servidor solo actúa como un intermediario que retransmite datos cifrados, sin la capacidad de leer el contenido original.

Con el E2EE, no solo protegemos tu información de accesos no autorizados, sino que te devolvemos el **control absoluto sobre tu privacidad**. La seguridad de tus conversaciones no depende de una promesa, sino de la **garantía matemática de la criptografía**. Este proyecto busca asegurar que tus palabras, y solo tus palabras, permanezcan confidenciales.

## Interfaz del cliente

<img width="828" alt="image" src="https://github.com/user-attachments/assets/73b0766d-b722-44b6-b8e9-cf302da9f1cf" />

## Objetivos

### Sobre la Criptografía Implementada
- Se ha implementado un cifrado E2EE para todos los mensajes, garantizando la confidencialidad absoluta de las conversaciones.
- Se implementó un protocolo personalizado basado en ECIES (Elliptic Curve Integrated Encryption Scheme) para proteger cada mensaje individualmente.
- Gracias al uso de claves efímeras por mensaje en el esquema ECIES, se garantiza que si la clave de largo plazo de un usuario es comprometida, los mensajes pasados no pueden ser descifrados.
- La arquitectura soporta el almacenamiento de mensajes cifrados para usuarios desconectados, que se entregan de forma segura cuando el usuario vuelve a estar en línea.

### Sobre el esquema y medidas de seguridad 
1. Se utiliza un sistema de registro de usuario/contraseña, con contraseñas hasheadas mediante bcrypt. Las sesiones se gestionan con JSON Web Tokens (JWT) para asegurar la identidad y los permisos en cada solicitud.
2. El servidor registra metadatos de conexión y transmisión para monitoreo y auditoría, sin almacenar nunca el contenido de los mensajes.
3. Los mensajes asíncronos se almacenan en la base de datos (MongoDB Atlas) en su formato cifrado, inaccesibles para el servidor. Las claves privadas de los usuarios nunca abandonan el dispositivo del cliente.

### Sobre el diseño y funcionalidades (con especificaciones de seguridad)

**Arquitectura**

![Etica y Seguridad de datos - diseño whatsapp drawio (1)](https://github.com/user-attachments/assets/c5097393-d042-4208-81a3-127424303bcc)

La aplicación tiene los siguientes flujos:

### Registro de usuarios
-Un cliente se registra en el servidor con su usuario y contraseña. El servidor devuelve un token JWT.
-Tras el primer inicio de sesión, el cliente genera un par de claves de identidad de largo plazo (basadas en curvas elípticas).
-El cliente almacena su clave privada de forma segura en el almacenamiento local del navegador (IndexedDB) y sube su clave pública de identidad al servidor.
-El servidor almacena esta clave pública para distribuirla a otros usuarios que deseen iniciar una conversación.

<img width="276" alt="image" src="https://github.com/user-attachments/assets/8c83376a-0fed-4168-bf1a-b99efb5fda1d" />

### Comunicación instantánea
1. El Cliente A inicia sesión y recibe un token JWT.

2. Para enviar un mensaje al Cliente B, el Cliente A solicita la clave pública de identidad del Cliente B al servidor.

3.  
   a. El Cliente A genera un par de claves efímeras (de un solo uso).  
   b. Usando su clave privada efímera y la clave pública de identidad del Cliente B, calcula un secreto compartido mediante el algoritmo ECDH.  
   c. A partir de este secreto, deriva una clave de cifrado simétrico (AES) y la usa para cifrar el mensaje.

4. El Cliente A envía un paquete al servidor que contiene el mensaje cifrado, su clave pública efímera y otros datos necesarios para el descifrado.

5. El servidor recibe el paquete cifrado y lo retransmite a todos los participantes de la conversación (incluido el emisor) a través de Socket.IO.

6.  
   a. El Cliente B (receptor) recibe el paquete.  
   b. Usando su clave privada de identidad y la clave pública efímera del Cliente A (que venía en el paquete), calcula el mismo secreto compartido.  
   c. Deriva la misma clave AES y descifra el mensaje para mostrarlo en la interfaz.


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

### Uso de herramientas para análisis de implementación

#### **Análisis estático con SonarQube**

* Se utilizó **SonarQube**, una plataforma de **Análisis Estático de Código (SAST - Static Application Security Testing)** y gestión de calidad del software.
* Esta herramienta permite analizar el código fuente sin necesidad de ejecutarlo.
* Detecta **errores (bugs), malas prácticas de codificación (code smells) y vulnerabilidades de seguridad** en tiempo real.
* Resulta especialmente útil para proyectos que integran distintos lenguajes, ya que SonarQube soporta múltiples tecnologías como Java, C#, JavaScript, Python, PHP, entre otras.
* Proporciona un panel centralizado para visualizar los resultados, identificar tendencias y calcular la deuda técnica, permitiendo mejorar la eficiencia y escalabilidad del sistema sin comprometer su seguridad.

#### **Detección de vulnerabilidades de seguridad**

* SonarQube asigna una calificación de riesgo a las vulnerabilidades detectadas en una escala que va de **E (riesgo crítico)** a **A (riesgo bajo)**, facilitando la priorización de soluciones según el impacto potencial en la aplicación.
* En el análisis realizado, se identificaron vulnerabilidades principalmente en la conexión con el backend.



#### **Reporte de métricas de SonarQube**

* La herramienta permite monitorear el progreso del desarrollo, mostrando el tiempo transcurrido desde la detección de una vulnerabilidad, así como el tiempo estimado para su resolución.
* Cada hallazgo incluye una explicación detallada y una propuesta de solución, destacando las líneas específicas de código involucradas.

<img width="699" alt="image" src="https://github.com/user-attachments/assets/349c56b5-736e-4968-9572-7cc6455ceb98" />
    
**Ejemplo detectado:**
Se identificó un riesgo en el servidor debido a una configuración insegura de **CORS** (Cross-Origin Resource Sharing), que permitía el acceso desde cualquier dominio. Esta mala configuración podría permitir a sitios maliciosos evadir restricciones del navegador y acceder a datos sensibles del usuario.


<img width="710" alt="image" src="https://github.com/user-attachments/assets/2efba513-5861-4c05-9649-bb06fa6df968" />

* SonarQube sugiere correcciones específicas para este tipo de vulnerabilidades mediante recomendaciones basadas en el análisis del código estático.
* Además Sonarqube detalla cada vulnerabilidad explicando que se debe hacer para resolver y enmarca las líneas de código de la vulnerabilidad.

<img width="756" alt="image" src="https://github.com/user-attachments/assets/ed7eaf79-a67a-402c-8ab9-eb0442126714" />

En este caso el riesgo detectado fue en el servidor, en la forma que configuramos CORS, permitiendo acceso desde cualquier dominio. Esto permite que un sitio web malicioso ignore las restricciones de seguridad del navegador y robe datos sensibles.

<img width="456" alt="image" src="https://github.com/user-attachments/assets/5bb54927-4bc0-48ad-b956-9b3ead76dc61" />

- A continuación esta la solución propuesta por Sonarqube basado en el análisis del código estático.

<img width="735" alt="image" src="https://github.com/user-attachments/assets/e0c133b1-509d-4dee-8c2b-ce88577b47d1" />

#### **Detección de bugs y deuda técnica**

* Además de los problemas de seguridad, SonarQube también identifica errores lógicos y otros factores que contribuyen a la **deuda técnica**, ayudando a mantener un código más limpio, mantenible y escalable.

<img width="671" alt="image" src="https://github.com/user-attachments/assets/583e6f5d-7498-441f-93ec-771dfe07cafe" />

### Resumen de las vulnerabilidades encontradas:

### Vulnerabilidades detectadas

#### whatsapp-backend/server.js
- Inyección SQL: construye consultas directamente con datos controlados por el usuario (múltiples flujos de ejecución).  
- Uso de encadenamiento opcional: se recomienda `?.` para mayor legibilidad.

#### whatsapp-frontend/src/App.js
- Profundidad excesiva de funciones (anidamiento > 4 niveles) en 4 ubicaciones.

#### whatsapp-frontend/src/Chat.js
- Props no validadas:  
  `messages`, `userName`, `chatUser`, `conversationId`, `otherUserId`, `setMessages`.  
- Uso de propiedades sin validación en iteraciones: `chatUser[].toUpperCase`, `messages.map`.

#### whatsapp-frontend/src/Login.js & Register.js
- Props no validadas:  
  Login: `onRegisterClick`, `onLoginSuccess`.  
  Register: `onLoginClick`, `onRegisterSuccess`.  
- Elementos interactivos no nativos sin rol ni manejo de teclado/ratón/táctil.

#### whatsapp-frontend/src/Sidebar.js
- Imports no usados: `DonutLargeIcon`, `ChatIcon`, `MoreVertIcon`.  
- Props no validadas: `userName`, `onLogout`, `selectChat`, `activeChatId`, `socket`.  
- Anidamiento excesivo de funciones (> 4 niveles) en múltiples ubicaciones.  
- Interactividad accesible: añadir roles y listeners de teclado.

#### whatsapp-frontend/src/SidebarChat.js
- Props no validadas: `otherUser`, `lastMessage`, `isActive`, `onClick`.  
- Uso de propiedades sin validación: `otherUser[].toUpperCase`, `lastMessage.ciphertext`.  
- Elemento interactivo no nativo: añadir rol y soporte de teclado/ratón/táctil.

#### whatsapp-frontend/src/crypto-service.js
- TODOs pendientes: completar tareas indicadas en comentarios.  
- Variables sin usar y asignaciones inútiles:  
  `identityKeyPubJwk`, `signedPreKeyPubJwk`, `opkPubJwk`.  


    
### **Identificación de riesgos asociados a la data**:

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

### **Plan de respuesta ante incidentes de seguridad**:
**Detección y Notificación:** 

- Monitoreo constante de logs y alertas de seguridad.

- Establecimiento de un canal de notificación para usuarios (ej. correo electrónico) y un sistema de alerta interno para el equipo.
    
**Contención:**
- Aislamiento de sistemas comprometidos.
- Revocación inmediata de tokens JWT comprometidos.
- Restablecimiento forzado de contraseñas de usuarios afectados.
- Deshabilitación temporal de funcionalidades vulnerables.

**Erradicación:**
  
- Identificación y parcheo de la vulnerabilidad raíz.
- Limpieza de cualquier artefacto malicioso.
- Rotación de claves de API y credenciales de acceso a la base de datos.

**Recuperación:**

- Restauración de sistemas desde backups limpios (si aplica).
- Verificación de la integridad de los datos.
- Reanudación gradual de los servicios.

**Análisis Post-Incidente:**

- Revisión de los logs y análisis forense para entender la causa raíz y el alcance del incidente.
- Actualización de políticas y procedimientos de seguridad.
- Comunicación transparente con los usuarios afectados (si es necesario y apropiado, de acuerdo a la legislación).
  

**Recomendaciones de protección de datos futura**:

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
- Implementar un sistema de distribución de llaves de altos estándares de seguridad.
- Encriptación de mensajes en el cliente, envió al servidor para transmisión E2EE.
- Permitir la transmición de mensajes asíncronos.
- Implementa autenticación fuera de banda.

**Para la primera entrega del proyecto se plantearon las siguientes tareas:**
- Implementar la interfaz tanto del usuario y en el backend para la mensajería instantánea, registro e inicio de sesión de usuarios.
- Implementar el sistema de gestión de llaves, tanto la autenticación por JWT, y de llave pública y privada.
- Implementar el sistema de cifrado de mensajes E2EE.
- Configuración del almacenamiento de mensajes y contraseñas con los respectivos backups(Mongodb-Atlas).

**Para la segunda entrega del proyecto se plantearon las siguientes tareas:**
- Realizar un análisis de la implementación basada basada en herramientas especializadas, elegimos Sonarqube.
- Implementar un protocolo personalizado basado ECIES para el esquema de seguridad.

### Protocolo de Cifrado Implementado

El proyecto implementa un protocolo de cifrado híbrido sin estado basado en ECIES. Este enfoque fue elegido por su robusta seguridad y menor complejidad de implementación en comparación con protocolos con estado como Signal.

1. **Esquema:** ECIES (Elliptic Curve Integrated Encryption Scheme), versión ECIES_V1.

2. **Generación de Claves por Mensaje:** Para cada mensaje, se genera un nuevo par de claves efímeras usando la curva ECDH P-256. Esto garantiza la Confidencialidad Futura (Forward Secrecy).

3. **Derivación de Clave:** El secreto compartido se procesa con HKDF (SHA-256) para derivar una clave de cifrado simétrico segura.

4. **Cifrado Simétrico:** El mensaje se cifra usando AES-256-GCM, que proporciona tanto confidencialidad como autenticación del texto cifrado.

5. **Payload Final:** El paquete enviado al servidor contiene { type: 'ECIES_V1', ephemeralPublicKey, iv, ciphertext }, haciendo que cada mensaje sea un paquete criptográfico autocontenido.

**Nota**: Este protocolo no implementa el Double Ratchet del Protocolo Signal, por lo que no posee la propiedad de auto-reparación (Post-Compromise Security). Sin embargo, ofrece un nivel de seguridad muy alto, adecuado para la mayoría de los casos de uso.

**Se culminaron todas**

### Consideraciones Éticas y de Privacidad

La aplicación ha sido diseñada con el principio fundamental de **restablecer la privacidad en la mensajería instantánea**, evitando la dependencia de terceros para proteger la confidencialidad de las comunicaciones. Las principales consideraciones éticas y de privacidad son:

- **Privacidad por diseño**: El cifrado de extremo a extremo (E2EE) garantiza que solo el emisor y el receptor puedan acceder al contenido de los mensajes, incluso el servidor actúa únicamente como intermediario de datos cifrados.

- **Autonomía del usuario**: Las claves privadas nunca se almacenan en el servidor, manteniéndose en el dispositivo del usuario. Esto da control total sobre la información compartida.

- **Minimización de datos**: Se evita almacenar información sensible en texto plano (como contraseñas o mensajes). Se utilizan hashes seguros (bcrypt) y cifrado robusto para datos en tránsito y en reposo.

- **Transparencia y trazabilidad**: Se registran logs de conexión y transmisión sin comprometer el contenido de los mensajes, lo que permite auditorías responsables sin violar la privacidad.

- **Prevención de abusos**: Se establecen políticas como la no retención de mensajes una vez entregados, autenticación robusta con JWT, y mecanismos para mitigar accesos no autorizados.

- **Responsabilidad técnica**: Se promueve la implementación segura del protocolo ECIES, incluyendo autenticación fuera de banda y análisis estático del código para detectar vulnerabilidades antes del despliegue.

Estas medidas aseguran que la aplicación respeta los derechos digitales de los usuarios, cumpliendo con principios éticos de seguridad, confidencialidad y responsabilidad tecnológica.



### Lecciones aprendidas y retrospectiva.

**Conceptos nuevos**
- **Comunicación en Tiempo Real con WebSockets**: Descubrimos que la mensajería instantánea demanda una comunicación bidireccional y persistente entre el backend y el frontend. Para lograr esto de manera eficiente, fue esencial implementar WebSockets. Esta tecnología nos permitió enviar mensajes en tiempo real desde el servidor a los clientes sin necesidad de consultar constantemente (polling) nuevos endpoints, lo que optimizó el rendimiento y la fluidez de la experiencia de chat.
- **Gestión de Backups en la Nube (MongoDB Atlas)**: Implementar un sistema de respaldo robusto para nuestra base de datos resultó sorprendentemente eficiente gracias a los servicios SaaS de almacenamiento como MongoDB Atlas. Sus configuraciones de Cloud Backup están altamente optimizadas, permitiéndonos establecer políticas de snapshots continuos y recuperación puntual de forma rápida. Esto nos liberó de la compleja tarea de gestionar la infraestructura de backups manualmente, permitiéndonos concentrarnos en otros componentes críticos del proyecto.

**Desafios**
- **Evaluación de Protocolos Criptográficos**: El desafío inicial fue la intención de implementar el Protocolo Signal. Sin embargo, un análisis profundo reveló su alta complejidad, especialmente en la gestión de estado del Double Ratchet. Esto condujo a una decisión: pivotar hacia un protocolo sin estado basado en ECIES. Esta decisión permitió entregar un producto final robusto y seguro, que cumple con el requisito crítico de Confidencialidad Futura, dentro de las limitaciones del proyecto. La lección más importante fue la necesidad de equilibrar la seguridad teórica "perfecta" con la complejidad de implementación práctica para construir un sistema seguro y funcional.
