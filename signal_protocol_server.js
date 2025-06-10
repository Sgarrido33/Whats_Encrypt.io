const crypto = require('node:crypto');
const { Message, Keys } = require('./persistence_server');

/**
 * Implementación del Protocolo Signal en Node.js
 * Incluye X3DH key agreement y Double Ratchet
 */

class SignalCrypto {
  /**
   * Genera un par de claves X25519
   */
  static generateKeyPair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
    return {
      publicKey: publicKey.export({ type: 'spki', format: 'der' }),
      privateKey: privateKey.export({ type: 'pkcs8', format: 'der' })
    };
  }

  /**
   * Deriva una clave compartida usando ECDH X25519
   */
  static deriveSharedSecret(privateKey, publicKey) {
    const privKeyObj = crypto.createPrivateKey({
      key: privateKey,
      type: 'pkcs8',
      format: 'der'
    });
    const pubKeyObj = crypto.createPublicKey({
      key: publicKey,
      type: 'spki',
      format: 'der'
    });
    
    return crypto.diffieHellman({
      privateKey: privKeyObj,
      publicKey: pubKeyObj
    });
  }

  /**
   * HKDF - Derivación de clave usando HMAC
   */
  static hkdf(ikm, salt = Buffer.alloc(32), info = Buffer.alloc(0), length = 32) {
    const prk = crypto.createHmac('sha256', salt).update(ikm).digest();
    
    let prev = Buffer.alloc(0);
    const okmParts = [];

    let i = 1;
    while (Buffer.concat(okmParts).length < length) {
      const hmac = crypto.createHmac('sha256', prk);
      hmac.update(prev);
      hmac.update(info);
      hmac.update(Buffer.from([i]));
      const output = hmac.digest();

      okmParts.push(output);
      prev = output;
      i++;
    }

    const okm = Buffer.concat(okmParts);
    return okm.slice(0, length);
  }

  /**
   * Cifrado AES-256-GCM
   */
  static encrypt(key, plaintext, associatedData = Buffer.alloc(0)) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    // .createCipherGCM('aes-256-gcm');
    cipher.setAAD(associatedData);
    // cipher.init(key, iv);

    const ciphertext = Buffer.concat([
      cipher.update(plaintext),
      cipher.final()
    ]);
    
    const tag = cipher.getAuthTag();
    
    return {
      ciphertext,
      iv,
      tag
    };
  }

  /**
   * Descifrado AES-256-GCM
   */
  static decrypt(key, ciphertext, iv, tag, associatedData = Buffer.alloc(0)) {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    // .createDecipherGCM('aes-256-gcm');
    decipher.setAAD(associatedData);
    // decipher.init(key, iv);
    decipher.setAuthTag(tag);
    
    return Buffer.concat([
      decipher.update(ciphertext),
      decipher.final()
    ]);
  } 

  /**
   * Firma digital usando Ed25519
   */
  static sign(privateKey, message) {
    const key = crypto.createPrivateKey({
      key: privateKey,
      format: 'der',
      type: 'pkcs8'
    });

    if (key.asymmetricKeyType !== 'ed25519') {
      throw new Error('❌ La clave privada no es Ed25519');
    }

    return crypto.sign(null, message, key);
  }


  /**
   * Verificación de firma Ed25519
   */
  static verify(publicKey, identityKeyDH, message, signature) {
    const key = crypto.createPublicKey({
      key: publicKey,
      format: 'der',
      type: 'spki'
    });

    if (key.asymmetricKeyType !== 'ed25519') {
      throw new Error('❌ La clave pública no es Ed25519');
    }

    return crypto.verify(null, message, key, signature);
  }

}

class KeyManager {
  constructor() {
    this.identityKey = null;
    this.identityKeyDH = null;
    this.signedPrekey = null;
    this.oneTimePrekeys = [];
    this.prekeyId = 0;
  }

  /**
   * Inicializa las claves del usuario
   */
  genereateIdentityKey(){
    const identityKeyPair = crypto.generateKeyPairSync('ed25519');
      this.identityKey = {
        publicKey: identityKeyPair.publicKey.export({ type: 'spki', format: 'der' }),
        privateKey: identityKeyPair.privateKey.export({ type: 'pkcs8', format: 'der' })
      };
  }
  generateSignedPrekey(){
    const keyPair = SignalCrypto.generateKeyPair();
    const signature = SignalCrypto.sign(this.identityKey.privateKey, keyPair.publicKey);
    
    this.signedPrekey = {
      id: Date.now(),
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
      signature: signature
    };
  }
  async createUserOnDb(dbNewUserKeys){
    try {
      const keys = new Keys(dbNewUserKeys);
      await keys.save();
      console.log("Creado el usuario ",dbNewUserKeys.username)
    } catch (err) {
      console.error("Error al guardar usuario:", err);
    }
  }

  async create_user(){
    const userId = process.env.USERID;
    const username = process.env.USERNAME;
    
    this.genereateIdentityKey();
    this.generateSignedPrekey();
    
    let publicKeysToServer = {
      userId:userId,
      username:username,
      publicIdentityKey:this.identityKey,
      publicSignedPrekey:this.signedPrekey.publicKey,
      signature:this.signedPrekey.signature,
      timestamp: this.signedPrekey.id,
    }
    this.createUserOnDb(publicKeysToServer);
  }
  
  async getKeys(userId){
    let dbRequest = {
      userId:userId
    }
    const user = await Keys.findOne(dbRequest);
    if (user){
      return user
    }
    throw new Error("No existen llaves del usuario ",user_id);
  }
  async initialize() {
    // USER EXISTS?
    // ASUME QUE YA EXISTE
    const userId = process.env.USERNAME;
    const refreshTime = process.env.REFRESHTIME;
    
    let keys = this.getKeys(userId);
    if(refreshTime)

    this.user_id = user_id
    this.username = username
    this.publicIdentityKey = publicIdentityKey
    this.publicSignedPrekey = publicSignedPrekey
    this.signature = signature

    

    if (!dbResponse.exist){
      throw new Error("Usuario no existe")
    }
    // UPLOAD SIGNED USER KEYS
    let user = dbResponse.user;
    let username = user.username;
    let identityKey = user.identityKey;
    const updatedSession = await Session.findOneAndUpdate(
      { username: usernameToFind }, // Query: encontrar el documento con este username
      { ephimeralKey: newEphimeralKey }, // Update: establecer el nuevo valor para ephimeralKey
      { new: true } 
      // Opciones:
      //   - new: true  retorna el documento MODIFICADO después de la actualización
      //   - new: false (por defecto) retorna el documento ORIGINAL antes de la actualización
    );
    
    // console.log('✅ Claves inicializadas correctamente');
  }
  
  initializeNewUser(){
    // Generar Identity Key (para firmas)
    const identityKeyPair = crypto.generateKeyPairSync('ed25519');
    this.identityKey = {
      publicKey: identityKeyPair.publicKey.export({ type: 'spki', format: 'der' }),
      privateKey: identityKeyPair.privateKey.export({ type: 'pkcs8', format: 'der' })
    };
 
    const identityKeyDH = crypto.generateKeyPairSync('x25519');
    this.identityKeyDH = {
      publicKey: identityKeyDH.publicKey.export({ type: 'spki', format: 'der' }),
      privateKey: identityKeyDH.privateKey.export({ type: 'pkcs8', format: 'der' })
    };
    // Generar Ephimeral Key
    this.generateEphimeralKey(this.identityKey);
    
    // Generar Signed Prekey
    this.generateSignedPrekey();

    // Generar One-Time Prekeys
    this.generateOneTimePrekeys(10);

    // console.log('✅ Claves inicializadas correctamente');
  }
  /**
   * Genera y firma una nueva Signed Prekey
   */
  async validateRegistration(user_id){
    const dbRequest = {
      "username":user_id
    }
    try {
      const user = await User.findOne(dbRequest);
      // user ? console.log("Usuario ",user_id," encontrado"): console.log("Usuario ",user_id," no encontrado");
      return {
        exist:user? true:false,
        user:user,
      }
    } catch (err) {
      throw new Error("Error al buscar el usuario: " + err.message);
    }
  }
  generateEphimeralKey(identityKey){ // Usar una variable de entorno
    const ephemeralKey = SignalCrypto.generateKeyPair();
    
    const dbUser = {
      "username": username,
      "identityKey": identityKey,
      "ephimeralKey": ephemeralKey,  
    };

    User.create(dbMessage)
        .then(data => {
            res.status(201).send(data);
        })
        .catch(err => res.status(500).send(err));
  }

  /**
   * Genera múltiples One-Time Prekeys
   */
  generateOneTimePrekeys(count) {
    for (let i = 0; i < count; i++) {
      const keyPair = SignalCrypto.generateKeyPair();
      this.oneTimePrekeys.push({
        id: this.prekeyId++,
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey
      });
    }
  }

  /**
   * Obtiene un paquete de pre-claves públicas para compartir
   */
  getPrekeyBundle() {
    const oneTimePrekey = this.oneTimePrekeys.length > 0 ? 
      this.oneTimePrekeys[0] : null;

    return {
      identityKey: this.identityKey.publicKey,
      identityKeyDH: this.identityKeyDH.publicKey,
      signedPrekey: {
        id: this.signedPrekey.id,
        publicKey: this.signedPrekey.publicKey,
        signature: this.signedPrekey.signature
      },
      oneTimePrekey: oneTimePrekey ? {
        id: oneTimePrekey.id,
        publicKey: oneTimePrekey.publicKey
      } : null
    };
  }

  /**
   * Consume una One-Time Prekey
   */
  consumeOneTimePrekey(id) {
    const index = this.oneTimePrekeys.findIndex(key => key.id === id);
    if (index !== -1) {
      return this.oneTimePrekeys.splice(index, 1)[0];
    }
    return null;
  }

  /**
   * Verifica la firma de una Signed Prekey
   */
  verifySignedPrekey(identityKey, identityKeyDH, signedPrekeyPublic, signature) {
    return SignalCrypto.verify(identityKey, identityKeyDH, signedPrekeyPublic, signature);
  }
}

class SignalSession {
  constructor() {
    this.rootKey = null;
    this.sendingChain = null;
    this.receivingChain = null;
    this.dhRatchet = {
      sending: null,
      receiving: null
    };
    this.messageKeys = new Map();
    this.sendingChainCounter = 0;
    this.receivingChainCounter = 0;
    this.dhRatchetCounter = 0;
  }

  /**
   * Inicializa la sesión con la clave raíz derivada de X3DH
   */
  initializeSession(sharedSecret) {
    this.rootKey = SignalCrypto.hkdf(sharedSecret, Buffer.from('Signal Root Key'), Buffer.alloc(0), 32);
    
    // Generar el primer par de claves DH para el ratchet
    const dhKeyPair = SignalCrypto.generateKeyPair();
    this.dhRatchet.sending = dhKeyPair;

    // // También inicializar clave de recepción como espejo
    // this.dhRatchet.receiving = SignalCrypto.generateKeyPair();

    // Inicializar cadenas de envío y recepción
    this.initializeChains();
    
    // console.log('🔐 Sesión Signal inicializada');
  }

  /**
   * Inicializa las cadenas de cifrado
   */
  initializeChains() {
    const chainKey = SignalCrypto.hkdf(this.rootKey, Buffer.from('Signal Chain Key'), Buffer.alloc(0), 32);
    this.sendingChain = { key: chainKey, counter: 0 };
    this.receivingChain = { key: chainKey, counter: 0 };
  }

  /**
   * Avanza la cadena de claves
   */
  advanceChain(chainKey) {
    return SignalCrypto.hkdf(chainKey, Buffer.from('Signal Chain Advance'), Buffer.alloc(0), 32);
  }

  /**
   * Deriva una clave de mensaje de la cadena
   */
  deriveMessageKey(chainKey, counter) {

    // console.log("🔑 Derivando clave de mensaje con:");
    // console.log("- ChainKey:", chainKey.toString('hex'));
    // console.log("- Counter:", counter);
    // const info = Buffer.concat([Buffer.from('Signal Message Key'), Buffer.from([counter])]);

    const counterBuf = Buffer.alloc(4);
    counterBuf.writeUInt32BE(counter);
    const info = Buffer.concat([Buffer.from('Signal Message Key'), counterBuf]);
    return SignalCrypto.hkdf(chainKey, Buffer.from('Signal Message Salt'), info, 32);
  }

  /**
   * Cifra un mensaje
   */
  encryptMessage(plaintext) {
    try {
      // Derivar clave de mensaje
      const currentCounter = this.sendingChain.counter;

      const messageKey = this.deriveMessageKey(this.sendingChain.key, currentCounter);
      
      // Crear datos asociados
      const counterBuf = Buffer.alloc(4);
      counterBuf.writeUInt32BE(currentCounter); // o encryptedMessage.counter

      const ratchetBuf = Buffer.alloc(4);
      ratchetBuf.writeUInt32BE(this.dhRatchetCounter); // o encryptedMessage.dhRatchetCounter
      
      const associatedData = Buffer.concat([
        Buffer.from('Signal Message'),
        counterBuf,
        ratchetBuf
      ]);

      // const associatedData = Buffer.concat([
      //   Buffer.from('Signal Message'),
      //   Buffer.from([this.sendingChain.counter]),
      //   Buffer.from([this.dhRatchetCounter])
      // ]);

      // Cifrar mensaje
      const encrypted = SignalCrypto.encrypt(messageKey, Buffer.from(plaintext), associatedData);

      // Avanzar cadena
      this.sendingChain.key = this.advanceChain(this.sendingChain.key);
      this.sendingChain.counter++;

      const message = {
        ciphertext: encrypted.ciphertext.toString('base64'),
        iv: encrypted.iv.toString('base64'),
        tag: encrypted.tag.toString('base64'),
        counter:currentCounter,
        dhRatchetKey: this.dhRatchet.sending ? this.dhRatchet.sending.publicKey.toString('base64') : null,
        dhRatchetCounter: this.dhRatchetCounter
      };

      // console.log(`📤 Mensaje cifrado (counter: ${message.counter})`);
      // console.log("🧪 DEBUG ENCRIPT:", {
      //   key: messageKey.toString('hex'),
      //   counter: this.sendingChain.counter - 1,
      //   aad: associatedData.toString('hex'),
      //   message: message.dhRatchetKey
      // });

      console.log("🔐 Encrypting with:");
      console.log("  messageKey:", messageKey.toString('hex'));
      console.log("  counter:", currentCounter);
      // console.log("  dhRatchetCounter:", this.dhRatchetCounter);
      // console.log("  AAD:", associatedData.toString('hex'));

      return message;

    } catch (error) {
      console.error('❌ Error cifrando mensaje:', error.message);
      throw new Error('Fallo en el cifrado del mensaje');
    }
  }

  /**
   * Descifra un mensaje
   */
  decryptMessage(encryptedMessage) {
    try {
      // Verificar si necesitamos actualizar el DH ratchet
      console.log("antes:",this.receivingChain.key.toString('hex'))
      console.log(this.dhRatchet.receiving.publicKey.toString('base64'))
      console.log(encryptedMessage.dhRatchetKey)
      // console.log("encryptedMessage.counter:",encryptedMessage.counter)
      if (encryptedMessage.dhRatchetKey){
        if(this.dhRatchetCounter !== 0){

          this.dhRatchet.receiving = {
            publicKey: senderEphemeralKey, // la clave pública de Alice
            privateKey: this.keyManager.identityKeyDH.privateKey // su par que Bob usó en DH2
          };
        }  
        else if (!this.dhRatchet.receiving || this.dhRatchet.receiving.publicKey.toString('base64') !== encryptedMessage.dhRatchetKey) {  
            console.log("DERIVANDO")
            // console.log("this.dhRatchet.receiving.publicKey.toString('base64') !== encryptedMessage.dhRatchetKey")
            // console.log(this.dhRatchet.receiving.publicKey.toString('base64') !== encryptedMessage.dhRatchetKey)
            this.updateDHRatchet(Buffer.from(encryptedMessage.dhRatchetKey, 'base64'));
        }
      }
      // let tempKey = this.receivingChain.key;
      // let tempCounter = this.receivingChain.counter;

      // // Avanzar temporalmente hasta el counter del mensaje
      // while (tempCounter < encryptedMessage.counter) {
      //   tempKey = this.advanceChain(tempKey);
      //   tempCounter++;
      // }


      // Derivar messageKey desde el punto correcto sin alterar el estado real
      console.log("despues:",this.receivingChain.key.toString('hex'))
      const messageKey = this.deriveMessageKey(this.receivingChain.key, encryptedMessage.counter);
      // const messageKey = this.deriveMessageKey(this.receivingChain.key, encryptedMessage.counter);
      
      // Crear datos asociados
      
      console.log("📦 2")
      const counterBuf = Buffer.alloc(4);
      counterBuf.writeUInt32BE(encryptedMessage.counter);

      
      console.log("📦 3")
      const ratchetBuf = Buffer.alloc(4);
      ratchetBuf.writeUInt32BE(encryptedMessage.dhRatchetCounter);

      
      console.log("📦 4")
      const associatedData = Buffer.concat([
        Buffer.from('Signal Message'),
        counterBuf,
        ratchetBuf
      ]);

      const ivBuf = Buffer.from(encryptedMessage.iv, 'base64');
      const tagBuf = Buffer.from(encryptedMessage.tag, 'base64');
      const ciphertextBuf = Buffer.from(encryptedMessage.ciphertext, 'base64');
      console.log("📥 Decrypting with:");
      console.log("  messageKey:", messageKey.toString('hex'));
      // console.log("  counter:", encryptedMessage.counter);
      // console.log("  dhRatchetCounter:", encryptedMessage.dhRatchetCounter);
      
      // Descifrar mensaje
      
      console.log("📦 5")
      // console.log("🧪 Verificando parámetros:");
      // console.log("  key.len:", messageKey.length); // debe ser 32
      // console.log("  iv.len:", Buffer.from(encryptedMessage.iv, 'base64').length); // debe ser 12
      // console.log("  tag.len:", Buffer.from(encryptedMessage.tag, 'base64').length); // debe ser 16
      // console.log("  ciphertext.len:", Buffer.from(encryptedMessage.ciphertext, 'base64').length);
      // console.log("  aad:", associatedData.toString('hex'));

      const plaintext = SignalCrypto.decrypt(
        messageKey,
        Buffer.from(encryptedMessage.ciphertext, 'base64'),
        Buffer.from(encryptedMessage.iv, 'base64'),
        Buffer.from(encryptedMessage.tag, 'base64'),
        associatedData
      );

      // Avanzar cadena si es el mensaje esperado
      
      console.log("📦 6")
      if (encryptedMessage.counter === this.receivingChain.counter) {
        
        console.log("📦 7")
        this.receivingChain.key = this.advanceChain(this.receivingChain.key);
        
        console.log("📦 8")
        this.receivingChain.counter++;
      }

      // console.log(`📥 Mensaje descifrado (counter: ${encryptedMessage.counter})`);
      return plaintext.toString();

    } catch (error) {
      console.error('❌ Error descifrando mensaje:', error.message);
      throw new Error('Fallo en el descifrado del mensaje');
    }
  }

  /**
   * Actualiza el DH ratchet cuando se recibe una nueva clave pública
   */
  updateDHRatchet(newPublicKey) {
  // ✅ Usamos la clave privada de recepción anterior (si existe)
    // console.log("this.dhRatchet:",this.dhRatchet)
    const previousReceivingKey = this.dhRatchet.receiving?.privateKey;
    
    if (!previousReceivingKey) {
      console.warn('⚠️ No hay clave privada previa para derivar el DH ratchet.');
      return;
    }

    // 🔐 Derivar nuevo secreto compartido
    const dh = SignalCrypto.deriveSharedSecret(previousReceivingKey, newPublicKey);

    // 🔁 Derivar nueva root key
    this.rootKey = SignalCrypto.hkdf(this.rootKey, dh, Buffer.from('Signal Root Update'), 32);

    // 🔄 Generar nuevo par de claves DH (envío propio)
    this.dhRatchet.sending = SignalCrypto.generateKeyPair();

    // 📥 Guardar la nueva clave pública del otro como recepción
    this.dhRatchet.receiving = {
      publicKey: newPublicKey,
      privateKey: previousReceivingKey // mantener por si hay más mensajes en orden
    };

    // 🔄 Reinicializar cadenas con la nueva root key
    this.initializeChains();
    this.dhRatchetCounter++;

    // console.log('🔄 DH Ratchet actualizado correctamente');
  }
}

class SignalProtocol {
  constructor() {
    this.keyManager = new KeyManager();
    this.sessions = new Map();
  }

  /**
   * Inicializa el protocolo
   */
  initialize() {
    this.keyManager.initialize();
  }

  /**
   * Obtiene el paquete de pre-claves para compartir
   */
  getPrekeyBundle() {
    return this.keyManager.getPrekeyBundle();
  }

  /**
   * Crea una sesión con otro usuario (X3DH iniciador)
   */
  createSession(remotePrekeyBundle, userId) {
    // console.log('📩 Recibido prekey bundle de:', userId);
    // console.log('🧾 Verificando firma de signed prekey...');

    try {
      // Verificar la signed prekey
      if (!this.keyManager.verifySignedPrekey(
        remotePrekeyBundle.identityKey,
        remotePrekeyBundle.identityKeyDH,
        remotePrekeyBundle.signedPrekey.publicKey,
        remotePrekeyBundle.signedPrekey.signature
      )) {
        throw new Error('Firma de signed prekey inválida');
      }

      // Generar ephemeral key
      const ephemeralKey = SignalCrypto.generateKeyPair();

      // Realizar cálculos DH para X3DH
      const dh1 = SignalCrypto.deriveSharedSecret(
        this.keyManager.identityKeyDH.privateKey,
        remotePrekeyBundle.signedPrekey.publicKey
      );

      const dh2 = SignalCrypto.deriveSharedSecret(
        ephemeralKey.privateKey,
        remotePrekeyBundle.identityKeyDH
      );

      const dh3 = SignalCrypto.deriveSharedSecret(
        ephemeralKey.privateKey,
        remotePrekeyBundle.signedPrekey.publicKey
      );

      let dh4 = Buffer.alloc(0);
      let usedOPKId = null;
      if (remotePrekeyBundle.oneTimePrekey) {
        dh4 = SignalCrypto.deriveSharedSecret(
          ephemeralKey.privateKey,
          remotePrekeyBundle.oneTimePrekey.publicKey
        );
        usedOPKId = remotePrekeyBundle.oneTimePrekey.id;
      }
      // console.log('📡 DH1 (IKpriv, SPKpub):', dh1.toString('hex'));
      // console.log('📡 DH2 (EKpriv, IKpub):', dh2.toString('hex'));
      // console.log('📡 DH3 (EKpriv, SPKpub):', dh3.toString('hex'));
      // if (remotePrekeyBundle.oneTimePrekey) {
      //   console.log('📡 DH4 (EKpriv, OPKpub):', dh4.toString('hex'));
      // } else {
      //   console.log('📭 No se usó One-Time Prekey (OPK)');
      // }

      // console.log('DH1:', dh1);
      // console.log('DH2:', dh2);
      // console.log('DH3:', dh3);
      // console.log('DH4:', dh4);
      // Combinar secretos DH
      const sk = Buffer.concat([dh1, dh2, dh3, dh4]);
      // console.log('🔗 Concatenando secretos DH, total:', sk.length);

      // console.log('SK length:', sk.length);
      // if (sk.length < 32) {
      //   throw new Error('Shared key material (sk) is too short for HKDF');
      // }

      // console.log('🔐 SK:', sk.toString('hex'), 'Length:', sk.length);

      if (sk.length === 0) {
        throw new Error('❌ Error: Secret key material está vacío antes de HKDF');
      }
      // Derivar clave compartida inicial
      const sharedSecret = SignalCrypto.hkdf(sk, Buffer.from('Signal X3DH'), Buffer.alloc(0), 32);

      // Crear y configurar sesión
      const session = new SignalSession();
      session.initializeSession(sharedSecret);
      this.sessions.set(userId, session);

      // Crear mensaje de inicialización
      const initMessage = {
        type: 'session_init',
        identityKey: this.keyManager.identityKeyDH.publicKey.toString('base64'),
        ephemeralKey: ephemeralKey.publicKey.toString('base64'),
        usedOneTimePrekey: usedOPKId
      };

      // console.log('📤 Enviando mensaje de sesión inicial:', initMessage);
      // console.log(`🤝 Sesión creada con usuario ${userId}`);
      return { session, initMessage };

    } catch (error) {
      console.error('❌ Error creando sesión:', error.message);
      throw error;
    }
  }

  /**
   * Procesa un mensaje de inicialización de sesión (X3DH receptor)
   */

  processSessionInit(initMessage, userId) {
    try {      
      const senderIdentityKey = Buffer.from(initMessage.identityKey, 'base64');
      const senderEphemeralKey = Buffer.from(initMessage.ephemeralKey, 'base64');
      // Realizar cálculos DH (receptor)
      const dh1 = SignalCrypto.deriveSharedSecret(
        this.keyManager.signedPrekey.privateKey,
        senderIdentityKey
      );

      const dh2 = SignalCrypto.deriveSharedSecret(
        this.keyManager.identityKeyDH.privateKey,
        senderEphemeralKey
      );

      const dh3 = SignalCrypto.deriveSharedSecret(
        this.keyManager.signedPrekey.privateKey,
        senderEphemeralKey
      );

      let dh4 = Buffer.alloc(0);

      if (initMessage.usedOneTimePrekey !== null) {
        const oneTimePrekey = this.keyManager.consumeOneTimePrekey(initMessage.usedOneTimePrekey);
        if (oneTimePrekey) {
          dh4 = SignalCrypto.deriveSharedSecret(oneTimePrekey.privateKey, senderEphemeralKey);
        }
      }
      
      const sk = Buffer.concat([dh1, dh2, dh3, dh4]);
      // console.log('🔗 Concatenando secretos DH, total:', sk.length);
      
      // Derivar la misma clave compartida
      const sharedSecret = SignalCrypto.hkdf(sk, Buffer.from('Signal X3DH'), Buffer.alloc(0), 32);
      
      // Crear y configurar sesión
      const session = new SignalSession();
      
      session.initializeSession(sharedSecret);

      // session.dhRatchet.receiving = {
      //   publicKey: senderEphemeralKey, // la clave pública de Alice
      //   privateKey: this.keyManager.identityKeyDH.privateKey // su par que Bob usó en DH2
      // };
      this.sessions.set(userId, session);      
      // console.log('✅ Sesión establecida correctamente con usuario:', userId);
      return session;
    } catch (error) {
      console.error('❌ Error procesando inicialización de sesión:', error.message);
      throw error;
    }
  }

  /**
   * Cifra un mensaje para un usuario específico
   */
  encryptMessage(userId, plaintext) {
    const session = this.sessions.get(userId);
    if (!session) {
      throw new Error(`No hay sesión establecida con el usuario ${userId}`);
    }
    return session.encryptMessage(plaintext);
  }

  /**
   * Descifra un mensaje de un usuario específico
   */
  decryptMessage(userId, encryptedMessage) {
    const session = this.sessions.get(userId);
    if (!session) {
      throw new Error(`No hay sesión establecida con el usuario ${userId}`);
    }
    return session.decryptMessage(encryptedMessage);
  }

  /**
   * Obtiene información del estado de las sesiones
   */
  getSessionInfo() {
    const info = {
      activeSessions: this.sessions.size,
      availableOneTimePrekeys: this.keyManager.oneTimePrekeys.length,
      identityKeyId: this.keyManager.identityKey ? 'presente' : 'ausente'
    };
    return info;
  }
}

  // Función de demostración
function demonstrateSignalProtocol() {
  console.log('🚀 Demostración del Protocolo Signal\n');

  // Inicializar Alice y Bob
  const alice = new SignalProtocol();
  const bob = new SignalProtocol();

  alice.initialize();
  bob.initialize();

  console.log('👥 Alice y Bob inicializados');

  // Alice obtiene el paquete de pre-claves de Bob
  const bobPrekeyBundle = bob.getPrekeyBundle();
  console.log('📦 Alice obtiene el paquete de pre-claves de Bob');

  // 🐞 DEBUG: Inspeccionando el bundle de Bob antes de crear la sesión
  // console.log('📦 Bob Prekey Bundle:');
  // console.log({
  //   identityKey: bobPrekeyBundle.identityKey?.toString('base64'),
  //   identityKeyDH: bobPrekeyBundle.identityKeyDH?.toString('base64'),
  //   signedPrekey: {
  //     id: bobPrekeyBundle.signedPrekey.id,
  //     publicKey: bobPrekeyBundle.signedPrekey.publicKey?.toString('base64'),
  //     signature: bobPrekeyBundle.signedPrekey.signature?.toString('base64'),
  //   },
  //   oneTimePrekey: bobPrekeyBundle.oneTimePrekey
  //     ? {
  //         id: bobPrekeyBundle.oneTimePrekey.id,
  //         publicKey: bobPrekeyBundle.oneTimePrekey.publicKey?.toString('base64'),
  //       }
  //     : null,
  // });

    // ✅ Verifica si la firma de la signedPrekey es válida manualmente (opcional doble chequeo)
    const isValid = alice.keyManager.verifySignedPrekey(
      bobPrekeyBundle.identityKey,
      bobPrekeyBundle.identityKeyDH,
      bobPrekeyBundle.signedPrekey.publicKey,
      bobPrekeyBundle.signedPrekey.signature
    );
    console.log(`🔐 Firma de Signed Prekey válida: ${isValid}`);

    // 🛠️ Crear sesión
    const { session: aliceSession, initMessage } = alice.createSession(bobPrekeyBundle, 'bob');
    console.log('✅ Alice crea la sesión con Bob');

    // 📤 DEBUG: Contenido del mensaje de inicialización
    // console.log('📨 Mensaje de inicialización enviado a Bob:');
    // console.log({
    //   type: initMessage.type,
    //   identityKey: initMessage.identityKey,
    //   ephemeralKey: initMessage.ephemeralKey,
    //   usedOneTimePrekey: initMessage.usedOneTimePrekey,
    // });

    // 🧠 DEBUG: Estado de la sesión de Alice
    // console.log('🧠 Estado de la sesión de Alice:');
    // console.log({
      // rootKey: aliceSession.rootKey.toString('hex'),
      // dhRatchet_sending: aliceSession.dhRatchet.sending,
      // dhRatchet_receiving: aliceSession.dhRatchet.receiving,
      // sendingKey: aliceSession.sendingChain.key.toString('hex'),
      // receivingKey: aliceSession.receivingChain.key.toString('hex'),
      // sendingCounter: aliceSession.sendingChain.counter,
      // receivingCounter: aliceSession.receivingChain.counter,
    // });



    // Bob procesa el mensaje de inicialización de Alice
    const bobSession = bob.processSessionInit(initMessage, 'alice');
    console.log('Bob procesa el mensaje de inicialización de Alice');
    // console.log("Root key Alice:", aliceSession.rootKey.toString("hex"));
    // console.log("Root key Bob:  ", bobSession.rootKey.toString("hex"));

    // console.log('🧠 Estado de la sesión de Bob:');
    // console.log({
    //   rootKey: bobSession.rootKey.toString('hex'),
    //   dhRatchet_sending: bobSession.dhRatchet.sending,
    //   dhRatchet_receiving: bobSession.dhRatchet.receiving,
      // rootKey: bobSession.rootKey.toString('hex'),
      // sendingKey: bobSession.sendingChain.key.toString('hex'),
      // receivingKey: bobSession.receivingChain.key.toString('hex'),
      // sendingCounter: bobSession.sendingChain.counter,
      // receivingCounter: bobSession.receivingChain.counter,
    // });

  console.log('\n💬 Intercambio de mensajes:');

  // Alice envía mensajes a Bob
  console.log('Alice → Bob:')
  console.log('Hola Bob! 👋')
  const message1 = alice.encryptMessage('bob', 'Hola Bob! 👋');
  console.log('ya envio')
  // console.log(JSON.stringify(message1, null, 2));
  console.log("message1:", message1)
  console.log('Bob recibe:')
  const decrypted1 = bob.decryptMessage('alice', message1);
  console.log(decrypted1)
  console.log('ya envio')
  // console.log(decrypted1);

  // Bob responde a Alice
  console.log('\nBob → Alice:')
  const message2 = bob.encryptMessage('alice', '¡Hola Alice! ¿Cómo estás? 😊');
  console.log('ya envio')
  // console.log(JSON.stringify(message2, null, 2));

  console.log('Alice recibe:')
  const decrypted2 = alice.decryptMessage('bob', message2);
  console.log('ya envio')
  // console.log(decrypted2);

  // Más mensajes para demostrar el ratchet
  console.log('\nAlice → Bob:')
  const message3 = alice.encryptMessage('bob', 'Todo bien, gracias por preguntar 🎉');
  const decrypted3 = bob.decryptMessage('alice', message3);
  console.log('ya envio')
  // console.log(decrypted3);

  console.log('\n📊 Estado de las sesiones:');
  console.log('Alice:', alice.getSessionInfo());
  console.log('Bob:', bob.getSessionInfo());

  console.log('\n✅ Demostración completada exitosamente!');
}

function formalTest() {
  // 
  const alice = new SignalProtocol();
  alice.initialize();
  alice.uploadEphimeralKey();

  const bob = new SignalProtocol();
  bob.initialize();
  bob.uploadEphimeralKey();
}
// Exportar clases y función de demostración
module.exports = {
  SignalProtocol,
  SignalSession,
  KeyManager,
  SignalCrypto,
  demonstrateSignalProtocol
};

// Ejecutar demostración si el archivo se ejecuta directamente
if (require.main === module) {
  demonstrateSignalProtocol();
}