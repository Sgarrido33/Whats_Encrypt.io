// src/crypto-service.js

import nacl from 'tweetnacl';
import {
  decodeBase64,
  encodeBase64,
  encodeUTF8,
  decodeUTF8,
} from 'tweetnacl-util';
import axios from './axios';

// La clave para guardar nuestra clave privada en el almacenamiento local
const PRIVATE_KEY_STORAGE_KEY = 'whatsapp-clone-private-key';

class CryptoService {
  constructor() {
    // Un objeto para guardar en memoria los secretos compartidos de cada conversación
    this.sharedSecrets = {};
  }

  /**
   * Revisa si ya existe una clave privada. Si no, genera un nuevo par,
   * guarda la clave privada localmente y sube la pública al servidor.
   */
  async generateAndRegisterKeys(authToken) {
    if (this.getPrivateKey()) {
      console.log('[CryptoService] La clave privada ya existe. No se generará una nueva.');
      return;
    }

    console.log('[CryptoService] No se encontró clave privada. Generando un nuevo par de claves...');

    const keyPair = nacl.box.keyPair();
    const privateKey = keyPair.secretKey;
    const publicKey = keyPair.publicKey;

    localStorage.setItem(PRIVATE_KEY_STORAGE_KEY, encodeBase64(privateKey));
    console.log('[CryptoService] Clave privada guardada en localStorage.');

    try {
      console.log('[CryptoService] Subiendo la clave pública al servidor...');
      await axios.post('/api/v1/keys/upload', {
        publicKey: encodeBase64(publicKey)
      }, {
        headers: {
          Authorization: `Bearer ${authToken}`,
        },
      });
      console.log('[CryptoService] Clave pública registrada exitosamente.');
    } catch (error) {
      console.error('Error al subir la clave pública:', error);
    }
  }

  /**
   * Obtiene la clave privada del almacenamiento local.
   * @returns {Uint8Array | null}
   */
  getPrivateKey() {
    const privateKeyB64 = localStorage.getItem(PRIVATE_KEY_STORAGE_KEY);
    if (!privateKeyB64) {
      return null;
    }
    return decodeBase64(privateKeyB64);
  }

  /**
   * Obtiene la clave pública de un usuario desde nuestro backend.
   * @returns {Promise<Uint8Array | null>}
   */
  async getPublicKeyForUser(userId, authToken) {
    try {
      console.log(`[CryptoService] Obteniendo clave pública para el usuario ${userId}`);
      const response = await axios.get(`/api/v1/keys/${userId}`, {
        headers: { Authorization: `Bearer ${authToken}` }
      });
      return decodeBase64(response.data.publicKey);
    } catch (error) {
      console.error(`Error obteniendo la clave pública para ${userId}:`, error);
      return null;
    }
  }

  /**
   * Calcula el secreto compartido con otro usuario y lo guarda en memoria.
   */
  computeAndStoreSharedSecret(otherUserId, theirPublicKey) {
    const myPrivateKey = this.getPrivateKey();
    if (!myPrivateKey || !theirPublicKey) {
      console.error('Falta la clave privada o la pública para calcular el secreto.');
      return;
    }
    const sharedSecret = nacl.box.before(theirPublicKey, myPrivateKey);
    this.sharedSecrets[otherUserId] = sharedSecret;
    console.log(`[CryptoService] Secreto compartido calculado y guardado para la conversación con ${otherUserId}.`);
  }

  // --- NUEVAS FUNCIONES ---

  /**
   * Cifra un mensaje para un destinatario específico.
   * @param {string} otherUserId - El ID del destinatario.
   * @param {string} message - El mensaje de texto plano a cifrar.
   * @returns {{ciphertext: string, nonce: string} | null} - El objeto con el texto cifrado y el nonce (en Base64), o null si falla.
   */
  encrypt(otherUserId, message) {
    const sharedSecret = this.sharedSecrets[otherUserId];
    if (!sharedSecret) {
      console.error(`No se encontró un secreto compartido para ${otherUserId}. No se puede cifrar.`);
      return null;
    }

    // Un 'nonce' es un número único que se debe usar para cada mensaje cifrado con la misma clave.
    // ¡NUNCA REUTILICES UN NONCE CON LA MISMA CLAVE!
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const messageUint8 = decodeUTF8(message); // Convertimos el mensaje de string a bytes

    const ciphertext = nacl.secretbox(messageUint8, nonce, sharedSecret);

    // Devolvemos el texto cifrado y el nonce, ambos en Base64 para poder enviarlos como JSON.
    return {
      ciphertext: encodeBase64(ciphertext),
      nonce: encodeBase64(nonce),
    };
  }

  /**
   * Descifra un mensaje de un remitente específico.
   * @param {string} senderId - El ID del remitente.
   * @param {{ciphertext: string, nonce: string}} payload - El objeto que contiene el texto cifrado y el nonce.
   * @returns {string | null} - El mensaje original en texto plano, o null si la verificación falla (mensaje corrupto o clave incorrecta).
   */
  decrypt(senderId, payload) {
    const sharedSecret = this.sharedSecrets[senderId];
    if (!sharedSecret) {
      console.error(`No se encontró un secreto compartido para ${senderId}. No se puede descifrar.`);
      return `(Mensaje cifrado no se pudo descifrar)`;
    }

    const ciphertext = decodeBase64(payload.ciphertext);
    const nonce = decodeBase64(payload.nonce);

    // 'secretbox.open' solo funciona si la clave, el nonce y la firma (interna) son correctos.
    // Si el mensaje fue alterado o la clave es incorrecta, devolverá 'null'.
    const decryptedMessage = nacl.secretbox.open(ciphertext, nonce, sharedSecret);

    if (decryptedMessage === null) {
      console.error('¡FALLO LA VERIFICACIÓN DEL MENSAJE! El mensaje podría estar corrupto o alterado.');
      return '(Fallo al descifrar el mensaje)';
    }

    // Devolvemos el mensaje descifrado convertido de bytes a un string.
    return encodeUTF8(decryptedMessage);
  }
}

const cryptoService = new CryptoService();
export default cryptoService;