import nacl from 'tweetnacl';
import {
  decodeBase64,
  encodeBase64,
  encodeUTF8,
  decodeUTF8,
} from 'tweetnacl-util';
import axios from './axios';
// --- NUEVO: Importamos las funciones de nuestra base de datos ---
import { getMyKeyPair, saveMyKeyPair, getSharedSecret, saveSharedSecret } from './db-service';

class CryptoService {


  async generateAndRegisterKeys(authToken) {
    const existingKeyPair = await getMyKeyPair();

    if (existingKeyPair) {
      console.log('[CryptoService] El par de claves ya existe en IndexedDB.');
      return;
    }

    console.log('[CryptoService] No se encontró par de claves. Generando uno nuevo...');

    const newKeyPair = nacl.box.keyPair();

    // ANTES: guardaba en localStorage
    // AHORA: guarda el par completo en IndexedDB
    await saveMyKeyPair(newKeyPair);
    console.log('[CryptoService] Par de claves guardado en IndexedDB.');

    try {
      console.log('[CryptoService] Subiendo la clave pública al servidor...');
      await axios.post('/api/v1/keys/upload', {
        publicKey: encodeBase64(newKeyPair.publicKey)
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
   * Obtiene la clave privada desde IndexedDB.
   */
  async getPrivateKey() {
    const keyPair = await getMyKeyPair();
    return keyPair ? keyPair.secretKey : null;
  }

  /**
   * Obtiene la clave pública de un usuario desde nuestro backend.
   */
  async getPublicKeyForUser(userId, authToken) {
    try {
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
   * Calcula el secreto compartido con otro usuario y lo guarda en IndexedDB.
   */
  async computeAndStoreSharedSecret(otherUserId, theirPublicKey) {
    const myPrivateKey = await this.getPrivateKey();
    if (!myPrivateKey || !theirPublicKey) {
      console.error('Falta la clave privada o la pública para calcular el secreto.');
      return null;
    }
    const sharedSecret = nacl.box.before(theirPublicKey, myPrivateKey);
    
    // ANTES: guardaba en un objeto en memoria
    // AHORA: guarda en IndexedDB para que persista
    await saveSharedSecret(otherUserId, sharedSecret);
    console.log(`[CryptoService] Secreto compartido calculado y guardado en IndexedDB para ${otherUserId}.`);
    return sharedSecret;
  }

  /**
   * Cifra un mensaje para un destinatario específico.
   */
  async encrypt(otherUserId, message) {
    // ANTES: leía de un objeto en memoria
    // AHORA: lee de IndexedDB
    let sharedSecret = await getSharedSecret(otherUserId);
    
    if (!sharedSecret) {
      console.error(`No se encontró un secreto compartido para ${otherUserId}. No se puede cifrar.`);
      // Podríamos intentar recalcularlo aquí como fallback, pero por ahora mostramos error.
      return null;
    }

    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const messageUint8 = decodeUTF8(message);
    const ciphertext = nacl.secretbox(messageUint8, nonce, sharedSecret);

    return {
      ciphertext: encodeBase64(ciphertext),
      nonce: encodeBase64(nonce),
    };
  }

  /**
   * Descifra un mensaje de un remitente específico.
   */
  async decrypt(otherUserId, payload) {
    const sharedSecret = await getSharedSecret(otherUserId);
    if (!sharedSecret) {
      console.error(`No se encontró un secreto compartido para ${otherUserId}. No se puede descifrar.`);
      return `(Error: No se encontró la clave de sesión para este mensaje)`;
    }

    const ciphertext = decodeBase64(payload.ciphertext);
    const nonce = decodeBase64(payload.nonce);
    const decryptedMessage = nacl.secretbox.open(ciphertext, nonce, sharedSecret);

    if (decryptedMessage === null) {
      return '(Fallo al descifrar el mensaje)';
    }

    return encodeUTF8(decryptedMessage);
  }
}

const cryptoService = new CryptoService();
export default cryptoService;