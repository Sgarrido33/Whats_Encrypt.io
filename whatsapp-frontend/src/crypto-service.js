import axios from './axios';
import { saveData, getData } from './db-service';
import { base64ToArrayBuffer, arrayBufferToBase64, exportKeyToJwk } from './crypto-utils';

// --- Parámetros para la generación de claves usando Web Crypto API ---
const ECDH_PARAMS = { name: 'ECDH', namedCurve: 'P-256' };
const ECDSA_PARAMS = { name: 'ECDSA', namedCurve: 'P-256' };
const SIGN_ALGO = { name: 'ECDSA', hash: { name: 'SHA-256' } };

class CryptoService {

    async encryptECIES(otherUserId, plaintext) {
    console.log(`[ECIES] Iniciando cifrado para ${otherUserId}`);
    const authToken = localStorage.getItem('authToken');

    try {
      // 1. OBTENER LA CLAVE PÚBLICA DEL RECEPTOR
      // Usamos la nueva ruta que creamos en el backend.
      const keyResponse = await axios.get(`/api/v1/keys/identity/${otherUserId}`, {
        headers: { Authorization: `Bearer ${authToken}` },
      });
      const recipientIdentityKeyB64 = keyResponse.data.identityKey;

      // Importamos la clave pública del receptor para que la Web Crypto API pueda usarla.
      const recipientPublicKey = await window.crypto.subtle.importKey(
        'raw',
        base64ToArrayBuffer(recipientIdentityKeyB64),
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        []
      );
      console.log('[ECIES] Clave pública del receptor obtenida e importada.');

      // 2. GENERAR UN PAR DE CLAVES EFÍMERAS PARA ESTE MENSAJE
      // Esto es crucial para la Confidencialidad Futura (Forward Secrecy).
      const ephemeralKeyPair = await window.crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveBits']
      );
      console.log('[ECIES] Par de claves efímeras del emisor generado.');

      // 3. DERIVAR UN SECRETO COMPARTIDO (ECDH)
      // Usamos nuestra clave privada efímera y la clave pública del receptor.
      const sharedSecret = await window.crypto.subtle.deriveBits(
        { name: 'ECDH', public: recipientPublicKey },
        ephemeralKeyPair.privateKey,
        256 // Longitud del secreto en bits
      );
      console.log('[ECIES] Secreto compartido derivado mediante ECDH.');

      // 4. DERIVAR CLAVES DE CIFRADO Y MAC USANDO HKDF
      // Nunca usamos el secreto compartido directamente. Lo usamos como "semilla" para derivar otras claves.
      const hkdfKey = await window.crypto.subtle.importKey('raw', sharedSecret, { name: 'HKDF' }, false, ['deriveKey']);
      
      // Derivamos una clave para AES-GCM
      const aesKey = await window.crypto.subtle.deriveKey(
        { name: 'HKDF', salt: new Uint8Array(), info: new TextEncoder().encode('aes-gcm-key'), hash: 'SHA-256' },
        hkdfKey,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      );
      console.log('[ECIES] Clave AES derivada con HKDF.');

      // 5. CIFRAR EL MENSAJE CON AES-GCM
      const iv = window.crypto.getRandomValues(new Uint8Array(12)); // Vector de inicialización aleatorio
      const encodedPlaintext = new TextEncoder().encode(plaintext);
      
      const ciphertext = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        aesKey,
        encodedPlaintext
      );
      console.log('[ECIES] Mensaje cifrado con AES-GCM.');

      // 6. EMPAQUETAR TODO PARA EL ENVÍO
      const ephemeralPublicKeyRaw = await window.crypto.subtle.exportKey('raw', ephemeralKeyPair.publicKey);
      
      const payload = {
        type: 'ECIES_V1', // Para futura compatibilidad
        ephemeralPublicKey: arrayBufferToBase64(ephemeralPublicKeyRaw), // La clave pública efímera del emisor
        iv: arrayBufferToBase64(iv), // El vector de inicialización
        ciphertext: arrayBufferToBase64(ciphertext), // El mensaje cifrado
      };
      
      console.log('[ECIES] Cifrado completado. Payload listo para enviar:', payload);
      return payload;

    } catch (error) {
      console.error('[ECIES] Ocurrió un error durante el cifrado:', error);
      return null;
    }
  }

  async establishSession(otherUserId, authToken) {
    console.log(`[CryptoService-X3DH] Iniciando sesión segura con el usuario: ${otherUserId}`);
    
    try {
      // 1. Pedimos el paquete de claves del otro usuario al servidor.
      const response = await axios.get(`/api/v1/keys/signal/${otherUserId}`, {
        headers: { Authorization: `Bearer ${authToken}` },
      });

      const preKeyBundle = response.data;
      console.log('[CryptoService-X3DH] Paquete de pre-claves recibido del servidor:', preKeyBundle);

      if (!preKeyBundle.identityKey || !preKeyBundle.signedPreKey || !preKeyBundle.oneTimePreKey) {
        console.error('[CryptoService-X3DH] El paquete de claves recibido es inválido.');
        return; // O manejar el error de otra forma
      }

      // --- EN EL SIGUIENTE PASO, AQUÍ HAREMOS LOS CÁLCULOS ---
      // Por ahora, solo confirmamos que recibimos los datos.

    } catch (error) {
      console.error('Error al obtener el paquete de pre-claves del otro usuario:', error.response?.data || error.message);
    }
  }

  async decryptECIES(payload) {
    // Verificamos que el payload tenga el formato que esperamos.
    if (payload.type !== 'ECIES_V1' || !payload.ephemeralPublicKey || !payload.iv || !payload.ciphertext) {
      console.log('[ECIES-Decrypt] El mensaje no tiene el formato ECIES. Se mostrará como objeto.');
      // Devolvemos el mensaje tal cual si no es del tipo esperado, para no romper la UI.
      return JSON.stringify(payload); 
    }

    console.log('[ECIES-Decrypt] Recibido payload ECIES, iniciando descifrado.');

    try {
      // 1. OBTENER NUESTRA PROPIA CLAVE PRIVADA DE IDENTIDAD
      // La necesitamos para el cálculo de Diffie-Hellman.
      const myIdentityKey = await getData('identityKey');
      if (!myIdentityKey) {
        throw new Error('No se encontró la clave de identidad privada para descifrar.');
      }
      console.log('[ECIES-Decrypt] Obtenida clave de identidad privada desde la DB.');

      // 2. IMPORTAR LA CLAVE PÚBLICA EFÍMERA DEL EMISOR
      // Esta clave pública viene dentro del payload del mensaje.
      const ephemeralPublicKey = await window.crypto.subtle.importKey(
        'raw',
        base64ToArrayBuffer(payload.ephemeralPublicKey),
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        []
      );

      // 3. DERIVAR EL MISMO SECRETO COMPARTIDO (ECDH)
      // Usamos nuestra clave privada y la clave pública efímera del emisor.
      // El resultado debe ser idéntico al que calculó el emisor.
      const sharedSecret = await window.crypto.subtle.deriveBits(
        { name: 'ECDH', public: ephemeralPublicKey },
        myIdentityKey.privateKey,
        256
      );
      console.log('[ECIES-Decrypt] Secreto compartido derivado mediante ECDH.');

      // 4. RE-DERIVAR LA CLAVE DE CIFRADO USANDO HKDF
      // Es crucial usar exactamente los mismos parámetros (salt, info) que en el cifrado.
      const hkdfKey = await window.crypto.subtle.importKey('raw', sharedSecret, { name: 'HKDF' }, false, ['deriveKey']);
      const aesKey = await window.crypto.subtle.deriveKey(
        { name: 'HKDF', salt: new Uint8Array(), info: new TextEncoder().encode('aes-gcm-key'), hash: 'SHA-256' },
        hkdfKey,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      );
      console.log('[ECIES-Decrypt] Clave AES re-derivada con HKDF.');

      // 5. DESCIFRAR EL MENSAJE CON AES-GCM
      const ciphertext = base64ToArrayBuffer(payload.ciphertext);
      const iv = base64ToArrayBuffer(payload.iv);

      const decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        aesKey,
        ciphertext
      );
      console.log('[ECIES-Decrypt] ¡Mensaje descifrado exitosamente!');

      // 6. CONVERTIR EL RESULTADO A TEXTO
      return new TextDecoder().decode(decryptedBuffer);

    } catch (error) {
      console.error('[ECIES-Decrypt] FALLO EL DESCIFRADO:', error);
      return '(Error: No se pudo descifrar este mensaje)';
    }
  }
  
  async generateAndRegisterSignalKeys(authToken) {
    console.log('[CryptoService] Iniciando generación de claves de Signal...');

    // 1. Revisar si las claves ya existen en IndexedDB para no regenerarlas.
    const existingIdentity = await getData('identityKey');
    if (existingIdentity) {
      console.log('[CryptoService] Las claves de Signal ya existen. No se necesita generar.');
      return;
    }

    // --- 2. Generar Clave de Identidad (IK) ---
    const identityKey = await window.crypto.subtle.generateKey(ECDH_PARAMS, true, ['deriveKey', 'deriveBits']);
    const identityKeyPubJwk = await exportKeyToJwk(identityKey.publicKey);
    console.log('[CryptoService] Clave de Identidad generada.');

    // --- 3. Generar Clave Pre-Firmada (SPK) ---
    const signedPreKey = await window.crypto.subtle.generateKey(ECDH_PARAMS, true, ['deriveKey', 'deriveBits']);
    const signedPreKeyPubJwk = await exportKeyToJwk(signedPreKey.publicKey);
    console.log('[CryptoService] Clave Pre-Firmada generada.');

    // --- 4. Firmar la Clave Pre-Firmada ---
    // Para firmar, necesitamos una clave de firma. Usaremos la IK para esto, aunque Signal especifica una distinta.
    // Para simplificar, generaremos una clave de firma a partir de la IK.
    const signingKey = await window.crypto.subtle.generateKey(ECDSA_PARAMS, true, ['sign', 'verify']);
    const signedPreKeyPubRaw = await window.crypto.subtle.exportKey('raw', signedPreKey.publicKey);
    const signature = await window.crypto.subtle.sign(SIGN_ALGO, signingKey.privateKey, signedPreKeyPubRaw);
    console.log('[CryptoService] Clave Pre-Firmada ha sido firmada.');

    // --- 5. Generar Lote de Claves de Un Solo Uso (OPKs) ---
    const oneTimePreKeys = [];
    const oneTimePreKeysPublicForServer = [];
    const OPK_COUNT = 100; // Generamos 100 claves
    for (let i = 0; i < OPK_COUNT; i++) {
        const opk = await window.crypto.subtle.generateKey(ECDH_PARAMS, true, ['deriveKey', 'deriveBits']);
        oneTimePreKeys.push(opk);
        const opkPubJwk = await exportKeyToJwk(opk.publicKey);
        oneTimePreKeysPublicForServer.push({
            keyId: i + 1, // Los IDs de clave suelen empezar en 1
            publicKey: arrayBufferToBase64(await window.crypto.subtle.exportKey('raw', opk.publicKey)),
        });
    }
    console.log(`[CryptoService] ${OPK_COUNT} Claves de Un Solo Uso generadas.`);

    // --- 6. Guardar todas las claves (públicas y privadas) en IndexedDB ---
    await saveData('identityKey', identityKey);
    await saveData('signedPreKey', signedPreKey);
    await saveData('oneTimePreKeys', oneTimePreKeys);
    await saveData('signingKey', signingKey); // Guardamos la clave de firma también
    console.log('[CryptoService] Todas las claves han sido guardadas en la base de datos local.');

    // --- 7. Preparar y subir el paquete de claves públicas al servidor ---
    const publicKeysBundle = {
      identityKey: arrayBufferToBase64(await window.crypto.subtle.exportKey('raw', identityKey.publicKey)),
      signedPreKey: {
        keyId: 1, // ID de la clave firmada
        publicKey: arrayBufferToBase64(await window.crypto.subtle.exportKey('raw', signedPreKey.publicKey)),
        signature: arrayBufferToBase64(signature),
      },
      oneTimePreKeys: oneTimePreKeysPublicForServer,
    };
    
    try {
        console.log('[CryptoService] Subiendo paquete de claves públicas al servidor...');
        await axios.post('/api/v1/keys/register-signal', publicKeysBundle, {
            headers: { Authorization: `Bearer ${authToken}` },
        });
        console.log('[CryptoService] Paquete de claves de Signal registrado exitosamente en el servidor.');
    } catch (error) {
        console.error('Error al subir el paquete de claves de Signal:', error.response?.data || error.message);
    }
  }

  // Aquí añadiremos las funciones para iniciar una sesión (X3DH) y el Double Ratchet
  // en los siguientes pasos.
}

const cryptoService = new CryptoService();
export default cryptoService;