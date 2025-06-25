import axios from './axios';
import { saveData, getData } from './db-service';
import { arrayBufferToBase64, exportKeyToJwk } from './crypto-utils';

// --- Parámetros para la generación de claves usando Web Crypto API ---
const ECDH_PARAMS = { name: 'ECDH', namedCurve: 'P-256' };
const ECDSA_PARAMS = { name: 'ECDSA', namedCurve: 'P-256' };
const SIGN_ALGO = { name: 'ECDSA', hash: { name: 'SHA-256' } };

class CryptoService {

  /**
   * Genera el paquete completo de claves de Signal, las guarda localmente
   * y sube las claves públicas al servidor.
   * Se ejecuta solo una vez, la primera vez que un usuario inicia sesión.
   */
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