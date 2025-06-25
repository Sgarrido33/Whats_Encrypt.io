export function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

/**
 * Convierte una cadena Base64 a un ArrayBuffer.
 * @param {string} base64 La cadena en formato Base64.
 * @returns {ArrayBuffer} El buffer convertido.
 */
export function base64ToArrayBuffer(base64) {
  const binary_string = window.atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Exporta una CryptoKey (pública o privada) a formato JWK (JSON Web Key).
 * @param {CryptoKey} key La clave a exportar.
 * @returns {Promise<JsonWebKey>} El objeto de la clave en formato JWK.
 */
export async function exportKeyToJwk(key) {
    return window.crypto.subtle.exportKey('jwk', key);
}