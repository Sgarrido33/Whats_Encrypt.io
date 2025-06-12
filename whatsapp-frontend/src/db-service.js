const DB_NAME = 'whatsapp-clone-crypto-db';
const DB_VERSION = 1;
let db;


function initDB() {
  return new Promise((resolve, reject) => {
    // Si la base de datos ya está inicializada, no hacemos nada.
    if (db) {
      return resolve(db);
    }

    console.log('[DB Service] Inicializando IndexedDB...');
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = (event) => {
      console.error('[DB Service] Error al abrir la base de datos:', event.target.error);
      reject('Error al abrir la base de datos.');
    };

    request.onsuccess = (event) => {
      db = event.target.result;
      console.log('[DB Service] Base de datos abierta exitosamente.');
      resolve(db);
    };

    request.onupgradeneeded = (event) => {
      console.log('[DB Service] Actualizando schema de la base de datos...');
      const database = event.target.result;

      // Almacén para nuestro par de claves. Usaremos un 'keyPath' fijo.
      if (!database.objectStoreNames.contains('myKeys')) {
        database.createObjectStore('myKeys', { keyPath: 'id' });
      }

      // Almacén para los secretos compartidos. La clave será el ID del otro usuario.
      if (!database.objectStoreNames.contains('sharedSecrets')) {
        database.createObjectStore('sharedSecrets', { keyPath: 'otherUserId' });
      }
    };
  });
}

/**
 * Guarda el par de claves del usuario en la base de datos.
 * @param {CryptoKeyPair} keyPair - El par de claves a guardar.
 */
export async function saveMyKeyPair(keyPair) {
  const database = await initDB();
  return new Promise((resolve, reject) => {
    // Creamos una transacción de escritura en el almacén 'myKeys'.
    const transaction = database.transaction(['myKeys'], 'readwrite');
    const store = transaction.objectStore('myKeys');
    
    // Guardamos el objeto. Usamos un ID fijo porque solo habrá un par de claves.
    store.put({ id: 'my-key-pair', keyPair });

    transaction.oncomplete = () => {
      console.log('[DB Service] Par de claves guardado exitosamente.');
      resolve();
    };
    transaction.onerror = (event) => {
      console.error('[DB Service] Error al guardar el par de claves:', event.target.error);
      reject(event.target.error);
    };
  });
}

/**
 * Obtiene el par de claves del usuario desde la base de datos.
 * @returns {Promise<CryptoKeyPair | null>}
 */
export async function getMyKeyPair() {
  const database = await initDB();
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(['myKeys'], 'readonly');
    const store = transaction.objectStore('myKeys');
    const request = store.get('my-key-pair');

    request.onsuccess = (event) => {
      if (event.target.result) {
        resolve(event.target.result.keyPair);
      } else {
        resolve(null); // No se encontró ningún par de claves
      }
    };
    request.onerror = (event) => {
      console.error('[DB Service] Error al obtener el par de claves:', event.target.error);
      reject(event.target.error);
    };
  });
}


/**
 * Guarda un secreto compartido para una conversación específica.
 * @param {string} otherUserId 
 * @param {Uint8Array} secret 
 */
export async function saveSharedSecret(otherUserId, secret) {
  const database = await initDB();
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(['sharedSecrets'], 'readwrite');
    const store = transaction.objectStore('sharedSecrets');
    store.put({ otherUserId, secret });

    transaction.oncomplete = () => {
      console.log(`[DB Service] Secreto compartido para ${otherUserId} guardado.`);
      resolve();
    };
    transaction.onerror = (event) => reject(event.target.error);
  });
}

/**
 * Obtiene un secreto compartido para una conversación específica.
 * @param {string} otherUserId 
 * @returns {Promise<Uint8Array | null>}
 */
export async function getSharedSecret(otherUserId) {
  const database = await initDB();
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(['sharedSecrets'], 'readonly');
    const store = transaction.objectStore('sharedSecrets');
    const request = store.get(otherUserId);

    request.onsuccess = (event) => {
      if (event.target.result) {
        resolve(event.target.result.secret);
      } else {
        resolve(null);
      }
    };
    request.onerror = (event) => reject(event.target.error);
  });
}