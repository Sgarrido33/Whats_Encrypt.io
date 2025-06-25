const DB_NAME = 'whatsapp-clone-signal-db';
const DB_VERSION = 1;
const STORE_NAME = 'signal_protocol_store';

// La clave de la solución: almacenamos la promesa de la conexión, no solo la conexión.
let dbPromise = null;

function getDbPromise() {
  if (!dbPromise) {
    console.log('[DB Service] No hay promesa de DB. Creando una nueva...');
    dbPromise = new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);

      request.onerror = (event) => {
        console.error('[DB Service] Error al abrir la base de datos:', event.target.error);
        // Si hay un error, reseteamos la promesa para poder intentarlo de nuevo.
        dbPromise = null;
        reject('Error al abrir la base de datos.');
      };

      request.onsuccess = (event) => {
        console.log('[DB Service] Base de datos abierta exitosamente.');
        resolve(event.target.result);
      };

      request.onupgradeneeded = (event) => {
        console.log('[DB Service] Actualizando schema de la base de datos...');
        const database = event.target.result;
        if (!database.objectStoreNames.contains(STORE_NAME)) {
          database.createObjectStore(STORE_NAME, { keyPath: 'key' });
        }
      };
    });
  }
  return dbPromise;
}

/**
 * Guarda un valor en el almacén de Signal.
 * @param {string} key - La clave bajo la cual se guardará el valor.
 * @param {any} value - El valor a guardar.
 */
export async function saveData(key, value) {
  const db = await getDbPromise();
  const transaction = db.transaction([STORE_NAME], 'readwrite');
  const store = transaction.objectStore(STORE_NAME);
  store.put({ key, value });

  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => {
      console.log(`[DB Service] Dato guardado exitosamente con la clave: ${key}`);
      resolve();
    };
    transaction.onerror = (event) => {
      console.error(`[DB Service] Error al guardar dato para la clave ${key}:`, event.target.error);
      reject(event.target.error);
    };
  });
}

/**
 * Obtiene un valor del almacén de Signal.
 * @param {string} key - La clave del valor a obtener.
 * @returns {Promise<any | null>} El valor encontrado o null.
 */
export async function getData(key) {
  const db = await getDbPromise();
  const transaction = db.transaction([STORE_NAME], 'readonly');
  const store = transaction.objectStore(STORE_NAME);
  const request = store.get(key);
  
  return new Promise((resolve, reject) => {
      request.onsuccess = (event) => {
        resolve(event.target.result ? event.target.result.value : null);
      };
      request.onerror = (event) => {
        console.error(`[DB Service] Error al obtener dato para la clave ${key}:`, event.target.error);
        reject(event.target.error);
      };
  });
}

/**
 * Limpia todos los datos del almacén.
 */
export async function clearAllData() {
  const db = await getDbPromise();
  const transaction = db.transaction([STORE_NAME], 'readwrite');
  const store = transaction.objectStore(STORE_NAME);
  store.clear();

  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => {
      console.log('[DB Service] Almacén de Signal limpiado exitosamente.');
      resolve();
    };
    transaction.onerror = (event) => {
      console.error('[DB Service] Error al limpiar el almacén:', event.target.error);
      reject(event.target.error);
    };
  });
}
