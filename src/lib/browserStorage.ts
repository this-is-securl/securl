interface StorageEnvelope<T> {
  version: number;
  data: T;
}

const DB_NAME = "external-posture-insight";
const STORE_NAME = "kv";

const hasIndexedDb = () =>
  typeof window !== "undefined" && typeof window.indexedDB !== "undefined";

const openDatabase = (): Promise<IDBDatabase> =>
  new Promise((resolve, reject) => {
    const request = window.indexedDB.open(DB_NAME, 1);

    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(STORE_NAME)) {
        database.createObjectStore(STORE_NAME);
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Could not open browser storage."));
  });

const readLegacyLocalStorage = <T,>(key: string, fallback: T, version: number): T => {
  if (typeof window === "undefined") {
    return fallback;
  }

  try {
    const raw = window.localStorage.getItem(key);
    if (!raw) {
      return fallback;
    }

    const parsed: unknown = JSON.parse(raw);
    if (
      parsed !== null &&
      parsed !== undefined &&
      typeof parsed === "object" &&
      "version" in parsed &&
      "data" in parsed &&
      typeof (parsed as Record<string, unknown>).version === "number"
    ) {
      const envelope = parsed as StorageEnvelope<T>;
      return envelope.version === version ? envelope.data : fallback;
    }

    if (parsed === null || parsed === undefined) {
      return fallback;
    }
    return parsed as T;
  } catch {
    return fallback;
  }
};

const writeLegacyLocalStorage = <T,>(key: string, value: T, version: number) => {
  if (typeof window === "undefined") {
    return;
  }

  try {
    window.localStorage.setItem(
      key,
      JSON.stringify({
        version,
        data: value,
      } satisfies StorageEnvelope<T>),
    );
  } catch {
    // Ignore localStorage fallback failures.
  }
};

export const readBrowserStorage = async <T,>(key: string, fallback: T, version: number): Promise<T> => {
  if (typeof window === "undefined") {
    return fallback;
  }

  if (!hasIndexedDb()) {
    return readLegacyLocalStorage(key, fallback, version);
  }

  try {
    const database = await openDatabase();
    const value = await new Promise<StorageEnvelope<T> | undefined>((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, "readonly");
      const store = transaction.objectStore(STORE_NAME);
      const request = store.get(key);

      request.onsuccess = () => resolve(request.result as StorageEnvelope<T> | undefined);
      request.onerror = () => reject(request.error ?? new Error(`Could not read ${key} from browser storage.`));
    });

    if (value && value.version === version) {
      return value.data;
    }

    const legacyValue = readLegacyLocalStorage(key, fallback, version);
    if (legacyValue !== fallback) {
      await writeBrowserStorage(key, legacyValue, version);
      try {
        window.localStorage.removeItem(key);
      } catch {
        // Ignore cleanup failure.
      }
      return legacyValue;
    }

    return fallback;
  } catch {
    return readLegacyLocalStorage(key, fallback, version);
  }
};

export const writeBrowserStorage = async <T,>(key: string, value: T, version: number): Promise<void> => {
  if (typeof window === "undefined") {
    return;
  }

  if (!hasIndexedDb()) {
    writeLegacyLocalStorage(key, value, version);
    return;
  }

  try {
    const database = await openDatabase();
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, "readwrite");
      const store = transaction.objectStore(STORE_NAME);
      store.put(
        {
          version,
          data: value,
        } satisfies StorageEnvelope<T>,
        key,
      );

      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error ?? new Error(`Could not write ${key} to browser storage.`));
      transaction.onabort = () => reject(transaction.error ?? new Error(`Could not write ${key} to browser storage.`));
    });

    try {
      window.localStorage.removeItem(key);
    } catch {
      // Ignore cleanup failure.
    }
  } catch {
    writeLegacyLocalStorage(key, value, version);
  }
};
