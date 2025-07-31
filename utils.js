import { toString as uint8ArrayToString } from 'uint8arrays/to-string';
import { fromString as uint8ArrayFromString } from 'uint8arrays/from-string';
import { webcrypto as crypto } from 'crypto';

export const generateId = () => {
  const bytes = new Uint8Array(16); // 128 bits of randomness
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
};





export function arrayBufferToBase64(buffer) {
    if (!buffer) return null;
    if (typeof buffer === 'string') return buffer; // Already base64
    
    // Handle various buffer-like objects
    let bytes;
    if (buffer instanceof Uint8Array) {
        bytes = buffer;
    } else if (buffer instanceof ArrayBuffer) {
        bytes = new Uint8Array(buffer);
    } else if (buffer.buffer instanceof ArrayBuffer) {
        // Handle typed arrays
        bytes = new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    } else if (buffer.data) {
        // Handle objects with data property
        bytes = new Uint8Array(buffer.data);
    } else {
        console.error('Unknown buffer type:', typeof buffer, buffer);
        return null;
    }
    
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

export const base64ToArrayBuffer = (base64) => {
    // Handle null/undefined
    if (!base64) return null;
    
    // If it's already an ArrayBuffer or Uint8Array, return as is
    if (base64 instanceof ArrayBuffer) return new Uint8Array(base64);
    if (base64 instanceof Uint8Array) return base64;
    
    // If it's an object with data property (from JSON serialization)
    if (typeof base64 === 'object' && base64.data) {
        return new Uint8Array(base64.data);
    }
    
    // Only process strings
    if (typeof base64 !== 'string') {
        console.error('Invalid input for base64 decoding:', typeof base64, base64);
        return null;
    }
    
    try {
        // Remove any whitespace
        const cleaned = base64.trim();
        
        // Validate base64 string
        const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
        if (!base64Regex.test(cleaned)) {
            console.error('Invalid base64 string format:', cleaned.substring(0, 50) + '...');
            return null;
        }
        
        const binary = atob(cleaned);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    } catch (e) {
        console.error('Failed to decode base64:', e.message, 'Input:', base64.substring(0, 50) + '...');
        return null;
    }
};
export function normalizePeerId(id) {
  if (!id) return null;

  if (typeof id === 'string') {
    return id;
  } else if (id instanceof Uint8Array) {
    return Array.from(id).map(b => b.toString(16).padStart(2, '0')).join('');
  } else if (id && id.constructor && id.constructor.name === 'Buffer') {
    const uint8 = new Uint8Array(id);
    return Array.from(uint8).map(b => b.toString(16).padStart(2, '0')).join('');
  } else if (id && (id.type === 'Buffer' || id.data)) {
    const uint8 = new Uint8Array(id.data || id);
    return Array.from(uint8).map(b => b.toString(16).padStart(2, '0')).join('');
  } else if (ArrayBuffer.isView(id)) {
    const uint8 = new Uint8Array(id.buffer, id.byteOffset, id.byteLength);
    return Array.from(uint8).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  console.error('Unknown peer ID type:', typeof id, id);
  return null;
}

export function hexToUint8Array (hex) {
  if (hex.length % 2) throw new Error('hex length must be even');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

export const JSONStringifyWithBigInt = (obj) => {
    function replacer(key, value) {
        // Handle BigInts by tagging them
        if (typeof value === 'bigint') {
            return { __type: 'BigInt', value: value.toString() }; 
        }
        // Handle Uint8Arrays by tagging them and encoding to Base64
        if (value instanceof Uint8Array) {
            return { __type: 'Uint8Array', value: uint8ArrayToString(value, 'base64') };
        }
        // Handle regular arrays that look like byte arrays (all elements are numbers 0-255)
        if (Array.isArray(value) && value.length > 0 && 
            value.every(v => typeof v === 'number' && v >= 0 && v <= 255)) {
            // Convert to Uint8Array first, then to base64
            const uint8 = new Uint8Array(value);
            return { __type: 'Uint8Array', value: uint8ArrayToString(uint8, 'base64') };
        }
        return value;
    }
    return JSON.stringify(obj, replacer);
};

export const JSONParseWithBigInt = (str) => {
    function reviver(key, value) {
        // Check for our tagged objects
        if (value && typeof value === 'object' && value.__type) {
            // Reconstruct BigInts
            if (value.__type === 'BigInt') {
                return BigInt(value.value); 
            }
            // CORRECTED: Reconstruct Uint8Arrays from Base64 using the library
            if (value.__type === 'Uint8Array') {
                return uint8ArrayFromString(value.value, 'base64');
            }
        }
        return value; 
    }
    return JSON.parse(str, reviver);
};

