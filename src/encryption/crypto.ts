/**
 * Core encryption/decryption module for obsidian-git.
 *
 * Scheme: AES-256-GCM with PBKDF2 key derivation.
 * File format:
 *   - 10 bytes: magic header "OBSGITENC\x00"
 *   - 1 byte:   version (0x01)
 *   - 16 bytes: PBKDF2 salt
 *   - 12 bytes: AES-GCM IV/nonce
 *   - rest:     ciphertext (includes 16-byte GCM auth tag)
 *
 * Uses Web Crypto API (available in Electron + mobile WebView).
 */

const MAGIC_HEADER = new Uint8Array([
    0x4f, 0x42, 0x53, 0x47, 0x49, 0x54, 0x45, 0x4e, 0x43, 0x00,
]); // "OBSGITENC\0"
const VERSION = 0x01;
const HEADER_LEN = 10; // magic
const VERSION_LEN = 1;
const SALT_LEN = 16;
const IV_LEN = 12;
const META_LEN = HEADER_LEN + VERSION_LEN + SALT_LEN + IV_LEN; // 39 bytes
const PBKDF2_ITERATIONS = 100_000;

/**
 * Check if data starts with the encryption magic header.
 */
export function isEncrypted(data: ArrayBuffer | Uint8Array): boolean {
    const view = new Uint8Array(
        data instanceof ArrayBuffer ? data : data.buffer,
        data instanceof ArrayBuffer ? 0 : data.byteOffset,
        Math.min(data.byteLength, HEADER_LEN + VERSION_LEN)
    );
    if (view.byteLength < HEADER_LEN + VERSION_LEN) return false;
    for (let i = 0; i < HEADER_LEN; i++) {
        if (view[i] !== MAGIC_HEADER[i]) return false;
    }
    return view[HEADER_LEN] === VERSION;
}

/**
 * Check if a string might be encrypted (starts with the magic bytes).
 */
export function isEncryptedString(data: string): boolean {
    return data.startsWith("OBSGITENC\x00");
}

async function deriveKey(
    password: string,
    salt: Uint8Array
): Promise<CryptoKey> {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations: PBKDF2_ITERATIONS,
            hash: "SHA-256",
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

/**
 * Encrypt plaintext bytes. Returns ArrayBuffer with header + salt + IV + ciphertext.
 */
export async function encrypt(
    plaintext: ArrayBuffer,
    password: string
): Promise<ArrayBuffer> {
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
    const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
    const key = await deriveKey(password, salt);

    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        plaintext
    );

    // Assemble: header + version + salt + iv + ciphertext
    const result = new Uint8Array(META_LEN + ciphertext.byteLength);
    result.set(MAGIC_HEADER, 0);
    result[HEADER_LEN] = VERSION;
    result.set(salt, HEADER_LEN + VERSION_LEN);
    result.set(iv, HEADER_LEN + VERSION_LEN + SALT_LEN);
    result.set(new Uint8Array(ciphertext), META_LEN);

    return result.buffer;
}

/**
 * Decrypt an encrypted ArrayBuffer. Returns plaintext ArrayBuffer.
 * Throws on wrong password or corrupted data.
 */
export async function decrypt(
    encrypted: ArrayBuffer,
    password: string
): Promise<ArrayBuffer> {
    const data = new Uint8Array(encrypted);
    if (data.byteLength < META_LEN + 16) {
        // minimum: header + at least GCM tag
        throw new Error("Encrypted data too short");
    }

    // Verify header
    if (!isEncrypted(data)) {
        throw new Error("Not an encrypted file (invalid header)");
    }

    const salt = data.slice(
        HEADER_LEN + VERSION_LEN,
        HEADER_LEN + VERSION_LEN + SALT_LEN
    );
    const iv = data.slice(
        HEADER_LEN + VERSION_LEN + SALT_LEN,
        META_LEN
    );
    const ciphertext = data.slice(META_LEN);

    const key = await deriveKey(password, salt);

    return crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        ciphertext
    );
}

/**
 * Encrypt a UTF-8 string. Returns encrypted ArrayBuffer.
 */
export async function encryptString(
    plaintext: string,
    password: string
): Promise<ArrayBuffer> {
    const enc = new TextEncoder();
    return encrypt(enc.encode(plaintext).buffer, password);
}

/**
 * Decrypt to a UTF-8 string. Throws on failure.
 */
export async function decryptToString(
    encrypted: ArrayBuffer,
    password: string
): Promise<string> {
    const plainBuffer = await decrypt(encrypted, password);
    const dec = new TextDecoder();
    return dec.decode(plainBuffer);
}
