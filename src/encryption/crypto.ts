/**
 * Meld Encrypt compatible encryption module.
 *
 * Uses the exact same crypto as Meld Encrypt plugin v2 (CryptoHelper2304_v2):
 *   - AES-256-GCM
 *   - PBKDF2 with SHA-512, 210,000 iterations
 *   - 16-byte random IV + 16-byte random salt
 *   - Encrypted bytes: [IV(16)][Salt(16)][Ciphertext+GCM_Tag]
 *   - Stored as base64 wrapped in Meld Encrypt markers
 *
 * Marker format: %%🔐β <base64_ciphertext> 🔐%%
 *
 * Files encrypted this way can be decrypted by Meld Encrypt plugin directly.
 */

const VECTOR_SIZE = 16; // IV size
const SALT_SIZE = 16;
const ITERATIONS = 210_000;

// Meld Encrypt v2 markers
const MELD_PREFIX = "%%\u{1F510}\u03B2 "; // %%🔐β
const MELD_SUFFIX = " \u{1F510}%%"; // 🔐%%
const MELD_HINT_MARKER = "\u{1F4A1}"; // 💡

/**
 * Check if text content is encrypted with Meld Encrypt markers.
 */
export function isMeldEncrypted(text: string): boolean {
    const trimmed = text.trim();
    return (
        (trimmed.startsWith("%%\u{1F510}") ||
            trimmed.startsWith("\u{1F510}")) &&
        (trimmed.endsWith("\u{1F510}%%") || trimmed.endsWith("\u{1F510}"))
    );
}

/**
 * Derive an AES-256-GCM key from password + salt using PBKDF2 (SHA-512).
 * Matches Meld Encrypt CryptoHelper2304_v2.
 */
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
            hash: "SHA-512",
            salt,
            iterations: ITERATIONS,
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

/**
 * Encrypt plaintext string to Meld Encrypt v2 format bytes.
 * Returns: [16-byte IV][16-byte Salt][Ciphertext+GCM_Tag]
 */
async function encryptToBytes(
    plaintext: string,
    password: string
): Promise<Uint8Array> {
    const salt = crypto.getRandomValues(new Uint8Array(SALT_SIZE));
    const iv = crypto.getRandomValues(new Uint8Array(VECTOR_SIZE));
    const key = await deriveKey(password, salt);
    const encoded = new TextEncoder().encode(plaintext);
    const ciphertext = new Uint8Array(
        await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded)
    );

    // Assemble: [IV][Salt][Ciphertext] — matches Meld Encrypt v2 layout
    const result = new Uint8Array(
        iv.byteLength + salt.byteLength + ciphertext.byteLength
    );
    result.set(iv, 0);
    result.set(salt, iv.byteLength);
    result.set(ciphertext, iv.byteLength + salt.byteLength);
    return result;
}

/**
 * Convert Uint8Array to string (for btoa).
 */
function bytesToString(bytes: Uint8Array): string {
    let str = "";
    for (let i = 0; i < bytes.length; i++) {
        str += String.fromCharCode(bytes[i]);
    }
    return str;
}

/**
 * Convert string to Uint8Array (from atob).
 */
function stringToBytes(str: string): Uint8Array {
    const bytes = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        bytes[i] = str.charCodeAt(i);
    }
    return bytes;
}

/**
 * Encrypt plaintext to a Meld Encrypt compatible string.
 * Output format: %%🔐β <base64_encrypted_data> 🔐%%
 */
export async function encryptForMeld(
    plaintext: string,
    password: string
): Promise<string> {
    const encrypted = await encryptToBytes(plaintext, password);
    const base64 = btoa(bytesToString(encrypted));
    return MELD_PREFIX + base64 + MELD_SUFFIX;
}

/**
 * Decrypt a Meld Encrypt formatted string.
 * Returns null if decryption fails (wrong password).
 */
export async function decryptFromMeld(
    encryptedText: string,
    password: string
): Promise<string | null> {
    try {
        const trimmed = encryptedText.trim();

        // Find and strip prefix
        let content = trimmed;
        const prefixes = [
            "%%\u{1F510}\u03B2 ",
            "\u{1F510}\u03B2 ",
            "%%\u{1F510}\u03B1 ",
            "\u{1F510}\u03B1 ",
            "%%\u{1F510} ",
            "\u{1F510} ",
        ];
        const suffixes = [" \u{1F510}%%", " \u{1F510}"];

        let foundPrefix = "";
        for (const p of prefixes) {
            if (content.startsWith(p)) {
                foundPrefix = p;
                content = content.substring(p.length);
                break;
            }
        }
        if (!foundPrefix) return null;

        for (const s of suffixes) {
            if (content.endsWith(s)) {
                content = content.substring(0, content.length - s.length);
                break;
            }
        }

        // Strip hint if present: 💡hint💡
        if (content.startsWith(MELD_HINT_MARKER)) {
            const hintEnd = content.indexOf(MELD_HINT_MARKER, 1);
            if (hintEnd > 0) {
                content = content.substring(hintEnd + MELD_HINT_MARKER.length);
            }
        }

        // Decode base64 to bytes
        const bytes = stringToBytes(atob(content));

        // Parse: [IV(16)][Salt(16)][Ciphertext]
        const iv = bytes.slice(0, VECTOR_SIZE);
        const salt = bytes.slice(VECTOR_SIZE, VECTOR_SIZE + SALT_SIZE);
        const ciphertext = bytes.slice(VECTOR_SIZE + SALT_SIZE);

        const key = await deriveKey(password, salt);
        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv },
            key,
            ciphertext
        );

        return new TextDecoder().decode(decrypted);
    } catch {
        return null;
    }
}
