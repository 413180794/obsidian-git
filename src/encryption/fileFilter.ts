/**
 * Glob pattern matching for determining which files should be encrypted.
 * Supports simple globs: *, **, ?, and ! for negation.
 */

// Files that should never be encrypted
const NEVER_ENCRYPT = [
    ".git",
    ".gitattributes",
    ".gitignore",
    ".gitmodules",
    ".obsidian/plugins",
    ".obsidian/workspace.json",
    ".obsidian/app.json",
];

/**
 * Convert a simple glob pattern to a RegExp.
 * Supports: *, **, ?
 */
function globToRegex(pattern: string): RegExp {
    let regex = "^";
    let i = 0;
    while (i < pattern.length) {
        const c = pattern[i];
        if (c === "*") {
            if (pattern[i + 1] === "*") {
                if (pattern[i + 2] === "/") {
                    regex += "(?:.+/)?";
                    i += 3;
                } else {
                    regex += ".*";
                    i += 2;
                }
            } else {
                regex += "[^/]*";
                i++;
            }
        } else if (c === "?") {
            regex += "[^/]";
            i++;
        } else if (c === ".") {
            regex += "\\.";
            i++;
        } else {
            regex += c;
            i++;
        }
    }
    regex += "$";
    return new RegExp(regex);
}

/**
 * Check if a file path should be encrypted based on user-configured patterns.
 * @param filePath - relative file path (e.g., "daily/2026-03-12-secret.md")
 * @param patterns - newline-separated glob patterns. Lines starting with ! are negation.
 * @returns true if the file should be encrypted
 */
export function shouldEncrypt(filePath: string, patterns: string): boolean {
    // Normalize path
    const normalizedPath = filePath.replace(/\\/g, "/");

    // Never encrypt git internals and plugin config
    for (const prefix of NEVER_ENCRYPT) {
        if (
            normalizedPath === prefix ||
            normalizedPath.startsWith(prefix + "/")
        ) {
            return false;
        }
    }

    const lines = patterns
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l.length > 0 && !l.startsWith("#"));

    if (lines.length === 0) return false;

    let matched = false;

    for (const line of lines) {
        if (line.startsWith("!")) {
            // Negation pattern
            const negPattern = line.substring(1).trim();
            if (globToRegex(negPattern).test(normalizedPath)) {
                matched = false;
            }
        } else {
            if (globToRegex(line).test(normalizedPath)) {
                matched = true;
            }
        }
    }

    return matched;
}
