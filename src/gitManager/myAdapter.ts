/* eslint-disable @typescript-eslint/require-await */
/* eslint-disable @typescript-eslint/only-throw-error */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-explicit-any */
import type { DataAdapter, Vault } from "obsidian";
import { normalizePath, TFile } from "obsidian";
import type ObsidianGit from "../main";
import { encryptForMeld, isMeldEncrypted } from "../encryption/crypto";
import { shouldEncrypt } from "../encryption/fileFilter";

export class MyAdapter {
    promises: any = {};
    adapter: DataAdapter;
    vault: Vault;
    index: ArrayBuffer | undefined;
    indexctime: number | undefined;
    indexmtime: number | undefined;
    lastBasePath: string | undefined;

    /**
     * When true, readFile is being called by a git staging operation.
     * Set by IsomorphicGit before git.add() and cleared after.
     */
    isGitOperation = false;

    constructor(
        vault: Vault,
        private readonly plugin: ObsidianGit
    ) {
        this.adapter = vault.adapter;
        this.vault = vault;
        this.lastBasePath = this.plugin.settings.basePath;

        this.promises.readFile = this.readFile.bind(this);
        this.promises.writeFile = this.writeFile.bind(this);
        this.promises.readdir = this.readdir.bind(this);
        this.promises.mkdir = this.mkdir.bind(this);
        this.promises.rmdir = this.rmdir.bind(this);
        this.promises.stat = this.stat.bind(this);
        this.promises.unlink = this.unlink.bind(this);
        this.promises.lstat = this.lstat.bind(this);
        this.promises.readlink = this.readlink.bind(this);
        this.promises.symlink = this.symlink.bind(this);
    }

    /**
     * Whether encryption is active: enabled + password set + patterns configured.
     */
    private get encryptionActive(): boolean {
        return (
            this.plugin.settings.encryptionEnabled &&
            !!this.plugin.localStorage.getEncryptionPassword() &&
            !!this.plugin.settings.encryptionPatterns.trim()
        );
    }

    /**
     * Get encryption password from localStorage.
     */
    private get encryptionPassword(): string {
        return this.plugin.localStorage.getEncryptionPassword() ?? "";
    }

    /**
     * Check if a file path should be encrypted.
     */
    private shouldEncryptPath(path: string): boolean {
        return shouldEncrypt(path, this.plugin.settings.encryptionPatterns);
    }

    /**
     * Encrypt matching files on disk before git staging.
     * Called by IsomorphicGit before git.add().
     * Replaces plaintext file content with Meld Encrypt format.
     * Returns list of files that were encrypted (for potential restore).
     */
    async encryptFilesOnDisk(
        filepaths: string[]
    ): Promise<{ path: string; originalContent: string }[]> {
        if (!this.encryptionActive) return [];

        const encrypted: { path: string; originalContent: string }[] = [];

        for (const filepath of filepaths) {
            if (!this.shouldEncryptPath(filepath)) continue;

            const file = this.vault.getAbstractFileByPath(filepath);
            if (!(file instanceof TFile)) continue;

            const content = await this.vault.read(file);

            // Skip if already encrypted
            if (isMeldEncrypted(content)) continue;

            // Skip empty files
            if (content.trim().length === 0) continue;

            const encryptedContent = await encryptForMeld(
                content,
                this.encryptionPassword
            );

            await this.vault.modify(file, encryptedContent);
            encrypted.push({ path: filepath, originalContent: content });
        }

        return encrypted;
    }

    /**
     * Restore files that were encrypted before staging.
     * Called if git.add() fails to revert the encryption.
     */
    async restoreFiles(
        files: { path: string; originalContent: string }[]
    ): Promise<void> {
        for (const { path, originalContent } of files) {
            const file = this.vault.getAbstractFileByPath(path);
            if (file instanceof TFile) {
                await this.vault.modify(file, originalContent);
            }
        }
    }

    async readFile(path: string, opts: any) {
        this.maybeLog("Read: " + path + JSON.stringify(opts));
        if (opts == "utf8" || opts.encoding == "utf8") {
            const file = this.vault.getAbstractFileByPath(path);
            if (file instanceof TFile) {
                this.maybeLog("Reuse");

                return this.vault.read(file);
            } else {
                return this.adapter.read(path);
            }
        } else {
            if (path.endsWith(this.gitDir + "/index")) {
                if (this.plugin.settings.basePath != this.lastBasePath) {
                    this.clearIndex();
                    this.lastBasePath = this.plugin.settings.basePath;
                    return this.adapter.readBinary(path);
                }
                return this.index ?? this.adapter.readBinary(path);
            }
            const file = this.vault.getAbstractFileByPath(path);
            if (file instanceof TFile) {
                this.maybeLog("Reuse");

                return this.vault.readBinary(file);
            } else {
                return this.adapter.readBinary(path);
            }
        }
    }
    async writeFile(path: string, data: string | ArrayBuffer) {
        this.maybeLog("Write: " + path);

        if (typeof data === "string") {
            const file = this.vault.getAbstractFileByPath(path);
            if (file instanceof TFile) {
                return this.vault.modify(file, data);
            } else {
                return this.adapter.write(path, data);
            }
        } else {
            if (path.endsWith(this.gitDir + "/index")) {
                this.index = data;
                this.indexmtime = Date.now();
                // this.adapter.writeBinary(path, data);
            } else {
                const file = this.vault.getAbstractFileByPath(path);
                if (file instanceof TFile) {
                    return this.vault.modifyBinary(file, data);
                } else {
                    return this.adapter.writeBinary(path, data);
                }
            }
        }
    }
    async readdir(path: string) {
        if (path === ".") path = "/";
        const res = await this.adapter.list(path);
        const all = [...res.files, ...res.folders];
        let formattedAll;
        if (path !== "/") {
            formattedAll = all.map((e) =>
                normalizePath(e.substring(path.length))
            );
        } else {
            formattedAll = all;
        }
        return formattedAll;
    }
    async mkdir(path: string) {
        return this.adapter.mkdir(path);
    }
    async rmdir(path: string, opts: any) {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
        return this.adapter.rmdir(path, opts?.options?.recursive ?? false);
    }
    async stat(path: string) {
        if (path.endsWith(this.gitDir + "/index")) {
            if (
                this.index !== undefined &&
                this.indexctime != undefined &&
                this.indexmtime != undefined
            ) {
                return {
                    isFile: () => true,
                    isDirectory: () => false,
                    isSymbolicLink: () => false,
                    size: this.index.byteLength,
                    type: "file",
                    ctimeMs: this.indexctime,
                    mtimeMs: this.indexmtime,
                };
            } else {
                const stat = await this.adapter.stat(path);
                if (stat == undefined) {
                    throw { code: "ENOENT" };
                }
                this.indexctime = stat.ctime;
                this.indexmtime = stat.mtime;
                return {
                    ctimeMs: stat.ctime,
                    mtimeMs: stat.mtime,
                    size: stat.size,
                    type: "file",
                    isFile: () => true,
                    isDirectory: () => false,
                    isSymbolicLink: () => false,
                };
            }
        }
        if (path === ".") path = "/";
        const file = this.vault.getAbstractFileByPath(path);
        this.maybeLog("Stat: " + path);
        if (file instanceof TFile) {
            this.maybeLog("Reuse stat");
            return {
                ctimeMs: file.stat.ctime,
                mtimeMs: file.stat.mtime,
                size: file.stat.size,
                type: "file",
                isFile: () => true,
                isDirectory: () => false,
                isSymbolicLink: () => false,
            };
        } else {
            const stat = await this.adapter.stat(path);
            if (stat) {
                return {
                    ctimeMs: stat.ctime,
                    mtimeMs: stat.mtime,
                    size: stat.size,
                    type: stat.type === "folder" ? "directory" : stat.type,
                    isFile: () => stat.type === "file",
                    isDirectory: () => stat.type === "folder",
                    isSymbolicLink: () => false,
                };
            } else {
                // used to determine whether a file exists or not
                throw { code: "ENOENT" };
            }
        }
    }
    async unlink(path: string) {
        return this.adapter.remove(path);
    }
    async lstat(path: string) {
        return this.stat(path);
    }
    async readlink(path: string) {
        throw new Error(`readlink of (${path}) is not implemented.`);
    }
    async symlink(path: string) {
        throw new Error(`symlink of (${path}) is not implemented.`);
    }

    async saveAndClear(): Promise<void> {
        if (this.index !== undefined) {
            await this.adapter.writeBinary(
                this.plugin.gitManager.getRelativeVaultPath(
                    this.gitDir + "/index"
                ),
                this.index,
                {
                    ctime: this.indexctime,
                    mtime: this.indexmtime,
                }
            );
        }
        this.clearIndex();
    }

    clearIndex() {
        this.index = undefined;
        this.indexctime = undefined;
        this.indexmtime = undefined;
    }

    private get gitDir(): string {
        return this.plugin.settings.gitDir || ".git";
    }

    private maybeLog(_: string) {
        // console.log(text);
    }
}
