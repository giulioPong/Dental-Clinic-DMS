# Tauri + React + TypeScript

Dental Clinic DMS desktop application.

## Development

```powershell
npm install
npm run tauri dev
```

## Prerequisites on Windows

- Node.js and npm
- Rust MSVC toolchain (`rustup`) and Visual Studio C++ Build Tools
- WebView2 Runtime
- Strawberry Perl x64 on `PATH` to build SQLCipher with vendored OpenSSL

Run the Rust unit tests from `src-tauri`:

```powershell
cargo test
```

## Rust module structure

- `src-tauri/src/db/`: SQLite, migrations, and FTS5
- `src-tauri/src/crypto/`: key derivation and AES-256-GCM
- `src-tauri/src/storage/`: encrypted blobs, soft delete, and ZIP export
- `src-tauri/src/commands/`: Tauri IPC commands
- `src-tauri/src/audit/`: append-only operation log
