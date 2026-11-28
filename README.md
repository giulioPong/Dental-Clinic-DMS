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
- `src-tauri/src/db/audit.rs`: append-only, HMAC-chained operation log
- `src-tauri/src/backup.rs`: data folder layout, single-instance lock, `--backup-db`

## Nightly backup

The data folder is `%APPDATA%\com.p0ng.dental-clinic-dms`:

- `vault\`: `vault.meta`, encrypted documents (`*.enc`), audit checkpoint
- `gestionale.db`: SQLCipher database (encrypted, but in use while the app runs)
- `backup-staging\`: encrypted snapshot + its checkpoint, written by the app on lock and every 30 minutes

The scheduled task first stages a consistent copy of the database, then runs restic.
`--backup-db` needs no password or key: the database file is already encrypted. If the app
is closed it copies the database (holding the single-instance lock, so the app cannot start
meanwhile); if the app is open it copies the app's latest snapshot.

```powershell
$data = "$env:APPDATA\com.p0ng.dental-clinic-dms"
# the release build is a GUI-subsystem exe: PowerShell must wait for it explicitly
$p = Start-Process -Wait -PassThru -FilePath "C:\Program Files\dental-clinic-dms\dental-clinic-dms.exe" `
      -ArgumentList "--backup-db", "`"$data\backup-staging`""
if ($p.ExitCode -ne 0) { exit $p.ExitCode }  # reason in backup-staging\backup-db.log
restic backup "$data\backup-staging" "$data\vault" --exclude "$data\vault\tmp"
```

Exit codes: `0` ok, `1` backup not done (see `backup-db.log`), `2` wrong arguments.
Use `--data-dir <folder>` if the data folder is elsewhere.

Restore: put `vault\` back, then copy `backup-staging\gestionale.db` to `gestionale.db` and
`backup-staging\audit.checkpoint` to `vault\audit.checkpoint`. Always take the checkpoint from
the staging folder, not from `vault\`: it must match the snapshot.
