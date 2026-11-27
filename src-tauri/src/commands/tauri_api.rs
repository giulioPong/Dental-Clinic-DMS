//! Involucri `#[tauri::command]` e avvio dell'app (Tauri v2). Nessuna logica: ogni comando
//! clona l'`Arc<AppCore>` e delega a `spawn_blocking`, così Argon2, disco e ZIP non
//! bloccano mai il thread principale e nessun `MutexGuard` attraversa un `.await`.
//!
//! In `lib.rs` del progetto Tauri:
//! ```ignore
//! mod commands; mod crypto; mod db; mod storage;
//! #[cfg_attr(mobile, tauri::mobile_entry_point)]
//! pub fn run() { commands::tauri_api::run() }
//! ```
//!
//! Eventi verso il frontend: `vault-locked` (mostra subito la Lock Screen),
//! `upload-progress` `{ done, total }` e `backup-error` `{ message }` (archivio bloccato,
//! ma checkpoint o snapshot non salvati: va mostrato un avviso), `maintenance-report`
//! (esito della manutenzione dopo lo sblocco: `failedFiles > 0` va segnalato) e
//! `maintenance-error` `{ message }`.
//!
//! Upload: il frontend NON legge i file in JavaScript. Ottiene i percorsi dal drag-and-drop
//! nativo (`getCurrentWebview().onDragDropEvent`) o da `open()` di `@tauri-apps/plugin-dialog`
//! e li passa qui; per l'export il percorso di destinazione arriva da `save()`. Le
//! capabilities concedono solo `dialog:allow-open` e `dialog:allow-save`. Rust apre i file
//! e li cifra in streaming. Limite di sicurezza: una WebView compromessa potrebbe passare
//! percorsi arbitrari, quindi il frontend non deve mai caricare contenuti remoti (CSP
//! restrittiva, nessuna navigazione esterna).
//!
//! Viewer: `open_document` risponde con byte grezzi (`tauri::ipc::Response`), non con un array
//! JSON. Lato React: `new Blob([buf], { type: mime })`, `URL.createObjectURL`, e
//! `URL.revokeObjectURL` alla chiusura dell'anteprima. Rust azzera il proprio buffer, ma le
//! copie nella WebView non sono controllabili da qui.

use super::*;
use crate::backup::{default_data_dir, InstanceLock, DB_FILE, STAGING_DIR, VAULT_DIR};
use std::sync::Arc;
use tauri::ipc::Response;
use tauri::{AppHandle, Emitter, Manager, RunEvent, State};

type Core<'a> = State<'a, Arc<AppCore>>;

const IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const WATCH_INTERVAL: Duration = Duration::from_secs(5);
const SNAPSHOT_EVERY_TICKS: u32 = 360; // 30 minuti
/// All'avvio: attesa massima del lock di istanza (il backup notturno lo tiene pochi istanti).
const INSTANCE_LOCK_WAIT: Duration = Duration::from_secs(30);
/// Alla chiusura: attesa massima delle operazioni pesanti prima dello snapshot finale.
const SHUTDOWN_WAIT: Duration = Duration::from_secs(30);

#[derive(Clone, Serialize)]
struct BackupErrorPayload {
    message: String,
}

fn emit_backup_error(app: &AppHandle, e: &CommandError) {
    let _ = app.emit("backup-error", BackupErrorPayload { message: e.message.clone() });
}

#[derive(Clone, Serialize)]
struct ProgressPayload {
    done: usize,
    total: usize,
}

async fn blocking<T, F>(f: F) -> Res<T>
where
    F: FnOnce() -> Res<T> + Send + 'static,
    T: Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|_| CommandError::new(ErrorCode::Internal, "Operazione interrotta."))?
}

/// Dopo ogni sblocco: quarantena orfani e purge del cestino, senza bloccare nessuno.
/// L'esito arriva al frontend come evento; un blocco nel frattempo non è un errore.
fn spawn_maintenance(app: AppHandle, core: Arc<AppCore>) {
    tauri::async_runtime::spawn_blocking(move || match core.maintenance() {
        Ok(report) => {
            let _ = app.emit("maintenance-report", report);
        }
        Err(e) if e.code == ErrorCode::Locked => {}
        Err(e) => {
            eprintln!("[dms] manutenzione: {}", e.message);
            let _ = app.emit("maintenance-error", BackupErrorPayload { message: e.message });
        }
    });
}

// ───────── ciclo di vita ─────────

#[tauri::command]
pub async fn status(core: Core<'_>) -> Res<Status> {
    let core = core.inner().clone();
    blocking(move || Ok(core.status())).await
}

#[tauri::command]
pub async fn setup_vault(core: Core<'_>, password: String) -> Res<UnlockInfo> {
    let core = core.inner().clone();
    blocking(move || core.setup_vault(&password)).await
}

#[tauri::command]
pub async fn unlock(app: AppHandle, core: Core<'_>, password: String) -> Res<UnlockInfo> {
    let core = core.inner().clone();
    let c2 = core.clone();
    let info = blocking(move || core.unlock(&password)).await?;
    spawn_maintenance(app, c2);
    Ok(info)
}

#[tauri::command]
pub async fn lock_vault(app: AppHandle, core: Core<'_>) -> Res<()> {
    let core = core.inner().clone();
    let r = blocking(move || core.lock()).await;
    // la sessione è chiusa anche se il salvataggio è fallito: la Lock Screen va mostrata
    let _ = app.emit("vault-locked", ());
    r.map(|_| ())
}

#[tauri::command]
pub async fn change_password(core: Core<'_>, old_password: String, new_password: String) -> Res<()> {
    let core = core.inner().clone();
    blocking(move || core.change_password(&old_password, &new_password)).await
}

// ───────── pazienti ─────────

#[tauri::command]
pub async fn search_patients(core: Core<'_>, query: String, limit: Option<u32>) -> Res<Vec<PatientHitDto>> {
    let core = core.inner().clone();
    blocking(move || core.search_patients(&query, limit.unwrap_or(20))).await
}

#[tauri::command]
pub async fn create_patient(
    core: Core<'_>,
    first_name: String,
    last_name: String,
    birth_date: String,
    fiscal_code: Option<String>,
) -> Res<String> {
    let core = core.inner().clone();
    blocking(move || core.create_patient(&first_name, &last_name, &birth_date, fiscal_code.as_deref())).await
}

#[tauri::command]
pub async fn update_patient(
    core: Core<'_>,
    id: String,
    first_name: String,
    last_name: String,
    birth_date: String,
    fiscal_code: Option<String>,
    notes: String,
) -> Res<()> {
    let core = core.inner().clone();
    blocking(move || core.update_patient(&id, &first_name, &last_name, &birth_date, fiscal_code.as_deref(), &notes)).await
}

#[tauri::command]
pub async fn get_patient(core: Core<'_>, id: String) -> Res<PatientDto> {
    let core = core.inner().clone();
    blocking(move || core.get_patient(&id)).await
}

#[tauri::command]
pub async fn delete_patient(core: Core<'_>, id: String) -> Res<()> {
    let core = core.inner().clone();
    blocking(move || core.delete_patient(&id)).await
}

#[tauri::command]
pub async fn restore_patient(core: Core<'_>, id: String) -> Res<()> {
    let core = core.inner().clone();
    blocking(move || core.restore_patient(&id)).await
}

// ───────── documenti ─────────

#[tauri::command]
pub async fn list_documents(core: Core<'_>, patient_id: String, tag: Option<String>) -> Res<Vec<DocumentDto>> {
    let core = core.inner().clone();
    blocking(move || core.list_documents(&patient_id, tag.as_deref())).await
}

#[tauri::command]
pub async fn delete_document(core: Core<'_>, id: String) -> Res<()> {
    let core = core.inner().clone();
    blocking(move || core.delete_document(&id)).await
}

#[tauri::command]
pub async fn restore_document(core: Core<'_>, id: String) -> Res<()> {
    let core = core.inner().clone();
    blocking(move || core.restore_document(&id)).await
}

#[tauri::command]
pub async fn reassign_document(core: Core<'_>, doc_id: String, new_patient_id: String) -> Res<()> {
    let core = core.inner().clone();
    blocking(move || core.reassign_document(&doc_id, &new_patient_id)).await
}

#[tauri::command]
pub async fn list_trash(core: Core<'_>) -> Res<TrashDto> {
    let core = core.inner().clone();
    blocking(move || core.list_trash()).await
}

#[tauri::command]
pub async fn upload_documents(
    app: AppHandle,
    core: Core<'_>,
    patient_id: String,
    paths: Vec<String>,
    category_tag: String,
) -> Res<UploadReport> {
    let core = core.inner().clone();
    blocking(move || {
        core.upload_documents(&patient_id, &paths, &category_tag, |done, total| {
            let _ = app.emit("upload-progress", ProgressPayload { done, total });
        })
    })
    .await
}

/// Risponde con i byte grezzi del documento. Nome, tipo e dimensione li ha già la lista documenti.
#[tauri::command]
pub async fn open_document(core: Core<'_>, id: String) -> Res<Response> {
    let core = core.inner().clone();
    blocking(move || {
        let (_meta, mut bytes) = core.open_document(&id)?;
        // si sposta il Vec nella risposta invece di copiarlo (fino a 50 MB): il buffer
        // dentro `Zeroizing` resta vuoto, e il Vec passato a Tauri non viene azzerato
        Ok(Response::new(std::mem::take(&mut *bytes)))
    })
    .await
}

#[tauri::command]
pub async fn export_patient_zip(core: Core<'_>, patient_id: String, dest_path: String) -> Res<ExportDto> {
    let core = core.inner().clone();
    blocking(move || core.export_patient_zip(&patient_id, Path::new(&dest_path))).await
}

/// Registro degli accessi in CSV. Date facoltative `YYYY-MM-DD` (giorni locali), estremi inclusi.
#[tauri::command]
pub async fn export_audit_csv(
    core: Core<'_>,
    dest_path: String,
    date_from: Option<String>,
    date_to: Option<String>,
) -> Res<AuditExportDto> {
    let core = core.inner().clone();
    blocking(move || core.export_audit_csv(Path::new(&dest_path), date_from.as_deref(), date_to.as_deref())).await
}

#[tauri::command]
pub async fn run_maintenance(core: Core<'_>) -> Res<MaintenanceReport> {
    let core = core.inner().clone();
    blocking(move || core.maintenance()).await
}

// ───────── avvio ─────────

pub fn run() {
    // Cartella dati e lock PRIMA di avviare Tauri: una seconda istanza termina subito, senza
    // finestra. È la stessa cartella di `app_data_dir()` (stesso identificativo, vedi il test
    // in `backup`) e quella che usa `--backup-db`.
    let Some(dir) = default_data_dir() else {
        eprintln!("[dms] cartella dati non determinabile");
        std::process::exit(1);
    };
    if let Err(e) = fs::create_dir_all(&dir) {
        eprintln!("[dms] cartella dati non accessibile: {e}");
        std::process::exit(1);
    }
    let lock = match InstanceLock::acquire_for_app(&dir, INSTANCE_LOCK_WAIT) {
        Ok(Some(l)) => l,
        Ok(None) => {
            eprintln!("[dms] l'applicazione è già aperta");
            return;
        }
        Err(e) => {
            eprintln!("[dms] lock di istanza non accessibile: {e}");
            std::process::exit(1);
        }
    };

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(move |app| {
            // tenuto per tutta la vita dell'app: `--backup-db` sa che il DB è in uso
            app.manage(lock);
            let core = Arc::new(
                AppCore::new(&dir.join(VAULT_DIR), &dir.join(DB_FILE), IDLE_TIMEOUT)?
                    .with_snapshot_dir(&dir.join(STAGING_DIR)),
            );
            app.manage(core.clone());

            // Blocco per inattività e snapshot periodico: il thread non tocca l'interfaccia,
            // si limita a chiudere la sessione ed emettere un evento.
            let handle = app.handle().clone();
            std::thread::spawn(move || {
                let mut ticks: u32 = 0;
                loop {
                    std::thread::sleep(WATCH_INTERVAL);
                    match core.expire_if_idle() {
                        Ok(true) => {
                            let _ = handle.emit("vault-locked", ());
                        }
                        Ok(false) => {}
                        Err(e) => {
                            let _ = handle.emit("vault-locked", ());
                            emit_backup_error(&handle, &e);
                        }
                    }
                    ticks = ticks.wrapping_add(1);
                    if ticks % SNAPSHOT_EVERY_TICKS == 0 {
                        match core.snapshot_db() {
                            Ok(()) => {}
                            Err(e) if e.code == ErrorCode::Locked => {} // nulla da salvare
                            Err(e) => emit_backup_error(&handle, &e),
                        }
                    }
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            status,
            setup_vault,
            unlock,
            lock_vault,
            change_password,
            search_patients,
            create_patient,
            update_patient,
            get_patient,
            delete_patient,
            restore_patient,
            list_documents,
            delete_document,
            restore_document,
            reassign_document,
            list_trash,
            upload_documents,
            open_document,
            export_patient_zip,
            export_audit_csv,
            run_maintenance,
        ])
        .build(tauri::generate_context!())
        .expect("errore durante l'avvio dell'applicazione");

    app.run(|handle, event| {
        // Chiusura pulita: chiavi azzerate, operazioni pesanti attese, checkpoint e snapshot
        // scritti. Si fa su `ExitRequested`, che arriva PRIMA che il loop termini; il
        // gestore è sincrono, quindi l'uscita aspetta la fine del salvataggio. `Exit` resta
        // come rete di sicurezza (es. uscita senza richiesta): se la sessione è già chiusa
        // `shutdown` non fa nulla.
        let phase = match event {
            RunEvent::ExitRequested { .. } => "ExitRequested",
            RunEvent::Exit => "Exit",
            _ => return,
        };
        if let Some(core) = handle.try_state::<Arc<AppCore>>() {
            let started = std::time::Instant::now();
            let r = core.shutdown(SHUTDOWN_WAIT);
            if let Err(e) = &r {
                eprintln!("[dms] chiusura ({phase}): {}", e.message);
            }
            if cfg!(debug_assertions) {
                eprintln!("[dms] chiusura ({phase}) in {:?}", started.elapsed());
            }
        }
    });
}