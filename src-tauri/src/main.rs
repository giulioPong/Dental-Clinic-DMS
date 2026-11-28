// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // `--backup-db <staging>` per lo scheduler notturno: si gestisce prima di avviare Tauri
    // (niente finestra, niente WebView) e il processo termina con il codice del backup.
    let args: Vec<String> = std::env::args().collect();
    if let Some(code) = dental_clinic_dms_lib::backup::cli_main(&args) {
        std::process::exit(code);
    }
    dental_clinic_dms_lib::run()
}
