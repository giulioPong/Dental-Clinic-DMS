mod audit;
pub mod backup;
mod commands;
mod crypto;
mod db;
mod storage;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    commands::tauri_api::run()
}
