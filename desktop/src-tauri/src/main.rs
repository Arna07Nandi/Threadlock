#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod stealth;

use tauri::Manager;
use tauri_plugin_global_shortcut::{GlobalShortcutExt, ShortcutState};

fn main() {
    tauri::Builder::default()
        .plugin(
            tauri_plugin_global_shortcut::Builder::new()
                .with_handler(|app, _shortcut, event| {
                    if event.state() == ShortcutState::Pressed {
                        if let Some(window) = app.get_webview_window("whisper-hud") {
                            let visible = window.is_visible().unwrap_or(false);
                            if visible {
                                let _ = window.hide();
                            } else {
                                stealth::enable_screen_share_stealth(&window);
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                    }
                })
                .build(),
        )
        .setup(|app| {
            if let Some(window) = app.get_webview_window("whisper-hud") {
                stealth::enable_screen_share_stealth(&window);
            }
            app.global_shortcut().register(stealth::MANUAL_SUMMON_HOTKEY)?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Threadlock desktop app");
}
