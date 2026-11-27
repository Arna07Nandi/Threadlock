// Threadlock Desktop Invisible Layer (Tauri v2 / Rust)
// 1. OS-level screen-share invisibility (NSWindowSharingNone on macOS, WDA_EXCLUDEFROMCAPTURE on Windows)
// 2. Global On-Demand Summon Hotkey (Cmd+Shift+Space / Ctrl+Shift+Space) if Threadlock stayed silent
// 3. Mandatory Pre-Call Consent Disclosure & Ephemeral Zero-Recording Mode

#[cfg(target_os = "macos")]
pub fn enable_screen_share_stealth(window: &tauri::WebviewWindow) {
    use cocoa::base::id;
    if let Ok(ns_win) = window.ns_window() {
        unsafe {
            let win_id = ns_win as id;
            // NSWindowSharingNone = 0: Excluded from Zoom, Meet, Teams, OBS & Apple ScreenCaptureKit
            let _: () = objc::msg_send![win_id, setSharingType: 0u64];
            let _: () = objc::msg_send![win_id, setLevel: 25i64];
        }
    }
}

#[cfg(target_os = "windows")]
pub fn enable_screen_share_stealth(window: &tauri::WebviewWindow) {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE};
    if let Ok(hwnd) = window.hwnd() {
        unsafe {
            // WDA_EXCLUDEFROMCAPTURE = 0x11: Excluded from Zoom, Meet, Teams, OBS & Snipping Tool
            let _ = SetWindowDisplayAffinity(HWND(hwnd.0 as _), WDA_EXCLUDEFROMCAPTURE);
        }
    }
}

pub const MANUAL_SUMMON_HOTKEY: &str = "CommandOrControl+Shift+Space";
pub const EPHEMERAL_ZERO_RECORDING_DEFAULT: bool = true;
