//! Helpers for placing transient Slint dialogs where the user is looking.

use slint::winit_030::winit::{
    dpi::PhysicalPosition, monitor::MonitorHandle, window::Window as WinitWindow,
};
use slint::winit_030::WinitWindowAccessor;

#[derive(Clone, Copy, Debug)]
struct ScreenBounds {
    x: i32,
    y: i32,
    width: i32,
    height: i32,
}

impl ScreenBounds {
    fn from_winit_monitor(monitor: &MonitorHandle) -> Self {
        let position = monitor.position();
        let size = monitor.size();

        Self {
            x: position.x,
            y: position.y,
            width: i32::try_from(size.width).unwrap_or(i32::MAX),
            height: i32::try_from(size.height).unwrap_or(i32::MAX),
        }
    }

    fn is_valid(self) -> bool {
        self.width > 0 && self.height > 0
    }
}

/// Center a transient Slint window on the most relevant monitor, then focus it.
///
/// On Windows, background prompts do not have a parent window, so the best hint
/// is the display that currently contains the mouse cursor. Other platforms use
/// winit's current/primary monitor information as a portable fallback.
pub(crate) fn center_on_active_monitor_and_focus(window: &slint::Window) {
    if !window.has_winit_window() {
        tracing::debug!("Skipping dialog placement because no winit window is available");
        return;
    }

    let _ = window.with_winit_window(|winit_window: &WinitWindow| {
        if !center_on_platform_active_monitor(winit_window)
            && !center_on_winit_monitor(winit_window)
        {
            tracing::warn!("Unable to determine monitor for dialog placement");
        }

        winit_window.focus_window();
        None::<()>
    });
}

#[cfg(windows)]
fn center_on_platform_active_monitor(window: &WinitWindow) -> bool {
    let Some(bounds) = cursor_monitor_work_area() else {
        return false;
    };

    center_window_in_bounds(window, bounds)
}

#[cfg(not(windows))]
fn center_on_platform_active_monitor(_window: &WinitWindow) -> bool {
    false
}

fn center_on_winit_monitor(window: &WinitWindow) -> bool {
    let monitor = window
        .current_monitor()
        .or_else(|| window.primary_monitor())
        .or_else(|| window.available_monitors().next());

    match monitor {
        Some(monitor) => {
            center_window_in_bounds(window, ScreenBounds::from_winit_monitor(&monitor))
        }
        None => false,
    }
}

fn center_window_in_bounds(window: &WinitWindow, bounds: ScreenBounds) -> bool {
    if !bounds.is_valid() {
        return false;
    }

    let window_size = window.outer_size();
    let window_width = i32::try_from(window_size.width).unwrap_or(i32::MAX);
    let window_height = i32::try_from(window_size.height).unwrap_or(i32::MAX);

    if window_width <= 0 || window_height <= 0 {
        return false;
    }

    let x = bounds
        .x
        .saturating_add((bounds.width - window_width).max(0) / 2);
    let y = bounds
        .y
        .saturating_add((bounds.height - window_height).max(0) / 2);

    window.set_outer_position(PhysicalPosition::new(x, y));
    true
}

#[cfg(windows)]
fn cursor_monitor_work_area() -> Option<ScreenBounds> {
    use windows::Win32::Foundation::POINT;
    use windows::Win32::Graphics::Gdi::{
        GetMonitorInfoW, MonitorFromPoint, MONITORINFO, MONITOR_DEFAULTTONEAREST,
    };
    use windows::Win32::UI::WindowsAndMessaging::GetCursorPos;

    let mut cursor = POINT { x: 0, y: 0 };
    if unsafe { GetCursorPos(&mut cursor) }.is_err() {
        return None;
    }

    let monitor = unsafe { MonitorFromPoint(cursor, MONITOR_DEFAULTTONEAREST) };
    if monitor.is_invalid() {
        return None;
    }

    let mut monitor_info = MONITORINFO {
        cbSize: std::mem::size_of::<MONITORINFO>() as u32,
        ..Default::default()
    };

    if !unsafe { GetMonitorInfoW(monitor, &mut monitor_info) }.as_bool() {
        return None;
    }

    let work_area = monitor_info.rcWork;
    let bounds = ScreenBounds {
        x: work_area.left,
        y: work_area.top,
        width: work_area.right.saturating_sub(work_area.left),
        height: work_area.bottom.saturating_sub(work_area.top),
    };

    bounds.is_valid().then_some(bounds)
}
