//! GTK4 verification overlay UI.
//!
//! Shows a live camera feed with circle mask + timeout ring during face verification.
//! Feature-gated behind `gtk-overlay` — compiles to no-ops without it.
//!
//! A single persistent GTK thread is spawned on first use (GTK can only init once).

use crate::face::liveness::LivenessFrame;
use std::sync::mpsc::SyncSender;

/// Handle to the current overlay session. Waits for window close on drop.
pub struct OverlayHandle {
    #[cfg(feature = "gtk-overlay")]
    done_rx: std::sync::mpsc::Receiver<()>,
}

/// Sender for pushing liveness frames to the overlay.
pub struct OverlaySender {
    #[cfg(feature = "gtk-overlay")]
    tx: SyncSender<LivenessFrame>,
}

impl OverlaySender {
    pub fn sender(&self) -> Option<&SyncSender<LivenessFrame>> {
        #[cfg(feature = "gtk-overlay")]
        { return Some(&self.tx); }
        #[cfg(not(feature = "gtk-overlay"))]
        { return None; }
    }

    pub fn send_final(&self, _success: bool) {
        #[cfg(feature = "gtk-overlay")]
        {
            let sentinel = LivenessFrame {
                rgb: vec![],
                width: 0,
                height: 0,
                face_detected: false,
                ear: 0.0,
                mar: 0.0,
                blinks: 0,
                mouth_events: 0,
                time_remaining_secs: 0.0,
                final_status: Some(_success),
            };
            let _ = self.tx.try_send(sentinel);
        }
    }
}

pub fn spawn_overlay() -> (OverlayHandle, OverlaySender) {
    #[cfg(feature = "gtk-overlay")]
    { return spawn_overlay_gtk(); }
    #[cfg(not(feature = "gtk-overlay"))]
    {
        return (OverlayHandle {}, OverlaySender {});
    }
}

impl Drop for OverlayHandle {
    fn drop(&mut self) {
        #[cfg(feature = "gtk-overlay")]
        {
            let _ = self.done_rx.recv_timeout(std::time::Duration::from_secs(3));
        }
    }
}

// ---------------------------------------------------------------------------
// GTK4 implementation
// ---------------------------------------------------------------------------

#[cfg(feature = "gtk-overlay")]
use std::sync::OnceLock;

#[cfg(feature = "gtk-overlay")]
struct OverlaySession {
    frame_rx: std::sync::mpsc::Receiver<LivenessFrame>,
    done_tx: SyncSender<()>,
}

#[cfg(feature = "gtk-overlay")]
static GTK_THREAD: OnceLock<std::sync::Mutex<SyncSender<OverlaySession>>> = OnceLock::new();

#[cfg(feature = "gtk-overlay")]
fn spawn_overlay_gtk() -> (OverlayHandle, OverlaySender) {
    let (frame_tx, frame_rx) = std::sync::mpsc::sync_channel::<LivenessFrame>(2);
    let (done_tx, done_rx) = std::sync::mpsc::sync_channel::<()>(1);

    let session_tx = GTK_THREAD.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::sync_channel::<OverlaySession>(4);
        std::thread::Builder::new()
            .name("vauth-overlay".into())
            .spawn(move || gtk_thread_main(rx))
            .unwrap_or_else(|e| {
                tracing::warn!("failed to spawn overlay thread: {e}");
                std::thread::spawn(|| {})
            });
        std::sync::Mutex::new(tx)
    });

    if let Ok(tx) = session_tx.lock() {
        let _ = tx.try_send(OverlaySession { frame_rx, done_tx });
    }

    (
        OverlayHandle { done_rx },
        OverlaySender { tx: frame_tx },
    )
}

#[cfg(feature = "gtk-overlay")]
fn gtk_thread_main(session_rx: std::sync::mpsc::Receiver<OverlaySession>) {
    // Force Wayland backend for layer-shell support.
    // Must be set before gtk4::init() on THIS thread.
    if std::env::var("WAYLAND_DISPLAY").is_ok() {
        unsafe { std::env::set_var("GDK_BACKEND", "wayland"); }
    }

    if gtk4::init().is_err() {
        tracing::warn!("GTK4 init failed — overlay disabled");
        while let Ok(s) = session_rx.recv() {
            let _ = s.done_tx.try_send(());
        }
        return;
    }

    let main_loop = glib::MainLoop::new(None, false);
    let session_rx = std::sync::Arc::new(std::sync::Mutex::new(session_rx));
    let session_rx_clone = session_rx.clone();

    glib::timeout_add_local(std::time::Duration::from_millis(50), move || {
        if let Ok(rx) = session_rx_clone.lock() {
            if let Ok(session) = rx.try_recv() {
                create_session_window(session);
            }
        }
        glib::ControlFlow::Continue
    });

    main_loop.run();
}

// ---------------------------------------------------------------------------
// Theme colors from Caelestia scheme
// ---------------------------------------------------------------------------

#[cfg(feature = "gtk-overlay")]
struct ThemeColors {
    bg: (f64, f64, f64),
    fg: (f64, f64, f64),
    primary: (f64, f64, f64),
    error: (f64, f64, f64),
    surface: (f64, f64, f64),
    dim: (f64, f64, f64),
}

#[cfg(feature = "gtk-overlay")]
fn hex_to_rgb(hex: &str) -> Option<(f64, f64, f64)> {
    let hex = hex.trim_start_matches('#');
    if hex.len() != 6 { return None; }
    let r = u8::from_str_radix(&hex[0..2], 16).ok()? as f64 / 255.0;
    let g = u8::from_str_radix(&hex[2..4], 16).ok()? as f64 / 255.0;
    let b = u8::from_str_radix(&hex[4..6], 16).ok()? as f64 / 255.0;
    Some((r, g, b))
}

#[cfg(feature = "gtk-overlay")]
fn load_theme() -> ThemeColors {
    let defaults = ThemeColors {
        bg: (0.09, 0.09, 0.11),     // #17171C
        fg: (0.96, 0.96, 0.96),     // #F5F5F6
        primary: (0.14, 0.74, 0.36), // #24BD5C
        error: (0.78, 0.43, 0.45),  // #C66E73
        surface: (0.04, 0.04, 0.04), // #0A0A0B
        dim: (0.53, 0.53, 0.53),    // #878787
    };

    // Try to read Caelestia color scheme
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return defaults,
    };
    let scheme_path = format!("{home}/.config/hypr/scheme/current.lua");
    let content = match std::fs::read_to_string(&scheme_path) {
        Ok(c) => c,
        Err(_) => return defaults,
    };

    let get = |key: &str| -> Option<(f64, f64, f64)> {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with(key) {
                // Parse: key = "HEXVAL",
                if let Some(start) = line.find('"') {
                    if let Some(end) = line[start+1..].find('"') {
                        return hex_to_rgb(&line[start+1..start+1+end]);
                    }
                }
            }
        }
        None
    };

    ThemeColors {
        bg: get("background =").unwrap_or(defaults.bg),
        fg: get("onBackground =").or_else(|| get("text =")).unwrap_or(defaults.fg),
        primary: get("primary =").unwrap_or(defaults.primary),
        error: get("error =").unwrap_or(defaults.error),
        surface: get("surface =").unwrap_or(defaults.surface),
        dim: get("subtext0 =").or_else(|| get("outline =")).unwrap_or(defaults.dim),
    }
}

// ---------------------------------------------------------------------------
// Window creation + drawing
// ---------------------------------------------------------------------------

#[cfg(feature = "gtk-overlay")]
fn create_session_window(session: OverlaySession) {
    use gtk4::prelude::*;
    use gtk4::{Window, Box as GtkBox, Orientation, DrawingArea};
    use std::cell::RefCell;
    use std::rc::Rc;

    let theme = Rc::new(load_theme());

    let window = Window::builder()
        .title("vauth — Face Verification")
        .build();

    // Set Hyprland/Caelestia window rules via Lua IPC.
    // Uses hl.window_rule() — the native Caelestia API.
    let _ = std::process::Command::new("hyprctl")
        .args(["eval", r#"hl.window_rule({ name = "vauth-overlay", match = { title = "vauth" }, float = true, pin = true })"#])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();

    let panel_h = 380;
    let circle_radius = 120.0;
    window.set_default_size(400, panel_h);

    // Drawing area for circle-masked camera + timeout ring
    let drawing_area = DrawingArea::new();
    drawing_area.set_size_request(-1, panel_h);
    drawing_area.set_hexpand(true);

    // Shared state for the draw callback
    let frame_data: Rc<RefCell<Option<LivenessFrame>>> = Rc::new(RefCell::new(None));
    let frame_data_draw = frame_data.clone();
    let theme_draw = theme.clone();
    let total_timeout: Rc<RefCell<Option<f32>>> = Rc::new(RefCell::new(None));
    let total_timeout_draw = total_timeout.clone();

    drawing_area.set_draw_func(move |_area, cr, width, height| {
        let theme = &*theme_draw;
        let w = width as f64;
        let h = height as f64;
        let cx = w / 2.0;
        let cy = h * 0.4; // camera circle sits upper-center
        let r = circle_radius;

        // Background
        cr.set_source_rgb(theme.bg.0, theme.bg.1, theme.bg.2);
        let _ = cr.paint();

        // Draw camera feed clipped to circle
        if let Some(ref frame) = *frame_data_draw.borrow() {
            if !frame.rgb.is_empty() && frame.width > 0 && frame.height > 0 {
                // Create image surface from RGB data
                let fw = frame.width as i32;
                let fh = frame.height as i32;
                let stride = gtk4::cairo::Format::Rgb24.stride_for_width(fw as u32).unwrap_or(fw * 4);

                // Convert RGB to Cairo's BGRX format
                let mut cairo_data = vec![0u8; (stride * fh) as usize];
                for y in 0..fh {
                    for x in 0..fw {
                        let src = ((y * fw + x) * 3) as usize;
                        let dst = (y * stride + x * 4) as usize;
                        if src + 2 < frame.rgb.len() && dst + 3 < cairo_data.len() {
                            cairo_data[dst] = frame.rgb[src + 2];     // B
                            cairo_data[dst + 1] = frame.rgb[src + 1]; // G
                            cairo_data[dst + 2] = frame.rgb[src];     // R
                            cairo_data[dst + 3] = 255;                // X
                        }
                    }
                }

                if let Ok(surface) = gtk4::cairo::ImageSurface::create_for_data(
                    cairo_data,
                    gtk4::cairo::Format::Rgb24,
                    fw,
                    fh,
                    stride,
                ) {
                    let _ = cr.save();

                    // Clip to circle
                    cr.arc(cx, cy, r, 0.0, 2.0 * std::f64::consts::PI);
                    cr.clip();

                    // Scale and center the camera feed in the circle
                    let scale = (2.0 * r) / (fw.min(fh) as f64);
                    let tx = cx - (fw as f64 * scale) / 2.0;
                    let ty = cy - (fh as f64 * scale) / 2.0;
                    cr.translate(tx, ty);
                    cr.scale(scale, scale);
                    let _ = cr.set_source_surface(&surface, 0.0, 0.0);
                    let _ = cr.paint();

                    let _ = cr.restore();
                }
            }
        }

        // Timeout ring
        let frame_ref = frame_data_draw.borrow();
        let (remaining, total) = if let Some(ref frame) = *frame_ref {
            let t = total_timeout_draw.borrow();
            let total = t.unwrap_or(frame.time_remaining_secs);
            (frame.time_remaining_secs, total)
        } else {
            (0.0, 1.0)
        };

        if total > 0.0 {
            let fraction = (remaining / total).clamp(0.0, 1.0) as f64;
            // Ease-out cubic
            let eased = 1.0 - (1.0 - fraction).powi(3);
            let sweep = eased * 2.0 * std::f64::consts::PI;
            let ring_r = r + 6.0;
            let start_angle = -std::f64::consts::FRAC_PI_2; // 12 o'clock

            // Track background (dim)
            cr.set_source_rgba(theme.dim.0, theme.dim.1, theme.dim.2, 0.3);
            cr.set_line_width(3.0);
            cr.arc(cx, cy, ring_r, 0.0, 2.0 * std::f64::consts::PI);
            let _ = cr.stroke();

            // Active arc (primary color)
            if sweep > 0.01 {
                cr.set_source_rgb(theme.primary.0, theme.primary.1, theme.primary.2);
                cr.set_line_width(3.0);
                cr.arc(cx, cy, ring_r, start_angle, start_angle + sweep);
                let _ = cr.stroke();
            }
        }

        // Circle border (no camera = just border)
        let has_frame = frame_ref.as_ref().map_or(false, |f| !f.rgb.is_empty());
        if !has_frame {
            cr.set_source_rgba(theme.dim.0, theme.dim.1, theme.dim.2, 0.5);
            cr.set_line_width(2.0);
            cr.arc(cx, cy, r, 0.0, 2.0 * std::f64::consts::PI);
            let _ = cr.stroke();
        }

        // Status text
        let status = if let Some(ref frame) = *frame_ref {
            if let Some(true) = frame.final_status { "Verified" }
            else if let Some(false) = frame.final_status { "Not recognized" }
            else { derive_status(frame) }
        } else {
            "Initializing..."
        };

        let text_y = cy + r + 36.0;
        cr.set_font_size(18.0);

        // Color based on status
        if let Some(ref frame) = *frame_ref {
            match frame.final_status {
                Some(true) => cr.set_source_rgb(theme.primary.0, theme.primary.1, theme.primary.2),
                Some(false) => cr.set_source_rgb(theme.error.0, theme.error.1, theme.error.2),
                None => cr.set_source_rgb(theme.fg.0, theme.fg.1, theme.fg.2),
            }
        } else {
            cr.set_source_rgb(theme.dim.0, theme.dim.1, theme.dim.2);
        }

        let extents = cr.text_extents(status).unwrap_or(gtk4::cairo::TextExtents::new(0.0, 0.0, 0.0, 0.0, 0.0, 0.0));
        cr.move_to(cx - extents.width() / 2.0, text_y);
        let _ = cr.show_text(status);

        // Countdown below status
        if let Some(ref frame) = *frame_ref {
            if frame.final_status.is_none() {
                let secs = frame.time_remaining_secs.ceil() as u32;
                if secs > 0 {
                    let countdown = format!("{secs}s");
                    cr.set_source_rgba(theme.dim.0, theme.dim.1, theme.dim.2, 0.7);
                    cr.set_font_size(14.0);
                    let ext = cr.text_extents(&countdown).unwrap_or(gtk4::cairo::TextExtents::new(0.0, 0.0, 0.0, 0.0, 0.0, 0.0));
                    cr.move_to(cx - ext.width() / 2.0, text_y + 24.0);
                    let _ = cr.show_text(&countdown);
                }
            }
        }

    });

    let vbox = GtkBox::new(Orientation::Vertical, 0);
    vbox.append(&drawing_area);
    window.set_child(Some(&vbox));

    // Apply theme background via CSS
    let css = format!(
        "window {{ background-color: rgb({},{},{}); }}",
        (theme.bg.0 * 255.0) as u8,
        (theme.bg.1 * 255.0) as u8,
        (theme.bg.2 * 255.0) as u8,
    );
    let provider = gtk4::CssProvider::new();
    provider.load_from_data(&css);
    if let Some(display) = gdk4::Display::default() {
        gtk4::style_context_add_provider_for_display(
            &display,
            &provider,
            gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    }

    window.present();

    let frame_rx = std::sync::Arc::new(std::sync::Mutex::new(session.frame_rx));
    let done_tx = Rc::new(RefCell::new(Some(session.done_tx)));
    let final_shown = Rc::new(RefCell::new(false));
    let window_ref = window.downgrade();

    glib::idle_add_local(move || {
        if *final_shown.borrow() {
            return glib::ControlFlow::Continue;
        }

        let mut latest: Option<LivenessFrame> = None;
        if let Ok(rx) = frame_rx.lock() {
            while let Ok(frame) = rx.try_recv() {
                latest = Some(frame);
            }
        }

        let Some(frame) = latest else {
            return glib::ControlFlow::Continue;
        };

        // Capture total timeout from first frame
        if total_timeout.borrow().is_none() {
            *total_timeout.borrow_mut() = Some(frame.time_remaining_secs);
        }

        if let Some(success) = frame.final_status {
            *final_shown.borrow_mut() = true;
            // Store final frame for the draw func
            *frame_data.borrow_mut() = Some(LivenessFrame {
                final_status: Some(success),
                ..Default::default()
            });
            drawing_area.queue_draw();

            let window_weak = window_ref.clone();
            let done = done_tx.clone();
            glib::timeout_add_local_once(
                std::time::Duration::from_millis(1500),
                move || {
                    if let Some(win) = window_weak.upgrade() {
                        win.close();
                    }
                    if let Some(tx) = done.borrow_mut().take() {
                        let _ = tx.try_send(());
                    }
                },
            );
            return glib::ControlFlow::Break;
        }

        *frame_data.borrow_mut() = Some(frame);
        drawing_area.queue_draw();

        if let Some(win) = window_ref.upgrade() {
            let _ = win;
            glib::ControlFlow::Continue
        } else {
            if let Some(tx) = done_tx.borrow_mut().take() {
                let _ = tx.try_send(());
            }
            glib::ControlFlow::Break
        }
    });
}

#[cfg(feature = "gtk-overlay")]
fn derive_status(frame: &LivenessFrame) -> &'static str {
    if !frame.face_detected {
        return "Look at camera";
    }
    if frame.blinks == 0 && frame.mouth_events == 0 {
        if frame.ear < crate::face::liveness::EAR_BLINK_THRESHOLD {
            return "Blink detected...";
        }
        return "Blink to verify";
    }
    "Verifying identity..."
}
