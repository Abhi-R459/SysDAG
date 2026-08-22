use ratatui::style::{Color, Modifier, Style};

pub const BG: Color = Color::Rgb(11, 12, 16);
pub const SURFACE: Color = Color::Rgb(22, 24, 32);
pub const RAIL: Color = Color::Rgb(17, 18, 24);
pub const TEXT: Color = Color::Rgb(198, 208, 245);
pub const MUTED: Color = Color::Rgb(108, 112, 134);
pub const DIM: Color = Color::Rgb(58, 60, 78);
pub const BLUE: Color = Color::Rgb(137, 180, 250);
pub const GREEN: Color = Color::Rgb(166, 227, 161);
pub const YELLOW: Color = Color::Rgb(249, 226, 175);
pub const ROSE: Color = Color::Rgb(243, 139, 168);
pub const PEACH: Color = Color::Rgb(250, 179, 135);
pub const TEAL: Color = Color::Rgb(148, 226, 213);
pub const LAVENDER: Color = Color::Rgb(180, 190, 254);
pub const INK: Color = Color::Rgb(17, 17, 27);

pub fn fg(c: Color) -> Style {
    Style::default().fg(c)
}

pub fn bold(c: Color) -> Style {
    Style::default().fg(c).add_modifier(Modifier::BOLD)
}

pub fn verdict_color(label: &str) -> Color {
    match label {
        "ANOMALOUS" => ROSE,
        "REVIEW" => YELLOW,
        "NORMAL" => GREEN,
        "TRAINED" => BLUE,
        "TRACING" => TEAL,
        "FAILED" => ROSE,
        _ => MUTED,
    }
}
