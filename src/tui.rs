//! Posting-inspired terminal UI for SysCall-DAG.
//!
//! Layout mirrors posting.sh: header + URL bar, collection sidebar,
//! request tabs, response pane, command palette, jump mode, footer keys.

use std::io::{self, stdout, IsTerminal};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyModifiers,
    MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph, Tabs, Wrap,
};
use ratatui::Frame;
use ratatui::Terminal;

use crate::detector::DecisionRecord;
use crate::event::TraceEvent;
use crate::pipeline::{Mode, RunReport};

const PINK: Color = Color::Rgb(243, 139, 168);
const TEAL: Color = Color::Rgb(137, 220, 235);
const GREEN: Color = Color::Rgb(166, 227, 161);
const YELLOW: Color = Color::Rgb(249, 226, 175);
const RED: Color = Color::Rgb(235, 87, 87);
const TEXT: Color = Color::Rgb(205, 214, 244);
const MUTED: Color = Color::Rgb(108, 112, 134);
const SURFACE: Color = Color::Rgb(30, 30, 46);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Focus {
    Collection,
    Request,
    Response,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReqTab {
    Events,
    Graph,
    Fingerprint,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RespTab {
    Decision,
    Evidence,
    Quality,
}

pub struct TuiOpts {
    pub target: String,
    pub target_args: Vec<String>,
}

struct App {
    report: RunReport,
    events: Vec<TraceEvent>,
    opts: TuiOpts,
    window: usize,
    event_sel: usize,
    evidence_sel: usize,
    focus: Focus,
    req_tab: ReqTab,
    resp_tab: RespTab,
    palette: bool,
    palette_q: String,
    palette_sel: usize,
    jump: bool,
    help: bool,
    req_scroll: u16,
    quit: bool,
}

impl App {
    fn new(report: RunReport, opts: TuiOpts) -> Self {
        let events = load_events(&report.run_dir);
        Self {
            report,
            events,
            opts,
            window: 0,
            event_sel: 0,
            evidence_sel: 0,
            focus: Focus::Collection,
            req_tab: ReqTab::Events,
            resp_tab: RespTab::Decision,
            palette: false,
            palette_q: String::new(),
            palette_sel: 0,
            jump: false,
            help: false,
            req_scroll: 0,
            quit: false,
        }
    }

    fn n_windows(&self) -> usize {
        self.report.encoded.len().max(1)
    }

    fn decision(&self) -> Option<&DecisionRecord> {
        self.report.decisions.get(self.window)
    }

    fn status_label(&self) -> (&'static str, Color) {
        if self.report.mode == Mode::Train {
            return ("TRAINED", TEAL);
        }
        match self.decision().map(|d| d.decision.as_str()) {
            Some("ANOMALOUS") => ("ANOMALOUS", RED),
            Some("REVIEW") => ("REVIEW", YELLOW),
            Some("NORMAL") => ("NORMAL", GREEN),
            Some("UNKNOWN") => ("UNKNOWN", MUTED),
            _ => ("READY", TEAL),
        }
    }

    fn window_events(&self) -> Vec<&TraceEvent> {
        let Some(enc) = self.report.encoded.get(self.window) else {
            return self.events.iter().collect();
        };
        let start = enc.graph.window.start_seq;
        let end = enc.graph.window.end_seq;
        let scoped: Vec<_> = self
            .events
            .iter()
            .filter(|e| e.seq >= start && e.seq <= end)
            .collect();
        if scoped.is_empty() {
            self.events.iter().collect()
        } else {
            scoped
        }
    }

    fn commands(&self) -> Vec<(&'static str, &'static str)> {
        vec![
            ("events", "Show Events tab"),
            ("graph", "Show Graph tab"),
            ("fingerprint", "Show Fingerprint tab"),
            ("decision", "Show Decision tab"),
            ("evidence", "Show Evidence tab"),
            ("quality", "Show Quality tab"),
            ("next-window", "Select next window"),
            ("prev-window", "Select previous window"),
            ("help", "Open help"),
            ("quit", "Leave SysCall-DAG"),
        ]
    }

    fn filtered_commands(&self) -> Vec<(&'static str, &'static str)> {
        let q = self.palette_q.to_ascii_lowercase();
        self.commands()
            .into_iter()
            .filter(|(k, d)| q.is_empty() || k.contains(&q) || d.to_ascii_lowercase().contains(&q))
            .collect()
    }

    fn run_command(&mut self, name: &str) {
        match name {
            "events" => self.req_tab = ReqTab::Events,
            "graph" => self.req_tab = ReqTab::Graph,
            "fingerprint" => self.req_tab = ReqTab::Fingerprint,
            "decision" => self.resp_tab = RespTab::Decision,
            "evidence" => self.resp_tab = RespTab::Evidence,
            "quality" => self.resp_tab = RespTab::Quality,
            "next-window" => self.move_window(1),
            "prev-window" => self.move_window(-1),
            "help" => self.help = true,
            "quit" => self.quit = true,
            _ => {}
        }
        self.palette = false;
        self.palette_q.clear();
    }

    fn move_window(&mut self, delta: i32) {
        let n = self.n_windows() as i32;
        let next = (self.window as i32 + delta).rem_euclid(n) as usize;
        self.window = next;
        self.event_sel = 0;
        self.evidence_sel = 0;
        self.req_scroll = 0;
    }
}

fn load_events(run_dir: &Path) -> Vec<TraceEvent> {
    let path = run_dir.join("events.jsonl");
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

fn host_line() -> String {
    let user = std::env::var("USER").unwrap_or_else(|_| "user".into());
    let host = std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "local".into());
    format!("{user}@{host}")
}

pub fn should_open(plain: bool, json: bool) -> bool {
    !plain && !json && io::stdout().is_terminal()
}

pub fn run(report: RunReport, opts: TuiOpts) -> Result<i32> {
    enable_raw_mode().context("enable raw mode")?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut app = App::new(report, opts);
    let result = loop_ui(&mut terminal, &mut app);
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    let anomalous = app
        .report
        .decisions
        .iter()
        .any(|d| d.decision == "ANOMALOUS");
    result?;
    Ok(if anomalous { 2 } else { 0 })
}

fn loop_ui(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App) -> Result<()> {
    while !app.quit {
        terminal.draw(|f| draw(f, app))?;
        if !event::poll(Duration::from_millis(200))? {
            continue;
        }
        match event::read()? {
            Event::Key(key) => handle_key(app, key),
            Event::Mouse(m) => {
                if matches!(
                    m.kind,
                    MouseEventKind::ScrollDown | MouseEventKind::ScrollUp
                ) {
                    let dir = if matches!(m.kind, MouseEventKind::ScrollDown) {
                        1
                    } else {
                        -1
                    };
                    match app.focus {
                        Focus::Collection => app.move_window(dir),
                        Focus::Request => {
                            app.req_scroll = bump(app.req_scroll, dir);
                        }
                        Focus::Response => {
                            let n = app.decision().map(|d| d.evidence.len()).unwrap_or(0);
                            if n > 0 {
                                let next = app.evidence_sel as i32 + dir;
                                app.evidence_sel = next.clamp(0, n as i32 - 1) as usize;
                            }
                        }
                    }
                }
            }
            Event::Resize(_, _) => {}
            _ => {}
        }
    }
    Ok(())
}

fn handle_key(app: &mut App, key: KeyEvent) {
    if app.palette {
        match key.code {
            KeyCode::Esc => {
                app.palette = false;
                app.palette_q.clear();
            }
            KeyCode::Enter => {
                let cmds = app.filtered_commands();
                if let Some((name, _)) = cmds.get(app.palette_sel) {
                    app.run_command(name);
                }
            }
            KeyCode::Up | KeyCode::Char('k') if key.modifiers.is_empty() => {
                app.palette_sel = app.palette_sel.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') if key.modifiers.is_empty() => {
                let n = app.filtered_commands().len();
                if n > 0 {
                    app.palette_sel = (app.palette_sel + 1).min(n - 1);
                }
            }
            KeyCode::Backspace => {
                app.palette_q.pop();
                app.palette_sel = 0;
            }
            KeyCode::Char(c)
                if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT =>
            {
                app.palette_q.push(c);
                app.palette_sel = 0;
            }
            _ => {}
        }
        return;
    }
    if app.help {
        if matches!(key.code, KeyCode::Esc | KeyCode::Char('q') | KeyCode::F(1)) {
            app.help = false;
        }
        return;
    }
    if app.jump {
        match key.code {
            KeyCode::Char('c') | KeyCode::Char('1') => app.focus = Focus::Collection,
            KeyCode::Char('r') | KeyCode::Char('2') => app.focus = Focus::Request,
            KeyCode::Char('s') | KeyCode::Char('3') => app.focus = Focus::Response,
            _ => {}
        }
        app.jump = false;
        return;
    }

    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    match key.code {
        KeyCode::Char('c') if ctrl => app.quit = true,
        KeyCode::Char('p') if ctrl => app.palette = true,
        KeyCode::Char('o') if ctrl => app.jump = true,
        KeyCode::F(1) => app.help = true,
        KeyCode::Char('q') => app.quit = true,
        KeyCode::Char('p') => app.palette = true,
        KeyCode::Char('o') => app.jump = true,
        KeyCode::Char('?') => app.help = true,
        KeyCode::Tab => {
            app.focus = match app.focus {
                Focus::Collection => Focus::Request,
                Focus::Request => Focus::Response,
                Focus::Response => Focus::Collection,
            };
        }
        KeyCode::BackTab => {
            app.focus = match app.focus {
                Focus::Collection => Focus::Response,
                Focus::Request => Focus::Collection,
                Focus::Response => Focus::Request,
            };
        }
        KeyCode::Char('1') => app.req_tab = ReqTab::Events,
        KeyCode::Char('2') => app.req_tab = ReqTab::Graph,
        KeyCode::Char('3') => app.req_tab = ReqTab::Fingerprint,
        KeyCode::Char('4') => app.resp_tab = RespTab::Decision,
        KeyCode::Char('5') => app.resp_tab = RespTab::Evidence,
        KeyCode::Char('6') => app.resp_tab = RespTab::Quality,
        KeyCode::Right | KeyCode::Char('l') if app.focus == Focus::Request => {
            app.req_tab = match app.req_tab {
                ReqTab::Events => ReqTab::Graph,
                ReqTab::Graph => ReqTab::Fingerprint,
                ReqTab::Fingerprint => ReqTab::Events,
            };
        }
        KeyCode::Left | KeyCode::Char('h') if app.focus == Focus::Request => {
            app.req_tab = match app.req_tab {
                ReqTab::Events => ReqTab::Fingerprint,
                ReqTab::Graph => ReqTab::Events,
                ReqTab::Fingerprint => ReqTab::Graph,
            };
        }
        KeyCode::Right | KeyCode::Char('l') if app.focus == Focus::Response => {
            app.resp_tab = match app.resp_tab {
                RespTab::Decision => RespTab::Evidence,
                RespTab::Evidence => RespTab::Quality,
                RespTab::Quality => RespTab::Decision,
            };
        }
        KeyCode::Left | KeyCode::Char('h') if app.focus == Focus::Response => {
            app.resp_tab = match app.resp_tab {
                RespTab::Decision => RespTab::Quality,
                RespTab::Evidence => RespTab::Decision,
                RespTab::Quality => RespTab::Evidence,
            };
        }
        KeyCode::Down | KeyCode::Char('j') => step_sel(app, 1),
        KeyCode::Up | KeyCode::Char('k') => step_sel(app, -1),
        KeyCode::Char('[') => app.move_window(-1),
        KeyCode::Char(']') => app.move_window(1),
        _ => {}
    }
}

fn step_sel(app: &mut App, dir: i32) {
    match app.focus {
        Focus::Collection => app.move_window(dir),
        Focus::Request => {
            let n = app.window_events().len() as i32;
            if n > 0 {
                let next = app.event_sel as i32 + dir;
                app.event_sel = next.clamp(0, n - 1) as usize;
            } else {
                app.req_scroll = bump(app.req_scroll, dir);
            }
        }
        Focus::Response => {
            let n = app.decision().map(|d| d.evidence.len()).unwrap_or(1) as i32;
            let next = app.evidence_sel as i32 + dir;
            app.evidence_sel = next.clamp(0, (n - 1).max(0)) as usize;
        }
    }
}

fn draw(f: &mut Frame, app: &App) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(1),
        ])
        .split(f.area());

    draw_header(f, root[0], app);
    draw_urlbar(f, root[1], app);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(28), Constraint::Percentage(72)])
        .split(root[2]);
    draw_collection(f, body[0], app);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(body[1]);
    draw_request(f, right[0], app);
    draw_response(f, right[1], app);
    draw_footer(f, root[3], app);

    if app.palette {
        draw_palette(f, app);
    }
    if app.help {
        draw_help(f);
    }
}

fn draw_header(f: &mut Frame, area: Rect, _app: &App) {
    let line = Line::from(vec![
        Span::styled(
            " SysCall-DAG ",
            Style::default()
                .fg(Color::Black)
                .bg(PINK)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!(" {} ", host_line()), Style::default().fg(MUTED)),
        Span::styled("  process anomaly monitor", Style::default().fg(MUTED)),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn draw_urlbar(f: &mut Frame, area: Rect, app: &App) {
    let (label, color) = match app.report.mode {
        Mode::Train => ("TRAIN", TEAL),
        Mode::Monitor => ("MONITOR", PINK),
        Mode::Auto => ("AUTO", YELLOW),
    };
    let args = if app.opts.target_args.is_empty() {
        String::new()
    } else {
        format!("  {}", app.opts.target_args.join(" "))
    };
    let inner = Line::from(vec![
        Span::styled(
            format!(" {label} ▼ "),
            Style::default()
                .fg(Color::Black)
                .bg(color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(&app.opts.target, Style::default().fg(TEXT)),
        Span::styled(args, Style::default().fg(MUTED)),
        Span::raw("   "),
        Span::styled(
            format!("{} ev  {} win", app.report.events, app.report.encoded.len()),
            Style::default().fg(MUTED),
        ),
    ]);
    let block = panel(" Target ", app.jump.then_some("j"), false);
    f.render_widget(Paragraph::new(inner).block(block), area);
}

fn draw_collection(f: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Collection;
    let items: Vec<ListItem> = if app.report.encoded.is_empty() {
        vec![ListItem::new("  (no windows)")]
    } else {
        app.report
            .encoded
            .iter()
            .enumerate()
            .map(|(i, enc)| {
                let dec = app.report.decisions.get(i);
                let badge =
                    dec.map(|d| d.decision.as_str())
                        .unwrap_or(if app.report.mode == Mode::Train {
                            "TRAIN"
                        } else {
                            "—"
                        });
                let color = match badge {
                    "ANOMALOUS" => RED,
                    "REVIEW" => YELLOW,
                    "NORMAL" | "TRAIN" => GREEN,
                    _ => MUTED,
                };
                let selected = i == app.window;
                let mark = if selected { "█ " } else { "  " };
                let line = Line::from(vec![
                    Span::styled(mark, Style::default().fg(PINK)),
                    Span::styled(
                        format!("{:<9} ", badge),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        enc.graph.window.window_id.clone(),
                        Style::default().fg(TEXT),
                    ),
                ]);
                ListItem::new(line)
            })
            .collect()
    };
    let mut state = ListState::default();
    state.select(Some(app.window));
    let title_right = " windows ";
    let block = panel(" Collection ", app.jump.then_some("c"), focused)
        .title(Line::from(title_right).right_aligned());
    let list = List::new(items).block(block).highlight_style(
        Style::default()
            .bg(if focused { PINK } else { SURFACE })
            .fg(if focused { Color::Black } else { TEXT }),
    );
    f.render_stateful_widget(list, area, &mut state);
}

fn draw_request(f: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Request;
    let titles = ["Events", "Graph", "Fingerprint"];
    let idx = match app.req_tab {
        ReqTab::Events => 0,
        ReqTab::Graph => 1,
        ReqTab::Fingerprint => 2,
    };
    let outer = panel(" Request ", app.jump.then_some("r"), focused);
    f.render_widget(outer, area);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(1)])
        .split(inner_of(area));

    let tabs = Tabs::new(titles.iter().copied().map(Line::from))
        .select(idx)
        .style(Style::default().fg(MUTED))
        .highlight_style(
            Style::default()
                .fg(PINK)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        )
        .divider(" • ");
    f.render_widget(tabs, chunks[0]);

    let body = match app.req_tab {
        ReqTab::Events => event_lines(app),
        ReqTab::Graph => graph_lines(app),
        ReqTab::Fingerprint => fingerprint_lines(app),
    };
    f.render_widget(
        Paragraph::new(body)
            .scroll((app.req_scroll, 0))
            .wrap(Wrap { trim: false }),
        chunks[1],
    );
}

fn draw_response(f: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Response;
    let (status, color) = app.status_label();
    let title = format!(" Response {status} ");
    let idx = match app.resp_tab {
        RespTab::Decision => 0,
        RespTab::Evidence => 1,
        RespTab::Quality => 2,
    };
    let outer = panel(&title, app.jump.then_some("s"), focused).style(Style::default().fg(color));
    f.render_widget(outer, area);

    let inner = inner_of(area);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(1)])
        .split(inner);
    let tabs = Tabs::new(
        ["Decision", "Evidence", "Quality"]
            .iter()
            .copied()
            .map(Line::from),
    )
    .select(idx)
    .style(Style::default().fg(MUTED))
    .highlight_style(
        Style::default()
            .fg(color)
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
    )
    .divider(" • ");
    f.render_widget(tabs, chunks[0]);
    f.render_widget(
        Paragraph::new(response_lines(app, idx)).wrap(Wrap { trim: false }),
        chunks[1],
    );
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    let hint = if app.jump {
        " jump  c collection  r request  s response   esc cancel"
    } else if app.palette {
        " type to filter   enter run   esc close"
    } else {
        " ^p Commands   o Jump   1-3 Request   4-6 Response   j/k Move   [/] Window   f1 Help   q Quit"
    };
    f.render_widget(
        Paragraph::new(Span::styled(hint, Style::default().fg(MUTED))),
        area,
    );
}

fn draw_palette(f: &mut Frame, app: &App) {
    let area = centered(f.area(), 60, 50);
    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(PINK))
        .title(" Commands ")
        .title(Line::from(" ^p ").right_aligned())
        .style(Style::default().bg(SURFACE).fg(TEXT));
    f.render_widget(block, area);
    let inner = inner_of(area);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(1)])
        .split(inner);
    f.render_widget(
        Paragraph::new(format!("> {}", app.palette_q)).style(Style::default().fg(TEAL)),
        chunks[0],
    );
    let cmds = app.filtered_commands();
    let items: Vec<ListItem> = cmds
        .iter()
        .map(|(k, d)| {
            ListItem::new(Line::from(vec![
                Span::styled(format!("{k:<16}"), Style::default().fg(PINK)),
                Span::styled(*d, Style::default().fg(TEXT)),
            ]))
        })
        .collect();
    let mut state = ListState::default();
    state.select(Some(app.palette_sel.min(items.len().saturating_sub(1))));
    f.render_stateful_widget(
        List::new(items).highlight_style(Style::default().bg(PINK).fg(Color::Black)),
        chunks[1],
        &mut state,
    );
}

fn draw_help(f: &mut Frame) {
    let area = centered(f.area(), 70, 70);
    f.render_widget(Clear, area);
    let text = vec![
        Line::from(Span::styled(
            "SysCall-DAG  ·  posting-style keyboard",
            Style::default().fg(PINK).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("Tab / Shift-Tab    cycle collection → request → response"),
        Line::from("j k  ↑ ↓           move in the focused pane"),
        Line::from("[ ]                previous / next window"),
        Line::from("1 2 3              Events · Graph · Fingerprint"),
        Line::from("4 5 6              Decision · Evidence · Quality"),
        Line::from("p  ^p              command palette"),
        Line::from("o  ^o              jump mode (c / r / s)"),
        Line::from("f1  ?              this help"),
        Line::from("q  ^c              quit"),
        Line::from(""),
        Line::from("Collection is the window list. Request is the syscall"),
        Line::from("trace. Response is the baseline decision — same shape"),
        Line::from("as Posting's request / response split."),
    ];
    f.render_widget(
        Paragraph::new(text).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(" Help ")
                .border_style(Style::default().fg(TEAL))
                .style(Style::default().bg(SURFACE).fg(TEXT)),
        ),
        area,
    );
}

fn panel(title: &str, jump: Option<&str>, focused: bool) -> Block<'static> {
    let mut t = title.to_string();
    if let Some(j) = jump {
        t = format!(" {j} {title}");
    }
    let color = if focused { PINK } else { MUTED };
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(t)
        .border_style(Style::default().fg(color))
        .style(Style::default().fg(TEXT))
}

fn bump(value: u16, dir: i32) -> u16 {
    if dir < 0 {
        value.saturating_sub(dir.unsigned_abs() as u16)
    } else {
        value.saturating_add(dir as u16)
    }
}

fn inner_of(area: Rect) -> Rect {
    Rect {
        x: area.x.saturating_add(1),
        y: area.y.saturating_add(1),
        width: area.width.saturating_sub(2),
        height: area.height.saturating_sub(2),
    }
}

fn centered(area: Rect, pct_x: u16, pct_y: u16) -> Rect {
    let popup = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - pct_y) / 2),
            Constraint::Percentage(pct_y),
            Constraint::Percentage((100 - pct_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - pct_x) / 2),
            Constraint::Percentage(pct_x),
            Constraint::Percentage((100 - pct_x) / 2),
        ])
        .split(popup[1])[1]
}

fn event_lines(app: &App) -> Vec<Line<'static>> {
    let evs = app.window_events();
    if evs.is_empty() {
        return vec![Line::from(Span::styled(
            "no events in this window",
            Style::default().fg(MUTED),
        ))];
    }
    evs.iter()
        .enumerate()
        .map(|(i, e)| {
            let path = e
                .args
                .path
                .as_deref()
                .or(e.args.fd_path.as_deref())
                .unwrap_or("");
            let ret = e.ret.map(|r| r.to_string()).unwrap_or_else(|| "?".into());
            let sty = if i == app.event_sel {
                Style::default().fg(Color::Black).bg(PINK)
            } else {
                Style::default().fg(TEXT)
            };
            Line::styled(
                format!(
                    "{:>4}  {:<12} {:<16} {:>6}  {}",
                    e.seq, e.syscall.name, e.labels.op, ret, path
                ),
                sty,
            )
        })
        .collect()
}

fn graph_lines(app: &App) -> Vec<Line<'static>> {
    let Some(enc) = app.report.encoded.get(app.window) else {
        return vec![Line::from("no graph")];
    };
    let mut lines = vec![Line::from(Span::styled(
        format!(
            "{}  nodes={}  edges={}",
            enc.graph.graph_id, enc.n_nodes, enc.n_edges
        ),
        Style::default().fg(TEAL),
    ))];
    for n in &enc.graph.nodes {
        let op = n.label_fields.get("op").cloned().unwrap_or_default();
        let pc = n
            .label_fields
            .get("path_class")
            .cloned()
            .unwrap_or_default();
        let color = if matches!(pc.as_str(), "DECOY" | "SYSTEM_CONFIG" | "HOME" | "SHELL") {
            RED
        } else if op.contains("NET_") {
            YELLOW
        } else if n.kind == "anchor" {
            MUTED
        } else {
            TEXT
        };
        lines.push(Line::from(Span::styled(
            format!("  {:<8}  {:<16} {}", n.id, op, pc),
            Style::default().fg(color),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "edges",
        Style::default().fg(MUTED),
    )));
    for e in &enc.graph.edges {
        let accent = if e.edge_type == "BUFFER_FLOW" {
            PINK
        } else {
            TEAL
        };
        lines.push(Line::from(Span::styled(
            format!("  {}  ─{}→  {}", e.src, e.edge_type, e.dst),
            Style::default().fg(accent),
        )));
    }
    lines
}

fn fingerprint_lines(app: &App) -> Vec<Line<'static>> {
    let Some(enc) = app.report.encoded.get(app.window) else {
        return vec![Line::from("no fingerprint")];
    };
    let mut lines = vec![
        Line::from(Span::styled(
            "WL fingerprint",
            Style::default().fg(TEAL).add_modifier(Modifier::BOLD),
        )),
        Line::from(enc.fingerprint.clone()),
        Line::from(""),
        Line::from(format!(
            "depth={}  nodes={}  edges={}",
            enc.wl_depth, enc.n_nodes, enc.n_edges
        )),
        Line::from(""),
        Line::from(Span::styled(
            "histogram  (round : color… = count)",
            Style::default().fg(MUTED),
        )),
    ];
    for ((round, color), count) in enc.features.iter().take(24) {
        let short = if color.len() > 16 {
            format!("{}…", &color[..16])
        } else {
            color.clone()
        };
        lines.push(Line::from(format!("  h{round}  {short}  ×{count}")));
    }
    lines
}

fn response_lines(app: &App, tab: usize) -> Vec<Line<'static>> {
    match tab {
        1 => evidence_lines(app),
        2 => quality_lines(app),
        _ => decision_lines(app),
    }
}

fn decision_lines(app: &App) -> Vec<Line<'static>> {
    if app.report.mode == Mode::Train {
        return vec![
            Line::from(Span::styled(
                "201  baseline committed",
                Style::default().fg(TEAL).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(format!(
                "learned {} events across {} window(s)",
                app.report.events,
                app.report.encoded.len()
            )),
            Line::from(
                app.report
                    .baseline_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "(in-memory)".into()),
            ),
            Line::from(""),
            Line::from("Re-run the same file on a different workload to monitor."),
        ];
    }
    let Some(d) = app.decision() else {
        return vec![Line::from("no decision for this window")];
    };
    let (label, color) = app.status_label();
    let nearest = d
        .nearest_normal
        .as_ref()
        .map(|n| format!("{}  jaccard {:.3}", n.prototype, n.weighted_jaccard))
        .unwrap_or_else(|| "—".into());
    vec![
        Line::from(Span::styled(
            format!("{label}   score {:.3}", d.score),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(format!(
            "review ≥ {:.2}    alert ≥ {:.2}",
            d.threshold_review, d.threshold_alert
        )),
        Line::from(format!(
            "exact {}    nodes {}    edges {}",
            if d.exact_known { "yes" } else { "no" },
            d.n_nodes,
            d.n_edges
        )),
        Line::from(format!("nearest  {nearest}")),
        Line::from(format!("window   {}", d.window_id)),
        Line::from(""),
        Line::from(Span::styled(d.note.clone(), Style::default().fg(MUTED))),
    ]
}

fn evidence_lines(app: &App) -> Vec<Line<'static>> {
    let Some(d) = app.decision() else {
        return vec![Line::from(Span::styled(
            "no evidence — this run trained a baseline",
            Style::default().fg(MUTED),
        ))];
    };
    if d.evidence.is_empty() {
        return vec![Line::from("no motifs differed from the nearest prototype")];
    }
    d.evidence
        .iter()
        .enumerate()
        .flat_map(|(i, e)| {
            let sty = if i == app.evidence_sel {
                Style::default().fg(Color::Black).bg(PINK)
            } else {
                Style::default().fg(TEXT)
            };
            vec![
                Line::styled(format!("• {}", e.motif), sty),
                Line::from(Span::styled(
                    format!("    {}   events {:?}", e.detail, e.events),
                    Style::default().fg(MUTED),
                )),
            ]
        })
        .collect()
}

fn quality_lines(app: &App) -> Vec<Line<'static>> {
    let q = app.decision().map(|d| d.quality.clone()).or_else(|| {
        app.report
            .encoded
            .get(app.window)
            .map(|e| e.graph.quality.clone())
    });
    let Some(q) = q else {
        return vec![Line::from("no quality record")];
    };
    vec![
        Line::from(format!("capture_loss      {}", q.capture_loss)),
        Line::from(format!("unknown_calls     {}", q.unknown_calls)),
        Line::from(format!("rejected_lines    {}", q.rejected_lines)),
        Line::from(format!("anchor_fraction   {:.3}", q.anchor_fraction)),
        Line::from(""),
        Line::from(Span::styled(
            app.report.run_dir.display().to_string(),
            Style::default().fg(MUTED),
        )),
    ]
}
