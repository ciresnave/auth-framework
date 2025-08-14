//! Terminal User Interface for Auth Framework Administration

#[cfg(feature = "tui")]
use crate::admin::AppState;
#[cfg(feature = "tui")]
use crate::errors::{AuthError, Result};
#[cfg(feature = "tui")]
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    crossterm::{
        event::{
            self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
        },
        execute,
        terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
    },
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Clear, Gauge, List, ListItem, ListState, Paragraph, Tabs, Wrap},
};
#[cfg(feature = "tui")]
use std::{
    io::{self, Stderr},
    time::{Duration, Instant},
};
#[cfg(feature = "tui")]
use tui_input::{Input, backend::crossterm::EventHandler};

#[cfg(feature = "tui")]
type TuiTerminal = Terminal<CrosstermBackend<Stderr>>;

#[cfg(feature = "tui")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Dashboard,
    Configuration,
    Users,
    Security,
    Servers,
    Logs,
}

#[cfg(feature = "tui")]
impl Tab {
    fn title(&self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard",
            Tab::Configuration => "Configuration",
            Tab::Users => "Users",
            Tab::Security => "Security",
            Tab::Servers => "Servers",
            Tab::Logs => "Logs",
        }
    }

    fn all() -> Vec<Tab> {
        vec![
            Tab::Dashboard,
            Tab::Configuration,
            Tab::Users,
            Tab::Security,
            Tab::Servers,
            Tab::Logs,
        ]
    }
}

#[cfg(feature = "tui")]
pub struct TuiApp {
    #[allow(dead_code)]
    state: AppState,
    current_tab: Tab,
    readonly: bool,
    should_quit: bool,
    last_update: Instant,
    input: Input,
    show_input_dialog: bool,
    input_title: String,
    list_state: ListState,
    selected_config_key: Option<String>,
    config_keys: Vec<String>,
    users: Vec<User>,
    security_events: Vec<SecurityEvent>,
    server_logs: Vec<LogEntry>,
}

#[cfg(feature = "tui")]
#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub email: String,
    pub active: bool,
    pub created: String,
    pub last_login: Option<String>,
}

#[cfg(feature = "tui")]
#[derive(Debug, Clone)]
pub struct SecurityEvent {
    pub timestamp: String,
    pub event_type: String,
    pub user: Option<String>,
    pub details: String,
    pub severity: String,
}

#[cfg(feature = "tui")]
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub component: String,
    pub message: String,
}

#[cfg(feature = "tui")]
pub async fn run_tui(state: AppState, readonly: bool) -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stderr = io::stderr();
    execute!(stderr, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stderr);
    let mut terminal = Terminal::new(backend)?;

    // Create app
    let mut app = TuiApp::new(state, readonly);

    // Load initial data
    app.load_initial_data().await;

    // Run the app
    let result = run_app(&mut terminal, &mut app).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result.map_err(|e| AuthError::Cli(format!("TUI error: {}", e)))
}

#[cfg(feature = "tui")]
impl TuiApp {
    pub fn new(state: AppState, readonly: bool) -> Self {
        Self {
            state,
            current_tab: Tab::Dashboard,
            readonly,
            should_quit: false,
            last_update: Instant::now(),
            input: Input::default(),
            show_input_dialog: false,
            input_title: String::new(),
            list_state: ListState::default(),
            selected_config_key: None,
            config_keys: vec![
                "jwt.secret_key".to_string(),
                "jwt.algorithm".to_string(),
                "jwt.expiry".to_string(),
                "session.name".to_string(),
                "session.secure".to_string(),
                "oauth2.google.client_id".to_string(),
                "threat_intel.enabled".to_string(),
            ],
            users: vec![
                User {
                    id: "1".to_string(),
                    email: "admin@example.com".to_string(),
                    active: true,
                    created: "2024-01-01".to_string(),
                    last_login: Some("2024-08-10 14:30:15".to_string()),
                },
                User {
                    id: "2".to_string(),
                    email: "user@example.com".to_string(),
                    active: true,
                    created: "2024-01-02".to_string(),
                    last_login: Some("2024-08-10 13:45:32".to_string()),
                },
                User {
                    id: "3".to_string(),
                    email: "inactive@example.com".to_string(),
                    active: false,
                    created: "2024-01-03".to_string(),
                    last_login: None,
                },
            ],
            security_events: vec![
                SecurityEvent {
                    timestamp: "2024-08-10 14:30:15".to_string(),
                    event_type: "login_success".to_string(),
                    user: Some("admin@example.com".to_string()),
                    details: "Successful login from 192.168.1.100".to_string(),
                    severity: "info".to_string(),
                },
                SecurityEvent {
                    timestamp: "2024-08-10 14:25:42".to_string(),
                    event_type: "login_failure".to_string(),
                    user: Some("invalid@example.com".to_string()),
                    details: "Failed login attempt from 203.0.113.1".to_string(),
                    severity: "warning".to_string(),
                },
                SecurityEvent {
                    timestamp: "2024-08-10 14:20:33".to_string(),
                    event_type: "password_reset".to_string(),
                    user: Some("user@example.com".to_string()),
                    details: "Password reset requested".to_string(),
                    severity: "info".to_string(),
                },
            ],
            server_logs: vec![
                LogEntry {
                    timestamp: "2024-08-10 14:35:12".to_string(),
                    level: "INFO".to_string(),
                    component: "web_server".to_string(),
                    message: "Server started on port 8080".to_string(),
                },
                LogEntry {
                    timestamp: "2024-08-10 14:34:58".to_string(),
                    level: "INFO".to_string(),
                    component: "config".to_string(),
                    message: "Configuration loaded successfully".to_string(),
                },
                LogEntry {
                    timestamp: "2024-08-10 14:34:55".to_string(),
                    level: "DEBUG".to_string(),
                    component: "auth".to_string(),
                    message: "JWT validation service initialized".to_string(),
                },
            ],
        }
    }

    pub async fn load_initial_data(&mut self) {
        // In a real implementation, this would load actual data from the auth service
        self.last_update = Instant::now();
    }

    pub async fn refresh_data(&mut self) {
        if self.last_update.elapsed() > Duration::from_secs(5) {
            self.load_initial_data().await;
        }
    }

    pub fn next_tab(&mut self) {
        let tabs = Tab::all();
        let current_index = tabs
            .iter()
            .position(|&t| t == self.current_tab)
            .unwrap_or(0);
        self.current_tab = tabs[(current_index + 1) % tabs.len()];
    }

    pub fn previous_tab(&mut self) {
        let tabs = Tab::all();
        let current_index = tabs
            .iter()
            .position(|&t| t == self.current_tab)
            .unwrap_or(0);
        self.current_tab = tabs[(current_index + tabs.len() - 1) % tabs.len()];
    }

    pub fn quit(&mut self) {
        self.should_quit = true;
    }
}

#[cfg(feature = "tui")]
async fn run_app(
    terminal: &mut TuiTerminal,
    app: &mut TuiApp,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        // Refresh data periodically
        app.refresh_data().await;

        // Draw the UI
        terminal.draw(|f| ui(f, app))?;

        // Handle events
        if event::poll(Duration::from_millis(50))?
            && let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press {
                    handle_key_event(key, app).await?;
                }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}

#[cfg(feature = "tui")]
async fn handle_key_event(
    key: KeyEvent,
    app: &mut TuiApp,
) -> Result<(), Box<dyn std::error::Error>> {
    if app.show_input_dialog {
        match key.code {
            KeyCode::Enter => {
                // Process input
                let input_value = app.input.value();
                if !input_value.is_empty() {
                    // Handle the input based on context
                    // In a real implementation, this would update configuration or perform actions
                }
                app.show_input_dialog = false;
                app.input.reset();
            }
            KeyCode::Esc => {
                app.show_input_dialog = false;
                app.input.reset();
            }
            _ => {
                app.input.handle_event(&crossterm::event::Event::Key(key));
            }
        }
        return Ok(());
    }

    match key.code {
        KeyCode::Char('q') => app.quit(),
        KeyCode::Tab => app.next_tab(),
        KeyCode::BackTab => app.previous_tab(),
        KeyCode::Char('r') => app.load_initial_data().await,
        KeyCode::Up => {
            let i = app.list_state.selected().unwrap_or(0);
            if i > 0 {
                app.list_state.select(Some(i - 1));
            }
        }
        KeyCode::Down => {
            let i = app.list_state.selected().unwrap_or(0);
            let max_index = match app.current_tab {
                Tab::Configuration => app.config_keys.len().saturating_sub(1),
                Tab::Users => app.users.len().saturating_sub(1),
                Tab::Security => app.security_events.len().saturating_sub(1),
                Tab::Logs => app.server_logs.len().saturating_sub(1),
                _ => 0,
            };
            if i < max_index {
                app.list_state.select(Some(i + 1));
            }
        }
        KeyCode::Enter => {
            if !app.readonly
                && app.current_tab == Tab::Configuration
                    && let Some(selected) = app.list_state.selected()
                        && selected < app.config_keys.len() {
                            app.selected_config_key = Some(app.config_keys[selected].clone());
                            app.input_title = format!("Edit {}", app.config_keys[selected]);
                            app.show_input_dialog = true;
                        }
        }
        KeyCode::F(1) => {
            // Show help
        }
        _ => {}
    }

    Ok(())
}

#[cfg(feature = "tui")]
fn ui(f: &mut Frame, app: &mut TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(f.area());

    // Tab bar
    let tab_titles: Vec<Line> = Tab::all()
        .iter()
        .map(|tab| Line::from(tab.title()))
        .collect();

    let tabs = Tabs::new(tab_titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Auth Framework Admin"),
        )
        .select(
            Tab::all()
                .iter()
                .position(|&t| t == app.current_tab)
                .unwrap_or(0),
        )
        .style(Style::default().fg(Color::White))
        .highlight_style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .bg(Color::Blue)
                .fg(Color::White),
        );

    f.render_widget(tabs, chunks[0]);

    // Main content area
    match app.current_tab {
        Tab::Dashboard => render_dashboard(f, chunks[1], app),
        Tab::Configuration => render_configuration(f, chunks[1], app),
        Tab::Users => render_users(f, chunks[1], app),
        Tab::Security => render_security(f, chunks[1], app),
        Tab::Servers => render_servers(f, chunks[1], app),
        Tab::Logs => render_logs(f, chunks[1], app),
    }

    // Input dialog overlay
    if app.show_input_dialog {
        render_input_dialog(f, app);
    }

    // Status bar
    let status_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(Rect {
            x: chunks[1].x,
            y: chunks[1].y + chunks[1].height.saturating_sub(1),
            width: chunks[1].width,
            height: 1,
        });

    let status = if app.readonly {
        "READ ONLY - Press 'q' to quit, Tab/Shift+Tab to navigate, 'r' to refresh"
    } else {
        "Press 'q' to quit, Tab/Shift+Tab to navigate, Enter to edit, 'r' to refresh"
    };

    let help = Paragraph::new(status).style(Style::default().fg(Color::Yellow));

    f.render_widget(help, status_chunks[0]);
}

#[cfg(feature = "tui")]
fn render_dashboard(f: &mut Frame, area: Rect, app: &TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(10)])
        .split(area);

    // System status overview
    let status_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(chunks[0]);

    // Web Server Status
    let web_server_block = Block::default()
        .title("Web Server")
        .borders(Borders::ALL)
        .style(Style::default().fg(Color::Green));

    let web_server_text = Paragraph::new("● Running\nPort: 8080\nUptime: 2h 15m")
        .block(web_server_block)
        .alignment(Alignment::Center);

    f.render_widget(web_server_text, status_chunks[0]);

    // Users
    let users_block = Block::default().title("Users").borders(Borders::ALL);

    let users_text = Paragraph::new(format!(
        "Total: {}\nActive: {}\nOnline: 2",
        app.users.len(),
        app.users.iter().filter(|u| u.active).count()
    ))
    .block(users_block)
    .alignment(Alignment::Center);

    f.render_widget(users_text, status_chunks[1]);

    // Security
    let security_block = Block::default().title("Security").borders(Borders::ALL);

    let recent_events = app.security_events.len();
    let security_text = Paragraph::new(format!(
        "Status: ✅ Healthy\nEvents (24h): {}\nThreats: 0",
        recent_events
    ))
    .block(security_block)
    .alignment(Alignment::Center);

    f.render_widget(security_text, status_chunks[2]);

    // System Health
    let health_block = Block::default()
        .title("System Health")
        .borders(Borders::ALL);

    let health_text = Paragraph::new("CPU: 15%\nMemory: 256MB\nDisk: 2.1GB")
        .block(health_block)
        .alignment(Alignment::Center);

    f.render_widget(health_text, status_chunks[3]);

    // Recent Activity
    let activity_items: Vec<ListItem> = app
        .security_events
        .iter()
        .take(10)
        .map(|event| {
            let style = match event.severity.as_str() {
                "warning" => Style::default().fg(Color::Yellow),
                "error" => Style::default().fg(Color::Red),
                _ => Style::default().fg(Color::White),
            };

            ListItem::new(format!(
                "{} - {} - {}",
                event.timestamp, event.event_type, event.details
            ))
            .style(style)
        })
        .collect();

    let activity = List::new(activity_items)
        .block(
            Block::default()
                .title("Recent Activity")
                .borders(Borders::ALL),
        )
        .style(Style::default().fg(Color::White));

    f.render_widget(activity, chunks[1]);
}

#[cfg(feature = "tui")]
fn render_configuration(f: &mut Frame, area: Rect, app: &mut TuiApp) {
    let items: Vec<ListItem> = app
        .config_keys
        .iter()
        .enumerate()
        .map(|(i, key)| {
            let style = if Some(i) == app.list_state.selected() {
                Style::default().bg(Color::Blue).fg(Color::White)
            } else {
                Style::default().fg(Color::White)
            };

            // In a real implementation, we'd get the actual value
            let value = match key.as_str() {
                "jwt.secret_key" => "***hidden***",
                "jwt.algorithm" => "HS256",
                "jwt.expiry" => "1h",
                "session.name" => "AUTH_SESSION",
                "session.secure" => "true",
                "oauth2.google.client_id" => "example-client-id",
                "threat_intel.enabled" => "true",
                _ => "unknown",
            };

            ListItem::new(format!("{}: {}", key, value)).style(style)
        })
        .collect();

    let title = if app.readonly {
        "Configuration (Read Only)"
    } else {
        "Configuration (Press Enter to edit)"
    };

    let config_list = List::new(items)
        .block(Block::default().title(title).borders(Borders::ALL))
        .style(Style::default().fg(Color::White));

    f.render_stateful_widget(config_list, area, &mut app.list_state);
}

#[cfg(feature = "tui")]
fn render_users(f: &mut Frame, area: Rect, app: &mut TuiApp) {
    let items: Vec<ListItem> = app
        .users
        .iter()
        .enumerate()
        .map(|(i, user)| {
            let style = if Some(i) == app.list_state.selected() {
                Style::default().bg(Color::Blue).fg(Color::White)
            } else if user.active {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::Red)
            };

            let status = if user.active { "Active" } else { "Inactive" };
            let last_login = user.last_login.as_deref().unwrap_or("Never");

            ListItem::new(format!(
                "{} | {} | {} | Created: {} | Last Login: {}",
                user.id, user.email, status, user.created, last_login
            ))
            .style(style)
        })
        .collect();

    let users_list = List::new(items)
        .block(Block::default().title("Users").borders(Borders::ALL))
        .style(Style::default().fg(Color::White));

    f.render_stateful_widget(users_list, area, &mut app.list_state);
}

#[cfg(feature = "tui")]
fn render_security(f: &mut Frame, area: Rect, app: &mut TuiApp) {
    let items: Vec<ListItem> = app
        .security_events
        .iter()
        .enumerate()
        .map(|(i, event)| {
            let style = if Some(i) == app.list_state.selected() {
                Style::default().bg(Color::Blue).fg(Color::White)
            } else {
                match event.severity.as_str() {
                    "warning" => Style::default().fg(Color::Yellow),
                    "error" => Style::default().fg(Color::Red),
                    _ => Style::default().fg(Color::White),
                }
            };

            let user_display = event.user.as_deref().unwrap_or("system");

            ListItem::new(format!(
                "{} | {} | {} | {}",
                event.timestamp, event.event_type, user_display, event.details
            ))
            .style(style)
        })
        .collect();

    let security_list = List::new(items)
        .block(
            Block::default()
                .title("Security Events")
                .borders(Borders::ALL),
        )
        .style(Style::default().fg(Color::White));

    f.render_stateful_widget(security_list, area, &mut app.list_state);
}

#[cfg(feature = "tui")]
fn render_servers(f: &mut Frame, area: Rect, _app: &TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Server Status
    let server_info = ["Web Server: Running on port 8080",
        "Auth Service: Active",
        "Database: Connected (PostgreSQL)",
        "Redis Cache: Connected",
        "Threat Intel: Active",
        "",
        "Resource Usage:",
        "  CPU: 15% (2 cores)",
        "  Memory: 256MB / 2GB",
        "  Disk: 2.1GB used",
        "  Network: 1.2MB/s in, 800KB/s out"];

    let server_paragraph = Paragraph::new(server_info.join("\n"))
        .block(
            Block::default()
                .title("Server Status")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: true });

    f.render_widget(server_paragraph, chunks[0]);

    // Performance Metrics (simplified)
    let perf_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33),
            Constraint::Percentage(33),
            Constraint::Percentage(34),
        ])
        .split(chunks[1]);

    let cpu_gauge = Gauge::default()
        .block(Block::default().title("CPU Usage").borders(Borders::ALL))
        .gauge_style(Style::default().fg(Color::Green))
        .percent(15);
    f.render_widget(cpu_gauge, perf_chunks[0]);

    let memory_gauge = Gauge::default()
        .block(Block::default().title("Memory Usage").borders(Borders::ALL))
        .gauge_style(Style::default().fg(Color::Blue))
        .percent(25);
    f.render_widget(memory_gauge, perf_chunks[1]);

    let disk_gauge = Gauge::default()
        .block(Block::default().title("Disk Usage").borders(Borders::ALL))
        .gauge_style(Style::default().fg(Color::Yellow))
        .percent(42);
    f.render_widget(disk_gauge, perf_chunks[2]);
}

#[cfg(feature = "tui")]
fn render_logs(f: &mut Frame, area: Rect, app: &mut TuiApp) {
    let items: Vec<ListItem> = app
        .server_logs
        .iter()
        .enumerate()
        .map(|(i, log)| {
            let style = if Some(i) == app.list_state.selected() {
                Style::default().bg(Color::Blue).fg(Color::White)
            } else {
                match log.level.as_str() {
                    "ERROR" => Style::default().fg(Color::Red),
                    "WARN" => Style::default().fg(Color::Yellow),
                    "DEBUG" => Style::default().fg(Color::Cyan),
                    _ => Style::default().fg(Color::White),
                }
            };

            ListItem::new(format!(
                "{} | {} | {} | {}",
                log.timestamp, log.level, log.component, log.message
            ))
            .style(style)
        })
        .collect();

    let logs_list = List::new(items)
        .block(Block::default().title("Server Logs").borders(Borders::ALL))
        .style(Style::default().fg(Color::White));

    f.render_stateful_widget(logs_list, area, &mut app.list_state);
}

#[cfg(feature = "tui")]
fn render_input_dialog(f: &mut Frame, app: &mut TuiApp) {
    let area = centered_rect(60, 20, f.area());
    f.render_widget(Clear, area);

    let input_block = Block::default()
        .title(&*app.input_title)
        .borders(Borders::ALL)
        .style(Style::default().bg(Color::Black));

    let input_paragraph = Paragraph::new(app.input.value()).block(input_block);

    f.render_widget(input_paragraph, area);

    // Set cursor position
    f.set_cursor_position((area.x + app.input.visual_cursor() as u16 + 1, area.y + 1));
}

#[cfg(feature = "tui")]
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
