//! Dashboard UI Rendering
//!
//! Renders the TUI dashboard using ratatui

use crate::tui::app::{CircuitState, DashboardApp, DashboardMetrics, KeyCode, LogLevel};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode as CrosstermKeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span},
    widgets::{
        Axis, Block, Borders, Chart, Dataset, Gauge, GraphType, List, ListItem, Paragraph, Row,
        Sparkline, Table, Tabs, Wrap,
    },
    Frame, Terminal,
};
use std::io::{self, Stdout};
use std::sync::Arc;
use std::time::Duration;

/// Dashboard runner
pub struct Dashboard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    app: DashboardApp,
}

impl Dashboard {
    /// Create and initialize the dashboard
    pub fn new(metrics: Arc<DashboardMetrics>) -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;

        Ok(Self {
            terminal,
            app: DashboardApp::new(metrics),
        })
    }

    /// Run the dashboard event loop
    pub fn run(&mut self) -> io::Result<()> {
        loop {
            // Update metrics
            self.app.metrics.update_calculated_metrics();

            // Draw
            self.terminal.draw(|f| draw_ui(f, &self.app))?;

            // Handle events with timeout
            if event::poll(Duration::from_millis(self.app.refresh_rate_ms))? {
                if let Event::Key(key) = event::read()? {
                    let key_code = match key.code {
                        CrosstermKeyCode::Char('q') | CrosstermKeyCode::Char('Q') => KeyCode::Quit,
                        CrosstermKeyCode::Esc => KeyCode::Escape,
                        CrosstermKeyCode::Tab => KeyCode::Tab,
                        CrosstermKeyCode::BackTab => KeyCode::BackTab,
                        CrosstermKeyCode::Left => KeyCode::Left,
                        CrosstermKeyCode::Right => KeyCode::Right,
                        CrosstermKeyCode::Up => KeyCode::Up,
                        CrosstermKeyCode::Down => KeyCode::Down,
                        CrosstermKeyCode::Char('?') | CrosstermKeyCode::Char('h') => KeyCode::Help,
                        CrosstermKeyCode::PageUp => KeyCode::PageUp,
                        CrosstermKeyCode::PageDown => KeyCode::PageDown,
                        CrosstermKeyCode::Enter => KeyCode::Enter,
                        _ => KeyCode::Other,
                    };
                    self.app.handle_key(key_code);
                }
            }

            if self.app.should_quit || !self.app.metrics.is_running() {
                break;
            }
        }

        Ok(())
    }

    /// Cleanup and restore terminal
    pub fn cleanup(&mut self) -> io::Result<()> {
        disable_raw_mode()?;
        execute!(
            self.terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        self.terminal.show_cursor()?;
        Ok(())
    }
}

impl Drop for Dashboard {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

/// Draw the main UI
fn draw_ui(f: &mut Frame, app: &DashboardApp) {
    let size = f.area();

    // Create main layout
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(0),    // Main content
            Constraint::Length(1), // Footer
        ])
        .split(size);

    // Draw header
    draw_header(f, app, chunks[0]);

    // Draw main content based on tab
    match app.current_tab {
        0 => draw_overview(f, app, chunks[1]),
        1 => draw_upstreams(f, app, chunks[1]),
        2 => draw_traffic(f, app, chunks[1]),
        3 => draw_logs(f, app, chunks[1]),
        _ => {}
    }

    // Draw footer
    draw_footer(f, chunks[2]);

    // Draw help overlay if needed
    if app.show_help {
        draw_help_overlay(f, size);
    }
}

/// Draw the header with tabs
fn draw_header(f: &mut Frame, app: &DashboardApp, area: Rect) {
    let titles = vec!["Overview", "Upstreams", "Traffic", "Logs"];
    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Prism Dashboard "),
        )
        .select(app.current_tab)
        .style(Style::default().fg(Color::White))
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(tabs, area);
}

/// Draw the footer
fn draw_footer(f: &mut Frame, area: Rect) {
    let footer = Paragraph::new(Line::from(vec![
        Span::raw(" "),
        Span::styled("Tab", Style::default().fg(Color::Cyan)),
        Span::raw(": Switch tabs  "),
        Span::styled("q", Style::default().fg(Color::Cyan)),
        Span::raw(": Quit  "),
        Span::styled("?", Style::default().fg(Color::Cyan)),
        Span::raw(": Help"),
    ]))
    .style(Style::default().fg(Color::DarkGray));
    f.render_widget(footer, area);
}

/// Draw the overview tab
fn draw_overview(f: &mut Frame, app: &DashboardApp, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // Stats row
            Constraint::Min(10),   // Charts
            Constraint::Length(6), // Gauges
        ])
        .split(area);

    // Stats row
    draw_stats_row(f, app, chunks[0]);

    // Charts
    draw_charts(f, app, chunks[1]);

    // Gauges
    draw_gauges(f, app, chunks[2]);
}

/// Draw statistics row
fn draw_stats_row(f: &mut Frame, app: &DashboardApp, area: Rect) {
    let metrics = &app.metrics;
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
        ])
        .split(area);

    let total = metrics
        .total_requests
        .load(std::sync::atomic::Ordering::Relaxed);
    let rps = metrics
        .requests_per_second
        .load(std::sync::atomic::Ordering::Relaxed);
    let active = metrics
        .active_connections
        .load(std::sync::atomic::Ordering::Relaxed);
    let avg_latency = metrics.average_latency_ms();
    let error_rate = metrics.error_rate();

    let stat_style = Style::default().fg(Color::White);
    let value_style = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD);

    let stats = [
        ("Total Requests", format!("{}", total)),
        ("Requests/sec", format!("{}", rps)),
        ("Active Conns", format!("{}", active)),
        ("Avg Latency", format!("{:.2}ms", avg_latency)),
        ("Error Rate", format!("{:.2}%", error_rate)),
    ];

    for (i, (label, value)) in stats.iter().enumerate() {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" {} ", label));
        let inner = block.inner(chunks[i]);
        f.render_widget(block, chunks[i]);

        let text = Paragraph::new(Line::from(vec![Span::styled(value, value_style)]))
            .style(stat_style)
            .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(text, inner);
    }
}

/// Draw charts
fn draw_charts(f: &mut Frame, app: &DashboardApp, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // RPS Chart
    let rps_data = app.metrics.get_rps_history();
    draw_sparkline_chart(f, chunks[0], " Requests/sec ", &rps_data, Color::Green);

    // Latency Chart
    let latency_data = app.metrics.get_latency_history();
    draw_sparkline_chart(f, chunks[1], " Latency (ms) ", &latency_data, Color::Yellow);
}

/// Draw a sparkline chart
fn draw_sparkline_chart(f: &mut Frame, area: Rect, title: &str, data: &[f64], color: Color) {
    let block = Block::default().borders(Borders::ALL).title(title);
    let inner = block.inner(area);
    f.render_widget(block, area);

    if data.is_empty() {
        let empty = Paragraph::new("No data yet")
            .style(Style::default().fg(Color::DarkGray))
            .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(empty, inner);
        return;
    }

    let max = data.iter().cloned().fold(f64::MIN, f64::max).max(1.0);
    let normalized: Vec<u64> = data.iter().map(|v| ((v / max) * 100.0) as u64).collect();

    let sparkline = Sparkline::default()
        .data(&normalized)
        .style(Style::default().fg(color));
    f.render_widget(sparkline, inner);
}

/// Draw gauges
fn draw_gauges(f: &mut Frame, app: &DashboardApp, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(area);

    let metrics = &app.metrics;

    // Success rate gauge
    let total = metrics
        .total_requests
        .load(std::sync::atomic::Ordering::Relaxed);
    let success = metrics
        .successful_requests
        .load(std::sync::atomic::Ordering::Relaxed);
    let success_rate = if total > 0 {
        (success as f64 / total as f64) * 100.0
    } else {
        100.0
    };
    draw_gauge(f, chunks[0], " Success Rate ", success_rate, Color::Green);

    // Uptime
    let uptime_text = app.uptime();
    let uptime_block = Block::default().borders(Borders::ALL).title(" Uptime ");
    let inner = uptime_block.inner(chunks[1]);
    f.render_widget(uptime_block, chunks[1]);
    let uptime_para = Paragraph::new(uptime_text)
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(ratatui::layout::Alignment::Center);
    f.render_widget(uptime_para, inner);

    // Bytes in
    let bytes_in = metrics.bytes_in.load(std::sync::atomic::Ordering::Relaxed);
    let bytes_in_text = DashboardMetrics::format_bytes(bytes_in);
    let bytes_in_block = Block::default().borders(Borders::ALL).title(" Bytes In ");
    let inner = bytes_in_block.inner(chunks[2]);
    f.render_widget(bytes_in_block, chunks[2]);
    let bytes_para = Paragraph::new(bytes_in_text)
        .style(
            Style::default()
                .fg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(ratatui::layout::Alignment::Center);
    f.render_widget(bytes_para, inner);

    // Bytes out
    let bytes_out = metrics.bytes_out.load(std::sync::atomic::Ordering::Relaxed);
    let bytes_out_text = DashboardMetrics::format_bytes(bytes_out);
    let bytes_out_block = Block::default().borders(Borders::ALL).title(" Bytes Out ");
    let inner = bytes_out_block.inner(chunks[3]);
    f.render_widget(bytes_out_block, chunks[3]);
    let bytes_para = Paragraph::new(bytes_out_text)
        .style(
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(ratatui::layout::Alignment::Center);
    f.render_widget(bytes_para, inner);
}

/// Draw a gauge
fn draw_gauge(f: &mut Frame, area: Rect, title: &str, percent: f64, color: Color) {
    let gauge = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title(title))
        .gauge_style(Style::default().fg(color))
        .percent(percent as u16)
        .label(format!("{:.1}%", percent));
    f.render_widget(gauge, area);
}

/// Draw upstreams tab
fn draw_upstreams(f: &mut Frame, app: &DashboardApp, area: Rect) {
    let upstreams = app.metrics.upstreams.read();

    if upstreams.is_empty() {
        let empty = Paragraph::new("No upstream servers configured")
            .style(Style::default().fg(Color::DarkGray))
            .alignment(ratatui::layout::Alignment::Center)
            .block(Block::default().borders(Borders::ALL).title(" Upstreams "));
        f.render_widget(empty, area);
        return;
    }

    let header = Row::new(vec![
        "Name",
        "Status",
        "Circuit",
        "Response Time",
        "Requests",
        "Active",
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = upstreams
        .iter()
        .map(|u| {
            let status_style = if u.healthy {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::Red)
            };
            let _circuit_style = match u.circuit_state {
                CircuitState::Closed => Style::default().fg(Color::Green),
                CircuitState::Open => Style::default().fg(Color::Red),
                CircuitState::HalfOpen => Style::default().fg(Color::Yellow),
            };
            Row::new(vec![
                u.name.clone(),
                if u.healthy { "Healthy" } else { "Unhealthy" }.to_string(),
                u.circuit_state.to_string(),
                format!("{:.2}ms", u.last_response_time.as_secs_f64() * 1000.0),
                format!("{}", u.total_requests),
                format!("{}", u.active_connections),
            ])
            .style(status_style)
        })
        .collect();

    let widths = [
        Constraint::Percentage(25),
        Constraint::Percentage(15),
        Constraint::Percentage(15),
        Constraint::Percentage(15),
        Constraint::Percentage(15),
        Constraint::Percentage(15),
    ];

    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Upstream Servers "),
    );

    f.render_widget(table, area);
}

/// Draw traffic tab
fn draw_traffic(f: &mut Frame, app: &DashboardApp, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Connection history
    let conn_data = app.metrics.get_connections_history();
    draw_line_chart(
        f,
        chunks[0],
        " Active Connections ",
        &conn_data,
        Color::Cyan,
    );

    // Error rate history
    let error_data = app.metrics.get_error_rate_history();
    draw_line_chart(f, chunks[1], " Error Rate (%) ", &error_data, Color::Red);
}

/// Draw a line chart
fn draw_line_chart(f: &mut Frame, area: Rect, title: &str, data: &[f64], color: Color) {
    let block = Block::default().borders(Borders::ALL).title(title);

    if data.is_empty() {
        let empty = Paragraph::new("No data yet")
            .style(Style::default().fg(Color::DarkGray))
            .alignment(ratatui::layout::Alignment::Center)
            .block(block);
        f.render_widget(empty, area);
        return;
    }

    let points: Vec<(f64, f64)> = data
        .iter()
        .enumerate()
        .map(|(i, &v)| (i as f64, v))
        .collect();

    let max_y = data.iter().cloned().fold(f64::MIN, f64::max).max(1.0);
    let max_x = data.len() as f64;

    let datasets = vec![Dataset::default()
        .marker(symbols::Marker::Braille)
        .style(Style::default().fg(color))
        .graph_type(GraphType::Line)
        .data(&points)];

    let x_labels: Vec<Span> = vec![];
    let y_labels: Vec<Span> = vec![
        Span::raw("0"),
        Span::raw(format!("{:.0}", max_y / 2.0)),
        Span::raw(format!("{:.0}", max_y)),
    ];

    let chart = Chart::new(datasets)
        .block(block)
        .x_axis(
            Axis::default()
                .style(Style::default().fg(Color::Gray))
                .bounds([0.0, max_x])
                .labels(x_labels),
        )
        .y_axis(
            Axis::default()
                .style(Style::default().fg(Color::Gray))
                .bounds([0.0, max_y * 1.1])
                .labels(y_labels),
        );

    f.render_widget(chart, area);
}

/// Draw logs tab
fn draw_logs(f: &mut Frame, app: &DashboardApp, area: Rect) {
    let logs = app.metrics.recent_logs.read();

    if logs.is_empty() {
        let empty = Paragraph::new("No logs yet")
            .style(Style::default().fg(Color::DarkGray))
            .alignment(ratatui::layout::Alignment::Center)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Recent Logs "),
            );
        f.render_widget(empty, area);
        return;
    }

    let items: Vec<ListItem> = logs
        .iter()
        .map(|log| {
            let style = match log.level {
                LogLevel::Debug => Style::default().fg(Color::DarkGray),
                LogLevel::Info => Style::default().fg(Color::White),
                LogLevel::Warn => Style::default().fg(Color::Yellow),
                LogLevel::Error => Style::default().fg(Color::Red),
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("[{}] ", log.level), style),
                Span::raw(&log.message),
            ]))
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Recent Logs "),
    );

    f.render_widget(list, area);
}

/// Draw help overlay
fn draw_help_overlay(f: &mut Frame, area: Rect) {
    let help_area = centered_rect(60, 60, area);

    let help_text = vec![
        Line::from(Span::styled(
            "Keyboard Shortcuts",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("Tab / →", Style::default().fg(Color::Yellow)),
            Span::raw("  Next tab"),
        ]),
        Line::from(vec![
            Span::styled("Shift+Tab / ←", Style::default().fg(Color::Yellow)),
            Span::raw("  Previous tab"),
        ]),
        Line::from(vec![
            Span::styled("↑ / ↓", Style::default().fg(Color::Yellow)),
            Span::raw("  Navigate lists"),
        ]),
        Line::from(vec![
            Span::styled("PgUp / PgDn", Style::default().fg(Color::Yellow)),
            Span::raw("  Scroll logs"),
        ]),
        Line::from(vec![
            Span::styled("q / Esc", Style::default().fg(Color::Yellow)),
            Span::raw("  Quit"),
        ]),
        Line::from(vec![
            Span::styled("?", Style::default().fg(Color::Yellow)),
            Span::raw("  Toggle help"),
        ]),
    ];

    let help = Paragraph::new(help_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Help ")
                .style(Style::default().bg(Color::Black)),
        )
        .wrap(Wrap { trim: true });

    f.render_widget(ratatui::widgets::Clear, help_area);
    f.render_widget(help, help_area);
}

/// Create a centered rectangle
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

/// Start the dashboard in a separate task
pub async fn run_dashboard(metrics: Arc<DashboardMetrics>) -> io::Result<()> {
    tokio::task::spawn_blocking(move || {
        let mut dashboard = Dashboard::new(metrics)?;
        dashboard.run()
    })
    .await
    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
}
