use std::io::{stdout, Stdout};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use dns_filter_storage::QueryStore;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{self, Event, KeyCode};
use ratatui::crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::crossterm::ExecutableCommand;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use ratatui::{Frame, Terminal};

fn open_db(db_path: &Option<PathBuf>) -> anyhow::Result<QueryStore> {
    match db_path {
        Some(path) => QueryStore::open(path).context("failed to open query log database"),
        None => QueryStore::in_memory().context("failed to create in-memory store"),
    }
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    db_path: Option<PathBuf>,
) -> anyhow::Result<()> {
    let store = open_db(&db_path)?;
    let mut last_tick = std::time::Instant::now();
    let tick_rate = Duration::from_secs(1);

    loop {
        terminal.draw(|f| ui(f, &store))?;

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') || key.code == KeyCode::Esc {
                    break;
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = std::time::Instant::now();
        }
    }

    Ok(())
}

fn ui(f: &mut Frame, store: &QueryStore) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Min(10),
            Constraint::Length(1),
        ])
        .split(area);

    // Title
    let title = Paragraph::new(Line::from(vec![Span::styled(
        "Ad-Wolf DNS Filter",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )]))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    // Stats
    let stats = store.stats_since(0).unwrap_or_default();
    let stats_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(chunks[1]);

    let stat_widgets = [
        ("Total", stats.total, Color::White),
        ("Blocked", stats.blocked, Color::Red),
        ("Allowed", stats.allowed, Color::Green),
        ("Cached", stats.cached, Color::Magenta),
    ];

    for ((label, value, color), chunk) in stat_widgets.iter().zip(stats_chunks.iter()) {
        let text = format!("{}\n{}", label, value);
        let p = Paragraph::new(text)
            .style(Style::default().fg(*color))
            .alignment(ratatui::layout::Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(p, *chunk);
    }

    // Top blocked + Recent queries
    let bottom_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(chunks[2]);

    // Top blocked
    let top_blocked = store.top_blocked(10).unwrap_or_default();
    let blocked_rows: Vec<Row> = top_blocked
        .iter()
        .enumerate()
        .map(|(i, (domain, count))| {
            Row::new(vec![
                Cell::from(format!("{}.", i + 1)),
                Cell::from(domain.clone()),
                Cell::from(format!("{}", count)),
            ])
        })
        .collect();

    let blocked_table = Table::new(
        blocked_rows,
        [
            Constraint::Length(4),
            Constraint::Min(15),
            Constraint::Length(8),
        ],
    )
    .header(
        Row::new(vec!["#", "Domain", "Count"]).style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .title(" Top Blocked ")
            .borders(Borders::ALL),
    );
    f.render_widget(blocked_table, bottom_chunks[0]);

    // Recent queries
    let recent = store.recent(15).unwrap_or_default();
    let recent_rows: Vec<Row> = recent
        .iter()
        .map(|e| {
            let action_color = match e.action.as_str() {
                "blocked" => Color::Red,
                "allowed" => Color::Green,
                "cached" => Color::Magenta,
                _ => Color::Yellow,
            };
            Row::new(vec![
                Cell::from(timestamp_str(e.timestamp)),
                Cell::from(e.domain.clone()),
                Cell::from(e.query_type.clone()),
                Cell::from(Span::styled(
                    e.action.clone(),
                    Style::default().fg(action_color),
                )),
            ])
        })
        .collect();

    let recent_table = Table::new(
        recent_rows,
        [
            Constraint::Length(10),
            Constraint::Min(15),
            Constraint::Length(6),
            Constraint::Length(10),
        ],
    )
    .header(
        Row::new(vec!["Time", "Domain", "Type", "Action"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .title(" Recent Queries ")
            .borders(Borders::ALL),
    );
    f.render_widget(recent_table, bottom_chunks[1]);

    // Footer
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(
            "[Q]",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("uit "),
    ]))
    .style(Style::default().fg(Color::DarkGray))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(footer, chunks[3]);
}

fn timestamp_str(ts: i64) -> String {
    let secs = ts as u64;
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    let s = secs % 60;
    format!("{:02}:{:02}:{:02}", h, m, s)
}

/// Run the TUI dashboard
pub fn run(db_path: Option<PathBuf>) -> anyhow::Result<()> {
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;

    let result = run_app(&mut terminal, db_path);

    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;
    result
}
