mod local_device_screen;
mod node_details_screen;
mod node_list_screen;

use crate::TopologyDatabase;
use crate::topology_manager::{StateLocal, StateRemote};
use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use local_device_screen::LocalDeviceScreen;
use node_details_screen::NodeDetailsScreen;
use node_list_screen::NodeListScreen;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Alignment;
use ratatui::prelude::{Line, Span};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Paragraph, Row, Wrap};
use std::fmt::{Debug, Display};
use std::io::Stdout;
use std::sync::Arc;
use std::time::Duration;

///////////////////////////////////////////////////////////////////////////
const REFRESH_INTERVAL: Duration = Duration::from_millis(500);

const STYLE_BG_TEXT: Style = Style::new().add_modifier(Modifier::DIM);
const STYLE_HIGHLIGHT: Style = Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD);
const STYLE_SELECTION: Style = Style::new()
    .bg(Color::Blue)
    .fg(Color::White)
    .add_modifier(Modifier::BOLD);

///////////////////////////////////////////////////////////////////////////
pub struct TopologyCli {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    event_stream: EventStream,
    node_list_screen: NodeListScreen,
    nested_screen: Option<NestedScreen>,
}

enum NestedScreen {
    NodeDetails(NodeDetailsScreen),
    LocalInfo(LocalDeviceScreen),
}

enum Navigation {
    Stay,
    Back,
    GoTo(NestedScreen),
}

impl TopologyCli {
    ///////////////////////////////////////////////////////////////////////////
    pub async fn start(db: Arc<TopologyDatabase>) {
        if let Err(e) = Self::run_event_loop(db).await {
            tracing::error!(%e, "topology_cli failed");
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    async fn run_event_loop(db: Arc<TopologyDatabase>) -> anyhow::Result<()> {
        let mut this = Self {
            terminal: Terminal::new(CrosstermBackend::new(std::io::stdout()))?,
            event_stream: EventStream::new(),
            node_list_screen: NodeListScreen {
                db,
                table_state: Default::default(),
            },
            nested_screen: None,
        };

        enable_raw_mode()?;
        execute!(this.terminal.backend_mut(), EnterAlternateScreen)?;

        loop {
            this.render().await?;

            if !this.handle_input_events().await? {
                break;
            }
        }
        Ok(())
    }

    ///////////////////////////////////////////////////////////////////////////
    async fn render(&mut self) -> anyhow::Result<()> {
        self.terminal.autoresize()?;

        let mut frame = self.terminal.get_frame();
        match self.nested_screen.as_mut() {
            Some(NestedScreen::NodeDetails(screen)) => screen.render(&mut frame).await,
            Some(NestedScreen::LocalInfo(screen)) => screen.render(&mut frame).await,
            None => self.node_list_screen.render(&mut frame).await,
        }

        self.terminal.apply_buffer()?;
        Ok(())
    }

    ///////////////////////////////////////////////////////////////////////////
    async fn handle_input_events(&mut self) -> anyhow::Result<bool> {
        let event_future = futures::StreamExt::next(&mut self.event_stream);
        let event_timeout = tokio::time::timeout(REFRESH_INTERVAL, event_future);

        let Ok(event) = event_timeout.await else {
            return Ok(true); // timeout, continue
        };
        let Some(event) = event else {
            return Ok(false); // stream ended, exit
        };
        let Event::Key(event) = event? else {
            return Ok(true); // non-key event, continue
        };

        if event.kind != KeyEventKind::Press {
            return Ok(true);
        }
        if matches!(event.code, KeyCode::Char('q') | KeyCode::Char('Q')) {
            return Ok(false);
        }

        let navigation = match self.nested_screen.as_mut() {
            Some(NestedScreen::NodeDetails(screen)) => screen.handle_key_event(event),
            Some(NestedScreen::LocalInfo(screen)) => screen.handle_key_event(event),
            None => self.node_list_screen.handle_key_event(event).await,
        };

        match navigation {
            Navigation::Stay => {}
            Navigation::Back => {
                self.nested_screen = None;
            }
            Navigation::GoTo(e) => {
                self.nested_screen = Some(e);
            }
        }
        Ok(true)
    }
}

impl Drop for TopologyCli {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
    }
}

///////////////////////////////////////////////////////////////////////////
// Formatting helpers
///////////////////////////////////////////////////////////////////////////
fn or_placeholder<T: Display>(value: Option<&T>) -> Span<'static> {
    value.map_or(Span::raw("-"), |e| Span::raw(e.to_string()))
}

fn or_placeholder_debug<T: Debug>(value: Option<&T>) -> Span<'static> {
    value.map_or(Span::raw("-"), |e| Span::raw(format!("{e:?}")))
}

fn format_phy_rate(phy_rate: Option<u64>) -> Span<'static> {
    let Some(phy_rate) = phy_rate else {
        return Span::raw("-");
    };

    let mbps = phy_rate / 1_000_000;
    if mbps < 1_000 {
        return Span::raw(format!("{mbps} Mbps"));
    }

    let gbps_whole = mbps / 1_000;
    let gbps_fract = (mbps % 1_000) / 100;
    if gbps_whole < 10 && gbps_fract > 0 {
        return Span::raw(format!("{gbps_whole}.{gbps_fract} Gbps"));
    }

    Span::raw(format!("{gbps_whole} Gbps"))
}

fn state_local_name(state: StateLocal) -> &'static str {
    match state {
        StateLocal::Idle => "Idle",
        StateLocal::ConvergingLocal(_) => "ConvergingLocal",
        StateLocal::ConvergedLocal => "ConvergedLocal",
    }
}

fn state_remote_name(state: StateRemote) -> &'static str {
    match state {
        StateRemote::Idle => "Idle",
        StateRemote::ConvergingRemote(_) => "ConvergingRemote",
        StateRemote::ConvergedRemote => "ConvergedRemote",
    }
}

///////////////////////////////////////////////////////////////////////////
// Widget builders
///////////////////////////////////////////////////////////////////////////
fn build_bordered_block<'a>(title: impl Into<Line<'a>>) -> Block<'a> {
    Block::default().title(title).borders(Borders::ALL)
}

fn build_placeholder_paragraph<'a>(message: &'a str, block: Block<'static>) -> Paragraph<'a> {
    let line = Line::from(Span::styled(message, STYLE_BG_TEXT));

    Paragraph::new(line)
        .block(block)
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true })
}

fn build_table_header_row(columns: &[&'static str]) -> Row<'static> {
    Row::new(columns.iter().copied().map(Span::raw)).style(STYLE_HIGHLIGHT)
}

fn build_hotkeys_line<'a>(hints: &[(&'a str, &'a str)]) -> Line<'a> {
    let mut spans = Vec::with_capacity(hints.len() * 4);
    let mut separator = "";

    for &(key, description) in hints {
        spans.push(Span::raw(separator));
        spans.push(Span::styled(key, STYLE_HIGHLIGHT));
        spans.push(Span::raw(" "));
        spans.push(Span::raw(description));
        separator = "    ";
    }
    Line::from(spans)
}
