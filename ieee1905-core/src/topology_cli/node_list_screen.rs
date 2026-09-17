use super::local_device_screen::LocalDeviceScreen;
use super::node_details_screen::NodeDetailsScreen;
use super::{
    Navigation, NestedScreen, STYLE_BG_TEXT, STYLE_SELECTION, build_bordered_block,
    build_hotkeys_line, build_placeholder_paragraph, build_table_header_row, or_placeholder,
    or_placeholder_debug, state_local_name, state_remote_name,
};
use crate::TopologyDatabase;
use crate::al_sap::AlServiceAccessPoint;
use crossterm::event::{KeyCode, KeyEvent};
use neli::consts::rtnl::Iff;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::prelude::{Line, Span};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Borders, HighlightSpacing, Paragraph, Row, Table, TableState, Wrap};
use std::sync::Arc;

///////////////////////////////////////////////////////////////////////////
pub struct NodeListScreen {
    pub db: Arc<TopologyDatabase>,
    pub table_state: TableState,
}

impl NodeListScreen {
    ///////////////////////////////////////////////////////////////////////////
    pub async fn handle_key_event(&mut self, event: KeyEvent) -> Navigation {
        match event.code {
            KeyCode::Up => self.table_state.select_previous(),
            KeyCode::Down => self.table_state.select_next(),
            KeyCode::Home => self.table_state.select_first(),
            KeyCode::End => self.table_state.select_last(),
            KeyCode::Char('i') | KeyCode::Char('I') => {
                return Navigation::GoTo(NestedScreen::LocalInfo(LocalDeviceScreen {
                    db: self.db.clone(),
                    tabs_table_state: TableState::new().with_selected(0),
                    content_table_state: TableState::new().with_selected(0),
                }));
            }
            KeyCode::Enter => {
                if let Some(index) = self.table_state.selected()
                    && let nodes = self.db.nodes.read().await
                    && let Some((al_mac, _)) = nodes.get_index(index)
                {
                    return Navigation::GoTo(NestedScreen::NodeDetails(NodeDetailsScreen {
                        db: self.db.clone(),
                        node_al_mac: *al_mac,
                        tabs_table_state: TableState::new().with_selected(0),
                        content_table_state: TableState::new().with_selected(0),
                    }));
                }
            }
            _ => {}
        }
        Navigation::Stay
    }

    ///////////////////////////////////////////////////////////////////////////
    pub async fn render(&mut self, frame: &mut Frame<'_>) {
        let [header_area, nodes_area, hotkeys_area] = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(6),
                Constraint::Min(5),
                Constraint::Length(3),
            ])
            .areas(frame.area());

        let [info_area, al_sap_area] = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
            .areas(header_area);

        self.render_info_panel(frame, info_area).await;
        self.render_al_sap_panel(frame, al_sap_area).await;
        self.render_nodes_panel(frame, nodes_area).await;
        self.render_hotkeys_panel(frame, hotkeys_area);
    }

    ///////////////////////////////////////////////////////////////////////////
    async fn render_info_panel(&self, frame: &mut Frame<'_>, area: Rect) {
        let interfaces = self.db.local_interface_list.read().await;
        let interfaces = interfaces.as_deref().unwrap_or_default();

        let mut lines = vec![
            Line::from(vec![
                Span::styled("Local AL MAC: ", STYLE_BG_TEXT),
                Span::raw(self.db.al_mac_address.to_string()),
                Span::styled(" (", STYLE_BG_TEXT),
                Span::raw(&self.db.interface_name),
                Span::styled(")  Mode: ", STYLE_BG_TEXT),
                Span::raw(match self.db.is_passive_mode() {
                    true => "passive",
                    false => "active",
                }),
            ]),
            Line::raw(format!("Interfaces ({}):", interfaces.len())),
        ];

        if interfaces.is_empty() {
            lines.push(Line::from(Span::styled(
                "- no local interfaces available",
                Style::default().fg(Color::DarkGray),
            )));
        }

        for interface in interfaces.iter() {
            let state = match interface.flags.contains(Iff::UP) {
                true => "up",
                false => "down",
            };

            lines.push(Line::from(vec![Span::raw(format!(
                "- {:<20}   {}   {state:<8}   {}",
                interface.name, interface.mac, interface.media_type,
            ))]));
        }

        let paragraph = Paragraph::new(lines).block(build_bordered_block("TOPOLOGY MANAGER"));
        frame.render_widget(paragraph, area);
    }

    ///////////////////////////////////////////////////////////////////////////
    async fn render_al_sap_panel(&self, frame: &mut Frame<'_>, area: Rect) {
        let mut enabled = None;
        let mut service_type = None;

        if let Some(al_sap) = AlServiceAccessPoint::get().await {
            enabled = Some(al_sap.is_enabled());
            service_type = al_sap.service_type();
        }

        let lines = vec![
            Line::from(vec![
                Span::styled("Enabled: ", STYLE_BG_TEXT),
                or_placeholder(enabled.as_ref()),
            ]),
            Line::from(vec![
                Span::styled("Service Type: ", STYLE_BG_TEXT),
                or_placeholder_debug(service_type.as_ref()),
            ]),
        ];

        let paragraph = Paragraph::new(lines)
            .block(build_bordered_block("AL SAP"))
            .wrap(Wrap { trim: true });

        frame.render_widget(paragraph, area);
    }

    ///////////////////////////////////////////////////////////////////////////
    async fn render_nodes_panel(&mut self, frame: &mut Frame<'_>, area: Rect) {
        let mut rows = Vec::new();
        for node in self.db.nodes.read().await.values() {
            let interfaces = node.device_data.local_interface_list.as_deref();
            let interfaces = interfaces.unwrap_or_default();

            let destination_mac = node.device_data.destination_mac;
            let interface = destination_mac
                .and_then(|mac| interfaces.iter().find(|e| e.mac == mac))
                .or_else(|| interfaces.iter().find(|e| e.mac == node.device_data.al_mac))
                .or_else(|| interfaces.first());

            let media_type = interface.map(|e| e.media_type);
            let interface_mac = destination_mac.or_else(|| interface.map(|e| e.mac));

            rows.push(Row::new([
                Span::raw(node.device_data.al_mac.to_string()),
                Span::raw(state_local_name(node.metadata.node_state_local)),
                Span::raw(state_remote_name(node.metadata.node_state_remote)),
                Span::raw(format!(
                    "{}s ago",
                    node.metadata.last_seen.elapsed().as_secs()
                )),
                or_placeholder(destination_mac.as_ref()),
                or_placeholder(node.metadata.lldp_neighbor.as_ref().map(|e| &e.port_id)),
                or_placeholder(interface_mac.as_ref()),
                or_placeholder(media_type.as_ref()),
            ]));
        }

        let block = build_bordered_block(format!("IEEE 1905 DEVICES ({})", rows.len()));
        if rows.is_empty() {
            let paragraph =
                build_placeholder_paragraph("No IEEE 1905 devices discovered yet", block);
            return frame.render_widget(paragraph, area);
        }

        let table_headers = [
            "AL MAC",
            "State Local",
            "State Remote",
            "Last Seen",
            "Destination",
            "LLDP",
            "Interface",
            "Media Type",
        ];

        let table_constraints = [
            Constraint::Length(17),
            Constraint::Length(16),
            Constraint::Length(16),
            Constraint::Length(10),
            Constraint::Length(17),
            Constraint::Length(17),
            Constraint::Length(17),
            Constraint::Fill(1),
        ];

        let table = Table::new(rows, table_constraints)
            .header(build_table_header_row(&table_headers))
            .block(block)
            .row_highlight_style(STYLE_SELECTION)
            .highlight_symbol("▶ ")
            .highlight_spacing(HighlightSpacing::Always)
            .column_spacing(3);

        frame.render_stateful_widget(table, area, &mut self.table_state);
    }

    ///////////////////////////////////////////////////////////////////////////
    fn render_hotkeys_panel(&self, frame: &mut Frame<'_>, area: Rect) {
        let line = build_hotkeys_line(&[
            ("↑/↓", "select node"),
            ("Enter", "node details"),
            ("i", "local device info"),
            ("q", "quit"),
        ]);

        let paragraph = Paragraph::new(line).block(Block::default().borders(Borders::ALL));
        frame.render_widget(paragraph, area);
    }
}
