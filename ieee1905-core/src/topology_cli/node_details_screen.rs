use super::{
    Navigation, STYLE_BG_TEXT, STYLE_SELECTION, build_bordered_block, build_hotkeys_line,
    build_placeholder_paragraph, build_table_header_row, format_phy_rate, or_placeholder,
    state_local_name, state_remote_name,
};
use crate::TopologyDatabase;
use crate::cmdu_codec::IEEE1905Neighbor;
use crate::topology_manager::Ieee1905Node;
use crossterm::event::{KeyCode, KeyEvent};
use pnet::datalink::MacAddr;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::prelude::{Line, Span};
use ratatui::widgets::{Block, Borders, HighlightSpacing, Paragraph, Row, Table, TableState};
use std::sync::Arc;

///////////////////////////////////////////////////////////////////////////
pub struct NodeDetailsScreen {
    pub db: Arc<TopologyDatabase>,
    pub node_al_mac: MacAddr,
    pub tabs_table_state: TableState,
    pub content_table_state: TableState,
}

impl NodeDetailsScreen {
    ///////////////////////////////////////////////////////////////////////////
    pub fn handle_key_event(&mut self, event: KeyEvent) -> Navigation {
        match event.code {
            KeyCode::Esc => return Navigation::Back,
            KeyCode::Left => self.select_tab(self.selected_tab_index().saturating_sub(1)),
            KeyCode::Right => self.select_tab(self.selected_tab_index() + 1),
            KeyCode::Up => self.content_table_state.select_previous(),
            KeyCode::Down => self.content_table_state.select_next(),
            KeyCode::Home => self.content_table_state.select_first(),
            KeyCode::End => self.content_table_state.select_last(),
            _ => {}
        }
        Navigation::Stay
    }

    ///////////////////////////////////////////////////////////////////////////
    fn selected_tab_index(&self) -> usize {
        self.tabs_table_state.selected().unwrap_or_default()
    }

    ///////////////////////////////////////////////////////////////////////////
    fn selected_tab(&self) -> NodeDetailsTab {
        NodeDetailsTab::ALL
            .get(self.selected_tab_index())
            .copied()
            .unwrap_or_default()
    }

    ///////////////////////////////////////////////////////////////////////////
    fn select_tab(&mut self, index: usize) {
        let index = index.min(NodeDetailsTab::ALL.len() - 1);
        if self.tabs_table_state.selected() == Some(index) {
            return;
        }
        self.tabs_table_state.select(Some(index));
        self.content_table_state = TableState::new().with_selected(0);
    }

    ///////////////////////////////////////////////////////////////////////////
    pub async fn render(&mut self, frame: &mut Frame<'_>) {
        let [info_area, body_area, hotkeys_area] = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(4),
                Constraint::Min(5),
                Constraint::Length(3),
            ])
            .areas(frame.area());

        let node = self.db.get_device(self.node_al_mac).await;
        let Some(node) = node else {
            self.render_missing_info_panel(frame, info_area.union(body_area));
            self.render_hotkeys_panel(frame, hotkeys_area);
            return;
        };

        let [tabs_area, content_area] = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(30), Constraint::Min(20)])
            .areas(body_area);

        match self.selected_tab() {
            NodeDetailsTab::Interfaces => {
                self.render_interfaces_table(frame, content_area, &node);
            }
            NodeDetailsTab::Ieee1905Neighbors => {
                self.render_ieee1905_neighbors_table(frame, content_area, &node);
            }
            NodeDetailsTab::NonIeee1905Neighbors => {
                self.render_non_ieee1905_neighbors_table(frame, content_area, &node);
            }
        }

        self.render_info_panel(frame, info_area, &node);
        self.render_tabs_panel(frame, tabs_area);
        self.render_hotkeys_panel(frame, hotkeys_area);
    }

    ///////////////////////////////////////////////////////////////////////////
    fn render_info_panel(&self, frame: &mut Frame<'_>, area: Rect, node: &Ieee1905Node) {
        let metadata = &node.metadata;
        let device = &node.device_data;

        let lines = vec![
            Line::from(vec![
                Span::styled("AL MAC: ", STYLE_BG_TEXT),
                Span::raw(device.al_mac.to_string()),
                Span::styled("  State: ", STYLE_BG_TEXT),
                Span::raw(state_local_name(metadata.node_state_local)),
                Span::styled(" / ", STYLE_BG_TEXT),
                Span::raw(state_remote_name(metadata.node_state_remote)),
                Span::styled("  Last seen: ", STYLE_BG_TEXT),
                Span::raw(format!("{}s ago", metadata.last_seen.elapsed().as_secs())),
                Span::styled("  Last update: ", STYLE_BG_TEXT),
                Span::raw(format!("{:?}", metadata.last_update)),
            ]),
            Line::from(vec![
                Span::styled("Profile: ", STYLE_BG_TEXT),
                Span::raw(format!("{:?}", device.ieee1905_profile_version)),
                Span::styled("  Fragmentation: ", STYLE_BG_TEXT),
                Span::raw(format!("{:?}", device.supported_fragmentation)),
                Span::styled("  Registrar: ", STYLE_BG_TEXT),
                or_placeholder(device.registrar.as_ref()),
            ]),
        ];

        let paragraph = Paragraph::new(lines).block(build_bordered_block("NODE"));
        frame.render_widget(paragraph, area);
    }

    ///////////////////////////////////////////////////////////////////////////
    fn render_tabs_panel(&mut self, frame: &mut Frame<'_>, area: Rect) {
        let rows = NodeDetailsTab::ALL.map(|tab| Row::new([Span::raw(tab.title())]));

        let table = Table::new(rows, [Constraint::Min(1)])
            .block(build_bordered_block("TABS"))
            .row_highlight_style(STYLE_SELECTION)
            .highlight_symbol("▶ ")
            .highlight_spacing(HighlightSpacing::Always);

        frame.render_stateful_widget(table, area, &mut self.tabs_table_state);
    }

    ///////////////////////////////////////////////////////////////////////////
    fn render_interfaces_table(&mut self, frame: &mut Frame<'_>, area: Rect, node: &Ieee1905Node) {
        let mut rows = Vec::new();

        let interfaces = node.device_data.local_interface_list.as_deref();
        for interface in interfaces.unwrap_or_default() {
            rows.push(Row::new([
                Span::raw(interface.mac.to_string()),
                or_placeholder(interface.media_type_extra.as_wifi().map(|e| &e.bssid)),
                or_placeholder(interface.bridging_tuple.as_ref()),
                format_phy_rate(interface.phy_rate),
                or_placeholder(interface.signal_strength_dbm.as_ref()),
                or_placeholder(interface.link_availability.as_ref()),
                Span::raw(interface.media_type.to_string()),
            ]));
        }

        let table_headers = [
            "MAC",
            "BSSID",
            "Bridging",
            "PHY Rate",
            "RSSI",
            "Availability",
            "Media Type",
        ];

        let table_constraints = [
            Constraint::Length(17),
            Constraint::Length(17),
            Constraint::Fill(1),
            Constraint::Fill(1),
            Constraint::Fill(1),
            Constraint::Fill(1),
            Constraint::Fill(3),
        ];

        let tab = NodeDetailsTab::Interfaces;
        self.render_content_panel(frame, area, tab, rows, &table_headers, &table_constraints);
    }

    ///////////////////////////////////////////////////////////////////////////
    fn render_ieee1905_neighbors_table(
        &mut self,
        frame: &mut Frame<'_>,
        area: Rect,
        node: &Ieee1905Node,
    ) {
        let mut rows = Vec::new();

        let device = &node.device_data;
        for interface in device.local_interface_list.as_deref().unwrap_or_default() {
            for neighbor in interface.ieee1905_neighbors.iter().flatten() {
                let bridged = neighbor.neighbor_flags & IEEE1905Neighbor::FLAG_BRIDGED != 0;
                let tx = device
                    .link_metric_tx
                    .iter()
                    .filter(|e| e.neighbour_al_mac == neighbor.neighbor_al_mac)
                    .flat_map(|e| e.interface_pairs.iter())
                    .find(|e| e.receiver_interface_mac == interface.mac);

                rows.push(Row::new([
                    Span::raw(interface.mac.to_string()),
                    Span::raw(neighbor.neighbor_al_mac.to_string()),
                    Span::raw(match bridged {
                        true => "yes",
                        false => "no",
                    }),
                    or_placeholder(tx.map(|e| &e.neighbour_interface_mac)),
                    Span::raw(interface.media_type.to_string()),
                ]));
            }
        }

        let table_headers = [
            "Local Interface",
            "Neighbor AL MAC",
            "Bridged",
            "Neighbor Interface",
            "Media Type",
        ];

        let table_constraints = [
            Constraint::Length(17),
            Constraint::Length(17),
            Constraint::Fill(1),
            Constraint::Fill(1),
            Constraint::Fill(3),
        ];

        let tab = NodeDetailsTab::Ieee1905Neighbors;
        self.render_content_panel(frame, area, tab, rows, &table_headers, &table_constraints);
    }

    ///////////////////////////////////////////////////////////////////////////
    fn render_non_ieee1905_neighbors_table(
        &mut self,
        frame: &mut Frame<'_>,
        area: Rect,
        node: &Ieee1905Node,
    ) {
        let mut rows = Vec::new();

        let interfaces = node.device_data.local_interface_list.as_deref();
        for interface in interfaces.unwrap_or_default() {
            for neighbor_mac in interface.non_ieee1905_neighbors.iter().flatten() {
                rows.push(Row::new([
                    Span::raw(interface.mac.to_string()),
                    Span::raw(neighbor_mac.to_string()),
                    Span::raw(interface.media_type.to_string()),
                ]));
            }
        }

        let table_headers = ["Local Interface", "Neighbor MAC", "Media Type"];
        let table_constraints = [
            Constraint::Length(17),
            Constraint::Length(17),
            Constraint::Fill(1),
        ];

        let tab = NodeDetailsTab::NonIeee1905Neighbors;
        self.render_content_panel(frame, area, tab, rows, &table_headers, &table_constraints);
    }

    ///////////////////////////////////////////////////////////////////////////
    fn render_content_panel(
        &mut self,
        frame: &mut Frame<'_>,
        area: Rect,
        tab: NodeDetailsTab,
        rows: Vec<Row<'static>>,
        headers: &[&'static str],
        constraints: &[Constraint],
    ) {
        let block = build_bordered_block(format!("{} ({})", tab.title(), rows.len()));

        if rows.is_empty() {
            let paragraph = build_placeholder_paragraph(tab.empty_message(), block);
            return frame.render_widget(paragraph, area);
        }

        let table = Table::new(rows, constraints.iter().copied())
            .header(build_table_header_row(headers))
            .block(block)
            .row_highlight_style(STYLE_SELECTION)
            .highlight_symbol("▶ ")
            .highlight_spacing(HighlightSpacing::Always)
            .column_spacing(3);

        frame.render_stateful_widget(table, area, &mut self.content_table_state);
    }

    ///////////////////////////////////////////////////////////////////////////
    fn render_missing_info_panel(&self, frame: &mut Frame<'_>, area: Rect) {
        let lines = vec![
            Line::from(vec![
                Span::styled("AL MAC: ", STYLE_BG_TEXT),
                Span::raw(self.node_al_mac.to_string()),
            ]),
            Line::from(vec![Span::styled(
                "This node is no longer present in the topology database",
                STYLE_BG_TEXT,
            )])
            .alignment(Alignment::Center),
        ];

        let paragraph = Paragraph::new(lines).block(build_bordered_block("NODE"));
        frame.render_widget(paragraph, area);
    }

    ///////////////////////////////////////////////////////////////////////////
    fn render_hotkeys_panel(&self, frame: &mut Frame<'_>, area: Rect) {
        let line = build_hotkeys_line(&[
            ("←/→", "switch tab"),
            ("↑/↓", "scroll"),
            ("Esc", "back"),
            ("q", "quit"),
        ]);

        let paragraph = Paragraph::new(line).block(Block::default().borders(Borders::ALL));
        frame.render_widget(paragraph, area);
    }
}

///////////////////////////////////////////////////////////////////////////
#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum NodeDetailsTab {
    #[default]
    Interfaces,
    Ieee1905Neighbors,
    NonIeee1905Neighbors,
}

impl NodeDetailsTab {
    const ALL: [NodeDetailsTab; 3] = [
        NodeDetailsTab::Interfaces,
        NodeDetailsTab::Ieee1905Neighbors,
        NodeDetailsTab::NonIeee1905Neighbors,
    ];

    fn title(self) -> &'static str {
        match self {
            NodeDetailsTab::Interfaces => "Interfaces",
            NodeDetailsTab::Ieee1905Neighbors => "1905 Neighbors",
            NodeDetailsTab::NonIeee1905Neighbors => "Non-1905 Neighbors",
        }
    }

    fn empty_message(self) -> &'static str {
        match self {
            NodeDetailsTab::Interfaces => "No interfaces reported",
            NodeDetailsTab::Ieee1905Neighbors => "No IEEE 1905 neighbors reported",
            NodeDetailsTab::NonIeee1905Neighbors => "No non-IEEE 1905 neighbors reported",
        }
    }
}
