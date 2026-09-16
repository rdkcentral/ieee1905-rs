use super::{
    Navigation, STYLE_BG_TEXT, STYLE_SELECTION, build_bordered_block, build_hotkeys_line,
    build_placeholder_paragraph, build_table_header_row, format_phy_rate, or_placeholder,
};
use crate::TopologyDatabase;
use crate::cmdu_codec::IEEE1905Neighbor;
use crate::topology_manager::Ieee1905LocalInterface;
use crossterm::event::{KeyCode, KeyEvent};
use neli::consts::rtnl::Iff;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::prelude::{Line, Span};
use ratatui::widgets::{Block, Borders, HighlightSpacing, Paragraph, Row, Table, TableState};
use std::sync::Arc;

///////////////////////////////////////////////////////////////////////////
pub struct LocalDeviceScreen {
    pub db: Arc<TopologyDatabase>,
    pub tabs_table_state: TableState,
    pub content_table_state: TableState,
}

impl LocalDeviceScreen {
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
    fn selected_tab(&self) -> LocalDeviceTab {
        LocalDeviceTab::ALL
            .get(self.selected_tab_index())
            .copied()
            .unwrap_or_default()
    }

    ///////////////////////////////////////////////////////////////////////////
    fn select_tab(&mut self, index: usize) {
        let index = index.min(LocalDeviceTab::ALL.len() - 1);
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
                Constraint::Length(3),
                Constraint::Min(5),
                Constraint::Length(3),
            ])
            .areas(frame.area());

        let [tabs_area, content_area] = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(30), Constraint::Min(20)])
            .areas(body_area);

        let if_list = {
            let lock = self.db.local_interface_list.read().await;
            lock.iter().flatten().cloned().collect::<Vec<_>>()
        };

        match self.selected_tab() {
            LocalDeviceTab::Interfaces => {
                self.render_interfaces_table(frame, content_area, &if_list);
            }
            LocalDeviceTab::Ieee1905Neighbors => {
                self.render_ieee1905_neighbors_table(frame, content_area, &if_list);
            }
            LocalDeviceTab::NonIeee1905Neighbors => {
                self.render_non_ieee1905_neighbors_table(frame, content_area, &if_list);
            }
        }

        self.render_info_panel(frame, info_area).await;
        self.render_tabs_panel(frame, tabs_area);
        self.render_hotkeys_panel(frame, hotkeys_area);
    }

    ///////////////////////////////////////////////////////////////////////////
    async fn render_info_panel(&self, frame: &mut Frame<'_>, area: Rect) {
        let line = Line::from(vec![
            Span::styled("AL MAC: ", STYLE_BG_TEXT),
            Span::raw(self.db.al_mac_address.to_string()),
            Span::styled("  (", STYLE_BG_TEXT),
            Span::raw(&self.db.interface_name),
            Span::styled(")  Mode: ", STYLE_BG_TEXT),
            Span::raw(match self.db.is_passive_mode() {
                true => "passive",
                false => "active",
            }),
        ]);

        let paragraph = Paragraph::new(line).block(build_bordered_block("LOCAL DEVICE"));
        frame.render_widget(paragraph, area);
    }

    ///////////////////////////////////////////////////////////////////////////
    fn render_tabs_panel(&mut self, frame: &mut Frame<'_>, area: Rect) {
        let rows = LocalDeviceTab::ALL.map(|tab| Row::new([Span::raw(tab.title())]));

        let table = Table::new(rows, [Constraint::Min(1)])
            .block(build_bordered_block("TABS"))
            .row_highlight_style(STYLE_SELECTION)
            .highlight_symbol("▶ ")
            .highlight_spacing(HighlightSpacing::Always);

        frame.render_stateful_widget(table, area, &mut self.tabs_table_state);
    }

    ///////////////////////////////////////////////////////////////////////////
    fn render_interfaces_table(
        &mut self,
        frame: &mut Frame<'_>,
        area: Rect,
        interfaces: &[Ieee1905LocalInterface],
    ) {
        let mut rows = Vec::new();

        for interface in interfaces {
            rows.push(Row::new([
                Span::raw(interface.name.clone()),
                Span::raw(interface.mac.to_string()),
                Span::raw(match interface.flags.contains(Iff::UP) {
                    true => "up",
                    false => "down",
                }),
                or_placeholder(interface.media_type_extra.as_wifi().map(|e| &e.bssid)),
                or_placeholder(interface.bridging_tuple.as_ref()),
                format_phy_rate(interface.phy_rate),
                or_placeholder(interface.signal_strength_dbm.as_ref()),
                or_placeholder(interface.link_availability.as_ref()),
                Span::raw(interface.media_type.to_string()),
            ]));
        }

        let table_headers = [
            "Name",
            "MAC",
            "State",
            "BSSID",
            "Bridging",
            "PHY Rate",
            "RSSI",
            "Availability",
            "Media Type",
        ];

        let table_constraints = [
            Constraint::Length(20),
            Constraint::Length(17),
            Constraint::Length(5),
            Constraint::Length(17),
            Constraint::Fill(1),
            Constraint::Fill(1),
            Constraint::Fill(1),
            Constraint::Fill(1),
            Constraint::Fill(3),
        ];

        let tab = LocalDeviceTab::Interfaces;
        self.render_content_panel(frame, area, tab, rows, &table_headers, &table_constraints);
    }

    ///////////////////////////////////////////////////////////////////////////
    fn render_ieee1905_neighbors_table(
        &mut self,
        frame: &mut Frame<'_>,
        area: Rect,
        interfaces: &[Ieee1905LocalInterface],
    ) {
        let mut rows = Vec::new();

        for interface in interfaces {
            for neighbor in interface.ieee1905_neighbors.iter().flatten() {
                let bridged = neighbor.neighbor_flags & IEEE1905Neighbor::FLAG_BRIDGED != 0;

                rows.push(Row::new([
                    Span::raw(interface.name.clone()),
                    Span::raw(interface.mac.to_string()),
                    Span::raw(neighbor.neighbor_al_mac.to_string()),
                    Span::raw(match bridged {
                        true => "yes",
                        false => "no",
                    }),
                    Span::raw(interface.media_type.to_string()),
                ]));
            }
        }

        let table_headers = [
            "Name",
            "Local Interface",
            "Neighbor AL MAC",
            "Bridged",
            "Media Type",
        ];

        let table_constraints = [
            Constraint::Length(20),
            Constraint::Length(17),
            Constraint::Length(17),
            Constraint::Fill(1),
            Constraint::Fill(3),
        ];

        let tab = LocalDeviceTab::Ieee1905Neighbors;
        self.render_content_panel(frame, area, tab, rows, &table_headers, &table_constraints);
    }

    ///////////////////////////////////////////////////////////////////////////
    fn render_non_ieee1905_neighbors_table(
        &mut self,
        frame: &mut Frame<'_>,
        area: Rect,
        interfaces: &[Ieee1905LocalInterface],
    ) {
        let mut rows = Vec::new();

        for interface in interfaces {
            for neighbor_mac in interface.non_ieee1905_neighbors.iter().flatten() {
                rows.push(Row::new([
                    Span::raw(interface.name.clone()),
                    Span::raw(interface.mac.to_string()),
                    Span::raw(neighbor_mac.to_string()),
                    Span::raw(interface.media_type.to_string()),
                ]));
            }
        }

        let table_headers = ["Name", "Local Interface", "Neighbor MAC", "Media Type"];
        let table_constraints = [
            Constraint::Length(20),
            Constraint::Length(17),
            Constraint::Length(17),
            Constraint::Fill(1),
        ];

        let tab = LocalDeviceTab::NonIeee1905Neighbors;
        self.render_content_panel(frame, area, tab, rows, &table_headers, &table_constraints);
    }

    ///////////////////////////////////////////////////////////////////////////
    fn render_content_panel(
        &mut self,
        frame: &mut Frame<'_>,
        area: Rect,
        tab: LocalDeviceTab,
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
enum LocalDeviceTab {
    #[default]
    Interfaces,
    Ieee1905Neighbors,
    NonIeee1905Neighbors,
}

impl LocalDeviceTab {
    const ALL: [LocalDeviceTab; 3] = [
        LocalDeviceTab::Interfaces,
        LocalDeviceTab::Ieee1905Neighbors,
        LocalDeviceTab::NonIeee1905Neighbors,
    ];

    fn title(self) -> &'static str {
        match self {
            LocalDeviceTab::Interfaces => "Interfaces",
            LocalDeviceTab::Ieee1905Neighbors => "1905 Neighbors",
            LocalDeviceTab::NonIeee1905Neighbors => "Non-1905 Neighbors",
        }
    }

    fn empty_message(self) -> &'static str {
        match self {
            LocalDeviceTab::Interfaces => "No interfaces reported",
            LocalDeviceTab::Ieee1905Neighbors => "No IEEE 1905 neighbors reported",
            LocalDeviceTab::NonIeee1905Neighbors => "No non-IEEE 1905 neighbors reported",
        }
    }
}
