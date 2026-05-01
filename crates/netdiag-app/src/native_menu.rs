use super::{Language, Tab, title_for_tab};
use eframe::egui;
use muda::{
    AboutMetadata, CheckMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu,
    accelerator::{Accelerator, CMD_OR_CTRL, Code, Modifiers},
};
use std::sync::mpsc;

const ID_NEW_ANALYSIS: &str = "netdiag.new-analysis";
const ID_IMPORT_TRACE: &str = "netdiag.import-trace";
const ID_RUN_SIMULATION: &str = "netdiag.run-simulation";
const ID_LIVE_API: &str = "netdiag.live-api";
const ID_CHECK_FOR_UPDATES: &str = "netdiag.check-for-updates";
const ID_OPEN_REPORT: &str = "netdiag.open-report";
const ID_OPEN_RUN_FOLDER: &str = "netdiag.open-run-folder";
const ID_SETTINGS: &str = "netdiag.settings";
const ID_HELP: &str = "netdiag.help";
const ID_VIEW_OVERVIEW: &str = "netdiag.view.overview";
const ID_VIEW_TELEMETRY: &str = "netdiag.view.telemetry";
const ID_VIEW_DIAGNOSIS: &str = "netdiag.view.diagnosis";
const ID_VIEW_RULE_ML: &str = "netdiag.view.rule-ml";
const ID_VIEW_DIGITAL_TWIN: &str = "netdiag.view.digital-twin";
const ID_VIEW_WHAT_IF: &str = "netdiag.view.what-if";
const ID_VIEW_REPORTS: &str = "netdiag.view.reports";

#[derive(Debug, Clone, Copy)]
pub enum NativeMenuCommand {
    NewAnalysis,
    ImportTrace,
    RunSimulation,
    LiveApi,
    CheckForUpdates,
    OpenReport,
    OpenRunFolder,
    Settings,
    Help,
    SwitchTab(Tab),
}

impl NativeMenuCommand {
    fn from_id(id: &str) -> Option<Self> {
        Some(match id {
            ID_NEW_ANALYSIS => Self::NewAnalysis,
            ID_IMPORT_TRACE => Self::ImportTrace,
            ID_RUN_SIMULATION => Self::RunSimulation,
            ID_LIVE_API => Self::LiveApi,
            ID_CHECK_FOR_UPDATES => Self::CheckForUpdates,
            ID_OPEN_REPORT => Self::OpenReport,
            ID_OPEN_RUN_FOLDER => Self::OpenRunFolder,
            ID_SETTINGS => Self::Settings,
            ID_HELP => Self::Help,
            ID_VIEW_OVERVIEW => Self::SwitchTab(Tab::Overview),
            ID_VIEW_TELEMETRY => Self::SwitchTab(Tab::Telemetry),
            ID_VIEW_DIAGNOSIS => Self::SwitchTab(Tab::Diagnosis),
            ID_VIEW_RULE_ML => Self::SwitchTab(Tab::RuleMl),
            ID_VIEW_DIGITAL_TWIN => Self::SwitchTab(Tab::DigitalTwin),
            ID_VIEW_WHAT_IF => Self::SwitchTab(Tab::WhatIf),
            ID_VIEW_REPORTS => Self::SwitchTab(Tab::Reports),
            _ => return None,
        })
    }
}

pub struct NativeMenu {
    _menu: Menu,
    receiver: mpsc::Receiver<NativeMenuCommand>,
    app_menu: Submenu,
    file_menu: Submenu,
    edit_menu: Submenu,
    view_menu: Submenu,
    window_menu: Submenu,
    help_menu: Submenu,
    about_item: PredefinedMenuItem,
    check_for_updates_item: MenuItem,
    settings_item: MenuItem,
    services_item: PredefinedMenuItem,
    hide_item: PredefinedMenuItem,
    hide_others_item: PredefinedMenuItem,
    show_all_item: PredefinedMenuItem,
    quit_item: PredefinedMenuItem,
    new_analysis_item: MenuItem,
    import_trace_item: MenuItem,
    run_simulation_item: MenuItem,
    live_api_item: MenuItem,
    open_report_item: MenuItem,
    open_run_folder_item: MenuItem,
    close_window_item: PredefinedMenuItem,
    undo_item: PredefinedMenuItem,
    redo_item: PredefinedMenuItem,
    cut_item: PredefinedMenuItem,
    copy_item: PredefinedMenuItem,
    paste_item: PredefinedMenuItem,
    select_all_item: PredefinedMenuItem,
    view_items: Vec<(Tab, CheckMenuItem)>,
    minimize_item: PredefinedMenuItem,
    zoom_item: PredefinedMenuItem,
    fullscreen_item: PredefinedMenuItem,
    bring_all_to_front_item: PredefinedMenuItem,
    help_item: MenuItem,
}

impl NativeMenu {
    pub fn install(ctx: &egui::Context, lang: Language) -> muda::Result<Self> {
        let (sender, receiver) = mpsc::channel();
        let repaint_ctx = ctx.clone();
        muda::MenuEvent::set_event_handler(Some(move |event: muda::MenuEvent| {
            if let Some(command) = NativeMenuCommand::from_id(event.id.as_ref()) {
                let _ = sender.send(command);
                repaint_ctx.request_repaint();
            }
        }));

        let app_menu = Submenu::new("NetDiag Twin", true);
        let about_item = PredefinedMenuItem::about(
            Some(menu_label(lang, MenuLabel::About)),
            Some(AboutMetadata {
                name: Some("NetDiag Twin".to_string()),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
                copyright: Some("NetDiag Twin".to_string()),
                ..Default::default()
            }),
        );
        let check_for_updates_item = MenuItem::with_id(
            ID_CHECK_FOR_UPDATES,
            menu_label(lang, MenuLabel::CheckForUpdates),
            true,
            None,
        );
        let settings_item = MenuItem::with_id(
            ID_SETTINGS,
            menu_label(lang, MenuLabel::Settings),
            true,
            Some(cmd(Code::Comma)),
        );
        let services_item =
            PredefinedMenuItem::services(Some(menu_label(lang, MenuLabel::Services)));
        let hide_item = PredefinedMenuItem::hide(Some(menu_label(lang, MenuLabel::Hide)));
        let hide_others_item =
            PredefinedMenuItem::hide_others(Some(menu_label(lang, MenuLabel::HideOthers)));
        let show_all_item =
            PredefinedMenuItem::show_all(Some(menu_label(lang, MenuLabel::ShowAll)));
        let quit_item = PredefinedMenuItem::quit(Some(menu_label(lang, MenuLabel::Quit)));
        let app_sep_1 = PredefinedMenuItem::separator();
        let app_sep_2 = PredefinedMenuItem::separator();
        let app_sep_3 = PredefinedMenuItem::separator();
        let app_sep_4 = PredefinedMenuItem::separator();
        app_menu.append_items(&[
            &about_item,
            &app_sep_1,
            &check_for_updates_item,
            &settings_item,
            &app_sep_2,
            &services_item,
            &app_sep_3,
            &hide_item,
            &hide_others_item,
            &show_all_item,
            &app_sep_4,
            &quit_item,
        ])?;

        let file_menu = Submenu::new(menu_label(lang, MenuLabel::File), true);
        let new_analysis_item = MenuItem::with_id(
            ID_NEW_ANALYSIS,
            menu_label(lang, MenuLabel::NewAnalysis),
            true,
            Some(cmd(Code::KeyN)),
        );
        let import_trace_item = MenuItem::with_id(
            ID_IMPORT_TRACE,
            menu_label(lang, MenuLabel::ImportTrace),
            true,
            Some(cmd(Code::KeyO)),
        );
        let run_simulation_item = MenuItem::with_id(
            ID_RUN_SIMULATION,
            menu_label(lang, MenuLabel::RunSimulation),
            true,
            Some(cmd(Code::KeyR)),
        );
        let live_api_item = MenuItem::with_id(
            ID_LIVE_API,
            menu_label(lang, MenuLabel::AddApi),
            true,
            Some(cmd_shift(Code::KeyL)),
        );
        let open_report_item = MenuItem::with_id(
            ID_OPEN_REPORT,
            menu_label(lang, MenuLabel::OpenReport),
            false,
            Some(cmd(Code::KeyE)),
        );
        let open_run_folder_item = MenuItem::with_id(
            ID_OPEN_RUN_FOLDER,
            menu_label(lang, MenuLabel::OpenRunFolder),
            false,
            Some(cmd_shift(Code::KeyO)),
        );
        let close_window_item =
            PredefinedMenuItem::close_window(Some(menu_label(lang, MenuLabel::CloseWindow)));
        let file_sep_1 = PredefinedMenuItem::separator();
        let file_sep_2 = PredefinedMenuItem::separator();
        let file_sep_3 = PredefinedMenuItem::separator();
        file_menu.append_items(&[
            &new_analysis_item,
            &import_trace_item,
            &file_sep_1,
            &run_simulation_item,
            &live_api_item,
            &file_sep_2,
            &open_report_item,
            &open_run_folder_item,
            &file_sep_3,
            &close_window_item,
        ])?;

        let edit_menu = Submenu::new(menu_label(lang, MenuLabel::Edit), true);
        let undo_item = PredefinedMenuItem::undo(Some(menu_label(lang, MenuLabel::Undo)));
        let redo_item = PredefinedMenuItem::redo(Some(menu_label(lang, MenuLabel::Redo)));
        let cut_item = PredefinedMenuItem::cut(Some(menu_label(lang, MenuLabel::Cut)));
        let copy_item = PredefinedMenuItem::copy(Some(menu_label(lang, MenuLabel::Copy)));
        let paste_item = PredefinedMenuItem::paste(Some(menu_label(lang, MenuLabel::Paste)));
        let select_all_item =
            PredefinedMenuItem::select_all(Some(menu_label(lang, MenuLabel::SelectAll)));
        let edit_sep_1 = PredefinedMenuItem::separator();
        let edit_sep_2 = PredefinedMenuItem::separator();
        edit_menu.append_items(&[
            &undo_item,
            &redo_item,
            &edit_sep_1,
            &cut_item,
            &copy_item,
            &paste_item,
            &select_all_item,
            &edit_sep_2,
        ])?;

        let view_menu = Submenu::new(menu_label(lang, MenuLabel::View), true);
        let view_items = vec![
            view_item(ID_VIEW_OVERVIEW, Tab::Overview, lang, true, Code::Digit1),
            view_item(ID_VIEW_TELEMETRY, Tab::Telemetry, lang, false, Code::Digit2),
            view_item(ID_VIEW_DIAGNOSIS, Tab::Diagnosis, lang, false, Code::Digit3),
            view_item(ID_VIEW_RULE_ML, Tab::RuleMl, lang, false, Code::Digit4),
            view_item(
                ID_VIEW_DIGITAL_TWIN,
                Tab::DigitalTwin,
                lang,
                false,
                Code::Digit5,
            ),
            view_item(ID_VIEW_WHAT_IF, Tab::WhatIf, lang, false, Code::Digit6),
            view_item(ID_VIEW_REPORTS, Tab::Reports, lang, false, Code::Digit7),
        ];
        for (_, item) in &view_items {
            view_menu.append(item)?;
        }

        let window_menu = Submenu::new(menu_label(lang, MenuLabel::Window), true);
        let minimize_item =
            PredefinedMenuItem::minimize(Some(menu_label(lang, MenuLabel::Minimize)));
        let zoom_item = PredefinedMenuItem::maximize(Some(menu_label(lang, MenuLabel::Zoom)));
        let fullscreen_item =
            PredefinedMenuItem::fullscreen(Some(menu_label(lang, MenuLabel::EnterFullScreen)));
        let bring_all_to_front_item = PredefinedMenuItem::bring_all_to_front(Some(menu_label(
            lang,
            MenuLabel::BringAllToFront,
        )));
        let window_sep_1 = PredefinedMenuItem::separator();
        let window_sep_2 = PredefinedMenuItem::separator();
        window_menu.append_items(&[
            &minimize_item,
            &zoom_item,
            &fullscreen_item,
            &window_sep_1,
            &bring_all_to_front_item,
            &window_sep_2,
        ])?;

        let help_menu = Submenu::new(menu_label(lang, MenuLabel::Help), true);
        let help_item =
            MenuItem::with_id(ID_HELP, menu_label(lang, MenuLabel::HelpItem), true, None);
        help_menu.append(&help_item)?;

        let menu = Menu::new();
        menu.append_items(&[
            &app_menu,
            &file_menu,
            &edit_menu,
            &view_menu,
            &window_menu,
            &help_menu,
        ])?;
        menu.init_for_nsapp();
        window_menu.set_as_windows_menu_for_nsapp();
        help_menu.set_as_help_menu_for_nsapp();

        Ok(Self {
            _menu: menu,
            receiver,
            app_menu,
            file_menu,
            edit_menu,
            view_menu,
            window_menu,
            help_menu,
            about_item,
            check_for_updates_item,
            settings_item,
            services_item,
            hide_item,
            hide_others_item,
            show_all_item,
            quit_item,
            new_analysis_item,
            import_trace_item,
            run_simulation_item,
            live_api_item,
            open_report_item,
            open_run_folder_item,
            close_window_item,
            undo_item,
            redo_item,
            cut_item,
            copy_item,
            paste_item,
            select_all_item,
            view_items,
            minimize_item,
            zoom_item,
            fullscreen_item,
            bring_all_to_front_item,
            help_item,
        })
    }

    pub fn drain_commands(&self) -> Vec<NativeMenuCommand> {
        let mut commands = Vec::new();
        while let Ok(command) = self.receiver.try_recv() {
            commands.push(command);
        }
        commands
    }

    pub fn sync(
        &self,
        lang: Language,
        tab: Tab,
        has_result: bool,
        has_live_api: bool,
        is_running: bool,
    ) {
        self.app_menu.set_text("NetDiag Twin");
        self.file_menu.set_text(menu_label(lang, MenuLabel::File));
        self.edit_menu.set_text(menu_label(lang, MenuLabel::Edit));
        self.view_menu.set_text(menu_label(lang, MenuLabel::View));
        self.window_menu
            .set_text(menu_label(lang, MenuLabel::Window));
        self.help_menu.set_text(menu_label(lang, MenuLabel::Help));

        self.about_item.set_text(menu_label(lang, MenuLabel::About));
        self.check_for_updates_item
            .set_text(menu_label(lang, MenuLabel::CheckForUpdates));
        self.settings_item
            .set_text(menu_label(lang, MenuLabel::Settings));
        self.services_item
            .set_text(menu_label(lang, MenuLabel::Services));
        self.hide_item.set_text(menu_label(lang, MenuLabel::Hide));
        self.hide_others_item
            .set_text(menu_label(lang, MenuLabel::HideOthers));
        self.show_all_item
            .set_text(menu_label(lang, MenuLabel::ShowAll));
        self.quit_item.set_text(menu_label(lang, MenuLabel::Quit));

        self.new_analysis_item
            .set_text(menu_label(lang, MenuLabel::NewAnalysis));
        self.new_analysis_item.set_enabled(!is_running);
        self.import_trace_item
            .set_text(menu_label(lang, MenuLabel::ImportTrace));
        self.import_trace_item.set_enabled(!is_running);
        self.run_simulation_item
            .set_text(menu_label(lang, MenuLabel::RunSimulation));
        self.run_simulation_item.set_enabled(!is_running);
        self.live_api_item.set_text(if has_live_api {
            menu_label(lang, MenuLabel::LiveApi)
        } else {
            menu_label(lang, MenuLabel::AddApi)
        });
        self.live_api_item.set_enabled(!is_running);
        self.open_report_item
            .set_text(menu_label(lang, MenuLabel::OpenReport));
        self.open_report_item.set_enabled(has_result);
        self.open_run_folder_item
            .set_text(menu_label(lang, MenuLabel::OpenRunFolder));
        self.open_run_folder_item.set_enabled(has_result);
        self.close_window_item
            .set_text(menu_label(lang, MenuLabel::CloseWindow));

        self.undo_item.set_text(menu_label(lang, MenuLabel::Undo));
        self.redo_item.set_text(menu_label(lang, MenuLabel::Redo));
        self.cut_item.set_text(menu_label(lang, MenuLabel::Cut));
        self.copy_item.set_text(menu_label(lang, MenuLabel::Copy));
        self.paste_item.set_text(menu_label(lang, MenuLabel::Paste));
        self.select_all_item
            .set_text(menu_label(lang, MenuLabel::SelectAll));

        for (item_tab, item) in &self.view_items {
            item.set_text(title_for_tab(*item_tab, lang));
            item.set_checked(*item_tab == tab);
        }

        self.minimize_item
            .set_text(menu_label(lang, MenuLabel::Minimize));
        self.zoom_item.set_text(menu_label(lang, MenuLabel::Zoom));
        self.fullscreen_item
            .set_text(menu_label(lang, MenuLabel::EnterFullScreen));
        self.bring_all_to_front_item
            .set_text(menu_label(lang, MenuLabel::BringAllToFront));
        self.help_item
            .set_text(menu_label(lang, MenuLabel::HelpItem));
    }
}

fn view_item(
    id: &'static str,
    tab: Tab,
    lang: Language,
    checked: bool,
    key: Code,
) -> (Tab, CheckMenuItem) {
    (
        tab,
        CheckMenuItem::with_id(id, title_for_tab(tab, lang), true, checked, Some(cmd(key))),
    )
}

fn cmd(key: Code) -> Accelerator {
    Accelerator::new(Some(CMD_OR_CTRL), key)
}

fn cmd_shift(key: Code) -> Accelerator {
    Accelerator::new(Some(CMD_OR_CTRL | Modifiers::SHIFT), key)
}

#[derive(Clone, Copy)]
enum MenuLabel {
    File,
    Edit,
    View,
    Window,
    Help,
    About,
    CheckForUpdates,
    Settings,
    Services,
    Hide,
    HideOthers,
    ShowAll,
    Quit,
    NewAnalysis,
    ImportTrace,
    RunSimulation,
    AddApi,
    LiveApi,
    OpenReport,
    OpenRunFolder,
    CloseWindow,
    Undo,
    Redo,
    Cut,
    Copy,
    Paste,
    SelectAll,
    Minimize,
    Zoom,
    EnterFullScreen,
    BringAllToFront,
    HelpItem,
}

fn menu_label(lang: Language, label: MenuLabel) -> &'static str {
    match (lang, label) {
        (Language::Zh, MenuLabel::File) => "文件",
        (Language::Zh, MenuLabel::Edit) => "编辑",
        (Language::Zh, MenuLabel::View) => "显示",
        (Language::Zh, MenuLabel::Window) => "窗口",
        (Language::Zh, MenuLabel::Help) => "帮助",
        (Language::Zh, MenuLabel::About) => "关于 NetDiag Twin",
        (Language::Zh, MenuLabel::CheckForUpdates) => "检查更新...",
        (Language::Zh, MenuLabel::Settings) => "设置...",
        (Language::Zh, MenuLabel::Services) => "服务",
        (Language::Zh, MenuLabel::Hide) => "隐藏 NetDiag Twin",
        (Language::Zh, MenuLabel::HideOthers) => "隐藏其他",
        (Language::Zh, MenuLabel::ShowAll) => "全部显示",
        (Language::Zh, MenuLabel::Quit) => "退出 NetDiag Twin",
        (Language::Zh, MenuLabel::NewAnalysis) => "新分析",
        (Language::Zh, MenuLabel::ImportTrace) => "导入 Trace...",
        (Language::Zh, MenuLabel::RunSimulation) => "运行仿真",
        (Language::Zh, MenuLabel::AddApi) => "添加 API...",
        (Language::Zh, MenuLabel::LiveApi) => "运行真实采集",
        (Language::Zh, MenuLabel::OpenReport) => "打开报告",
        (Language::Zh, MenuLabel::OpenRunFolder) => "打开运行目录",
        (Language::Zh, MenuLabel::CloseWindow) => "关闭窗口",
        (Language::Zh, MenuLabel::Undo) => "撤销",
        (Language::Zh, MenuLabel::Redo) => "重做",
        (Language::Zh, MenuLabel::Cut) => "剪切",
        (Language::Zh, MenuLabel::Copy) => "复制",
        (Language::Zh, MenuLabel::Paste) => "粘贴",
        (Language::Zh, MenuLabel::SelectAll) => "全选",
        (Language::Zh, MenuLabel::Minimize) => "最小化",
        (Language::Zh, MenuLabel::Zoom) => "缩放",
        (Language::Zh, MenuLabel::EnterFullScreen) => "进入全屏",
        (Language::Zh, MenuLabel::BringAllToFront) => "全部置于顶层",
        (Language::Zh, MenuLabel::HelpItem) => "NetDiag Twin 帮助",
        (Language::En, MenuLabel::File) => "File",
        (Language::En, MenuLabel::Edit) => "Edit",
        (Language::En, MenuLabel::View) => "View",
        (Language::En, MenuLabel::Window) => "Window",
        (Language::En, MenuLabel::Help) => "Help",
        (Language::En, MenuLabel::About) => "About NetDiag Twin",
        (Language::En, MenuLabel::CheckForUpdates) => "Check for Updates...",
        (Language::En, MenuLabel::Settings) => "Settings...",
        (Language::En, MenuLabel::Services) => "Services",
        (Language::En, MenuLabel::Hide) => "Hide NetDiag Twin",
        (Language::En, MenuLabel::HideOthers) => "Hide Others",
        (Language::En, MenuLabel::ShowAll) => "Show All",
        (Language::En, MenuLabel::Quit) => "Quit NetDiag Twin",
        (Language::En, MenuLabel::NewAnalysis) => "New Analysis",
        (Language::En, MenuLabel::ImportTrace) => "Import Trace...",
        (Language::En, MenuLabel::RunSimulation) => "Run Simulation",
        (Language::En, MenuLabel::AddApi) => "Add API...",
        (Language::En, MenuLabel::LiveApi) => "Run Live Collection",
        (Language::En, MenuLabel::OpenReport) => "Open Report",
        (Language::En, MenuLabel::OpenRunFolder) => "Open Run Folder",
        (Language::En, MenuLabel::CloseWindow) => "Close Window",
        (Language::En, MenuLabel::Undo) => "Undo",
        (Language::En, MenuLabel::Redo) => "Redo",
        (Language::En, MenuLabel::Cut) => "Cut",
        (Language::En, MenuLabel::Copy) => "Copy",
        (Language::En, MenuLabel::Paste) => "Paste",
        (Language::En, MenuLabel::SelectAll) => "Select All",
        (Language::En, MenuLabel::Minimize) => "Minimize",
        (Language::En, MenuLabel::Zoom) => "Zoom",
        (Language::En, MenuLabel::EnterFullScreen) => "Enter Full Screen",
        (Language::En, MenuLabel::BringAllToFront) => "Bring All to Front",
        (Language::En, MenuLabel::HelpItem) => "NetDiag Twin Help",
    }
}
