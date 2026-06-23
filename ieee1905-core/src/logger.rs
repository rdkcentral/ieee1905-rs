mod rolling_file_appender;

use crate::CliArgs;
use crate::logger::rolling_file_appender::RollingFileAppender;
use std::num::NonZeroUsize;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{Layer, Registry};

///////////////////////////////////////////////////////////////////////////
const BYTES_IN_MB: NonZeroUsize = NonZeroUsize::new(1024 * 1024).unwrap();
const DEFAULT_FILTER: &str = "ieee1905=info,tower_http=debug";

///////////////////////////////////////////////////////////////////////////
pub fn init_logger(cli: &CliArgs) -> Option<WorkerGuard> {
    // prepare filter (env -> cli args -> defaults)
    let filter = parse_filter_targets(cli.filter.as_deref());

    // logging to stdout
    let fmt_layer = build_fmt_layer(cli);

    // logging to fs
    let (file_layer, file_layer_guard) = build_file_layer(cli);

    // combined logger
    let logging_layer = Layer::and_then(fmt_layer, file_layer);

    #[cfg(feature = "enable_tokio_console")]
    if cli.console_subscriber {
        use tracing_subscriber::Layer;

        let console_layer = console_subscriber::ConsoleLayer::builder()
            .with_default_env()
            .server_addr(std::net::SocketAddr::from(([0, 0, 0, 0], 6669)))
            .spawn();

        tracing::info!("Tokio console: Enabled");
        tracing_subscriber::registry()
            .with(logging_layer.with_filter(filter))
            .with(console_layer)
            .init();

        return file_layer_guard;
    }

    tracing::info!("Tokio console: Disabled");
    tracing_subscriber::registry()
        .with(logging_layer)
        .with(filter)
        .init();

    file_layer_guard
}

///////////////////////////////////////////////////////////////////////////
fn parse_filter_targets(cli_filter: Option<&str>) -> Targets {
    if let Ok(filter) = std::env::var("RUST_LOG")
        && let Ok(targets) = filter.parse()
    {
        return targets;
    }

    if let Some(filter) = cli_filter
        && let Ok(targets) = filter.parse()
    {
        return targets;
    }

    DEFAULT_FILTER.parse().unwrap_or_default()
}

///////////////////////////////////////////////////////////////////////////
fn build_fmt_layer(cli: &CliArgs) -> Option<impl Layer<Registry>> {
    if cli.no_stdout_appender {
        return None;
    }

    #[cfg(feature = "topology_ui")]
    if cli.topology_ui {
        return None;
    }

    Some(
        tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_level(true)
            .with_span_events(FmtSpan::CLOSE),
    )
}

///////////////////////////////////////////////////////////////////////////
fn build_file_layer(cli: &CliArgs) -> (Option<impl Layer<Registry>>, Option<WorkerGuard>) {
    let Some(folder) = cli.file_appender.as_deref() else {
        return (None, None);
    };

    let file_appender = RollingFileAppender::daily(folder, "ieee1905_", ".log")
        .max_files(cli.file_appender_files_count)
        .max_file_size(cli.file_appender_max_file_size.saturating_mul(BYTES_IN_MB));

    let (non_blocking, guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
        .buffered_lines_limit(1024)
        .finish(file_appender);

    let layer = tracing_subscriber::fmt::layer()
        .with_writer(non_blocking)
        .with_target(true)
        .with_level(true)
        .with_span_events(FmtSpan::CLOSE);

    (Some(layer), Some(guard))
}
