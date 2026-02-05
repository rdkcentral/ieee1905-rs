mod rolling_file_appender;

use crate::logger::rolling_file_appender::RollingFileAppender;
use crate::CliArgs;
use std::num::NonZeroUsize;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

///////////////////////////////////////////////////////////////////////////
const BYTES_IN_MB: NonZeroUsize = NonZeroUsize::new(1024 * 1024).unwrap();

///////////////////////////////////////////////////////////////////////////
pub fn init_logger(cli: &CliArgs) -> Option<WorkerGuard> {
    // modify this filter for your tracing during run time
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cli.filter));

    // logging to stdout
    let fmt_layer = (!cli.no_stdout_appender && !cli.topology_ui).then(|| {
        tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_level(true)
            .with_span_events(FmtSpan::CLOSE)
    });

    // logging to fs
    let mut file_layer_guard = None;
    let file_layer = cli.file_appender.as_ref().map(|folder| {
        let file_appender = RollingFileAppender::daily(folder, "ieee1905_", ".log")
            .max_files(cli.file_appender_files_count)
            .max_file_size(cli.file_appender_max_file_size.saturating_mul(BYTES_IN_MB));

        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        file_layer_guard = Some(guard);

        tracing_subscriber::fmt::layer()
            .with_writer(non_blocking)
            .with_target(true)
            .with_level(true)
            .with_span_events(FmtSpan::CLOSE)
    });

    // combined logger
    let logging_layer = tracing_subscriber::Layer::and_then(fmt_layer, file_layer);

    #[cfg(feature = "enable_tokio_console")]
    if cli.console_subscriber {
        tracing::info!("Tokio console: Enabled");
        tracing_subscriber::registry()
            .with(logging_layer.with_filter(filter))
            .with(console_subscriber::spawn())
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
