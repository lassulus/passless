use env_logger::Builder;
use log::LevelFilter;
#[cfg(target_os = "linux")]
use log::{Log, Metadata, Record};
#[cfg(target_os = "linux")]
use systemd_journal_logger::JournalLog;

const LOG_LEVEL_ENV: &str = "PASSLESS_LOG_LEVEL";
const LOG_STYLE_ENV: &str = "PASSLESS_LOG_STYLE";
#[cfg(target_os = "linux")]
const SYSLOG_IDENTIFIER_ENV: &str = "PASSLESS_SYSLOG_IDENTIFIER";
#[cfg(target_os = "linux")]
const DEFAULT_SYSLOG_IDENTIFIER: &str = "passless";

#[cfg(target_os = "linux")]
struct FilteredJournalLog {
    filter: env_logger::Logger,
    journal: JournalLog,
}

#[cfg(target_os = "linux")]
impl Log for FilteredJournalLog {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        Log::enabled(&self.filter, metadata)
    }

    fn log(&self, record: &Record<'_>) {
        if self.filter.matches(record) {
            Log::log(&self.journal, record);
        }
    }

    fn flush(&self) {
        Log::flush(&self.journal);
    }
}

fn configured_builder(filter: Option<&str>, style: Option<&str>) -> Builder {
    let mut builder = Builder::new();
    builder.filter_level(LevelFilter::Debug);

    // Environment configuration overrides the default filter, matching the
    // documented env_logger precedence.
    if let Some(filter) = filter {
        builder.parse_filters(filter);
    }
    if let Some(style) = style {
        builder.parse_write_style(style);
    }

    builder
}

fn log_builder() -> Builder {
    let filter = std::env::var(LOG_LEVEL_ENV).ok();
    let style = std::env::var(LOG_STYLE_ENV).ok();
    configured_builder(filter.as_deref(), style.as_deref())
}

/// Log to journald when it is connected (a systemd unit). `false` when not, or when that fails.
#[cfg(target_os = "linux")]
fn init_journal(max_level: LevelFilter) -> bool {
    if !systemd_journal_logger::connected_to_journal() {
        return false;
    }
    match JournalLog::new() {
        Ok(journal) => {
            let identifier = std::env::var(SYSLOG_IDENTIFIER_ENV)
                .unwrap_or_else(|_| DEFAULT_SYSLOG_IDENTIFIER.to_string());
            let filter = log_builder().build();
            let journal = journal.with_syslog_identifier(identifier);

            log::set_boxed_logger(Box::new(FilteredJournalLog { filter, journal }))
                .expect("Logger was already installed.");
            log::set_max_level(max_level);
            true
        }
        Err(error) => {
            eprintln!(
                "Failed to initialize native journald logging ({error}); falling back to stderr"
            );
            false
        }
    }
}

pub fn init(max_level: LevelFilter) {
    #[cfg(target_os = "linux")]
    if init_journal(max_level) {
        return;
    }

    let mut builder = log_builder();
    builder.format_timestamp_millis().init();
    log::set_max_level(max_level);
}

#[cfg(test)]
mod tests {
    use log::{Level, LevelFilter, Log, Metadata};

    use super::configured_builder;

    #[test]
    fn default_filter_is_debug() {
        let logger = configured_builder(None, None).build();
        assert_eq!(logger.filter(), LevelFilter::Debug);
    }

    #[test]
    fn global_filter_overrides_default() {
        let logger = configured_builder(Some("warn"), None).build();
        assert_eq!(logger.filter(), LevelFilter::Warn);
    }

    #[test]
    fn module_filter_is_preserved() {
        let logger = configured_builder(Some("soft_fido2=warn"), None).build();
        let metadata = Metadata::builder()
            .level(Level::Debug)
            .target("soft_fido2::ctap")
            .build();
        assert!(!Log::enabled(&logger, &metadata));
    }
}
