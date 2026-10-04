pub mod assets;
pub mod database;
pub mod dns;
pub mod error;
pub mod events;
pub mod evidence;
pub mod orchestration;
pub mod process;
pub mod protocol;
pub mod providers;
pub mod sanitize;
pub mod scope;
pub mod targets;
pub mod web;

pub fn now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .expect("UTC timestamp is representable")
}
