pub mod anthropic_compat;
pub(crate) mod anthropic_sse;
pub mod auth;
pub mod codex_auth;
pub(crate) mod codex_models;
pub(crate) mod codex_network;
pub mod codex_protocol;
pub(crate) mod codex_transport;
pub mod config;
pub mod connect;
pub mod dsml_shim;
pub mod messages;
pub mod models;
pub mod openai_chat;
pub mod openai_responses;
pub mod policy;
pub(crate) mod provider_contracts;
pub mod science_control;
pub mod server;
/// POSIX build of the external-skill install bridge (openat/flock/uid-based
/// authority fence). The whole implementation is compiled only on Unix.
#[cfg(unix)]
#[path = "skill_install_unix.rs"]
pub mod skill_install;
/// Windows placeholder: the MCP/bridge install-uninstall surface is disabled,
/// while the gateway process itself still starts and proxies normally.
#[cfg(not(unix))]
#[path = "skill_install_windows.rs"]
pub mod skill_install;
pub mod static_profile;
