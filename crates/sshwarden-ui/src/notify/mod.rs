#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use self::windows::{prompt_authorization, prompt_authorization_blocking};

#[cfg(not(windows))]
mod fallback;

#[cfg(not(windows))]
pub use fallback::prompt_authorization;
