//! Resolving a config value that lives outside the config file.
//!
//! The threat model is the one in `config::Secret`: the agent runs under the
//! same uid as nyet, so a source only draws a line if something checks WHO is
//! asking. On macOS the Keychain does exactly that — an item created by nyet
//! carries an ACL naming nyet's code signature, and any other process reading
//! it gets a password prompt the agent cannot answer.
//!
//! Two rules make that hold, and both are easy to lose:
//!
//! 1. **Never shell out to `/usr/bin/security`.** The ACL is checked against
//!    the process that asks, so the trusted application would be `security` —
//!    a binary the agent can run itself. The native API is not a nicety here,
//!    it is the whole mechanism.
//! 2. **nyet creates the item itself.** The creating application lands in the
//!    ACL; an item made by `security` or Keychain Access trusts the wrong
//!    binary from birth.
//!
//! Reads run with user interaction disabled, so an agent-triggered call gets a
//! clean error instead of a dialog on the human's screen.

use crate::config::Secret;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Both halves of the Keychain item name. The service is constant so every
/// item nyet owns is greppable in Keychain Access; the account is the name
/// written in the config (`password = { keychain = "prod-db" }`).
const KEYCHAIN_SERVICE: &str = "nyet";

/// How long a `{ command = ... }` may take. Long enough for a biometric
/// unlock, short enough that an agent's call fails instead of hanging.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub enum SecretError {
    /// `{ env = "VAR" }` but the variable is not set (or not UTF-8).
    MissingEnvVar {
        var: String,
        not_unicode: bool,
    },
    /// The command could not be started, exited non-zero, or timed out.
    /// Its stderr is deliberately NOT carried: it is written for the human at
    /// the terminal and may quote the secret it failed to fetch.
    CommandFailed {
        message: String,
    },
    /// The command printed nothing — a silent empty password is worse than a
    /// loud failure (it reads as "no password configured" downstream).
    Empty {
        source: &'static str,
    },
    /// `{ keychain = ... }` on a platform without one.
    KeychainUnsupported,
    /// No such item: it was never created, or created under another name.
    KeychainNotFound {
        item: String,
    },
    /// The item exists but this binary is not in its ACL — nyet was rebuilt
    /// (`cargo install` changes the code signature), so it is no longer the
    /// application the item trusts.
    KeychainNotOurs {
        item: String,
    },
    KeychainFailed {
        message: String,
    },
}

/// The value itself. IO happens here and only here, and only for the
/// connection actually in use — `nyet list` never touches a keychain.
pub fn resolve(secret: &Secret) -> Result<String, SecretError> {
    match secret {
        Secret::Literal(text) => Ok(text.clone()),
        Secret::Elsewhere(r) => {
            if let Some(var) = &r.env {
                return from_env(var);
            }
            if let Some(command) = &r.command {
                return from_command(command);
            }
            if let Some(item) = &r.keychain {
                return from_keychain(item);
            }
            // config::Secret::validate rejects "no source" at parse time.
            unreachable!("a secret reference names exactly one source")
        }
    }
}

fn from_env(var: &str) -> Result<String, SecretError> {
    match std::env::var(var) {
        Ok(value) if value.is_empty() => Err(SecretError::Empty { source: "env" }),
        Ok(value) => Ok(value),
        Err(std::env::VarError::NotUnicode(_)) => Err(SecretError::MissingEnvVar {
            var: var.to_string(),
            not_unicode: true,
        }),
        Err(_) => Err(SecretError::MissingEnvVar {
            var: var.to_string(),
            not_unicode: false,
        }),
    }
}

/// `sh -c` on purpose: the config owner writes this line, and pipes into `jq`
/// are the normal shape of a `bw get ... | jq -r` recipe. `${VAR}` inside it
/// is rejected at parse time, so the agent cannot rewrite the command through
/// the environment.
fn from_command(command: &str) -> Result<String, SecretError> {
    let failed = |message: String| SecretError::CommandFailed { message };
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        // Swallowed rather than inherited: the agent reads nyet's stderr, and
        // a password manager's diagnostics are not for it.
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| failed(format!("could not run the command: {e}")))?;

    let deadline = Instant::now() + COMMAND_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(failed(format!(
                    "the command did not finish within {}s",
                    COMMAND_TIMEOUT.as_secs()
                )));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return Err(failed(format!("could not wait for the command: {e}"))),
        }
    };
    if !status.success() {
        return Err(failed(match status.code() {
            Some(code) => format!("the command exited with status {code}"),
            None => "the command was killed by a signal".to_string(),
        }));
    }
    let mut out = String::new();
    child
        .stdout
        .take()
        .expect("stdout is piped")
        .read_to_string(&mut out)
        .map_err(|e| failed(format!("the command's output is not valid UTF-8 ({e})")))?;
    // One trailing newline is how every CLI prints a value; anything else is
    // the secret's own business.
    let value = out.strip_suffix('\n').unwrap_or(&out);
    let value = value.strip_suffix('\r').unwrap_or(value);
    match value.is_empty() {
        true => Err(SecretError::Empty { source: "command" }),
        false => Ok(value.to_string()),
    }
}

#[cfg(target_os = "macos")]
fn from_keychain(item: &str) -> Result<String, SecretError> {
    use security_framework::base::Error as SfError;
    use security_framework::os::macos::keychain::SecKeychain;

    // No dialog, ever, on the read path: this call can be triggered by the
    // agent, and a prompt on the human's screen at that moment is both a
    // nuisance and a thing to click through without reading. The error codes
    // below say precisely what happened instead. The guard restores the
    // process-wide setting on drop.
    let _no_ui = SecKeychain::disable_user_interaction().map_err(|e: SfError| {
        SecretError::KeychainFailed {
            message: format!("the keychain could not be asked quietly ({})", e.code()),
        }
    })?;
    let keychain = SecKeychain::default().map_err(|e: SfError| SecretError::KeychainFailed {
        message: format!("the login keychain could not be opened ({})", e.code()),
    })?;
    match keychain.find_generic_password(KEYCHAIN_SERVICE, item) {
        Ok((password, _)) => String::from_utf8(password.to_vec())
            .map_err(|_| SecretError::KeychainFailed {
                message: "the stored value is not valid UTF-8".to_string(),
            })
            .and_then(|value| match value.is_empty() {
                true => Err(SecretError::Empty { source: "keychain" }),
                false => Ok(value),
            }),
        Err(e) => Err(match e.code() {
            // errSecItemNotFound
            -25300 => SecretError::KeychainNotFound {
                item: item.to_string(),
            },
            // errSecAuthFailed: the item is there, this binary is not in its
            // ACL. Measured: exactly what a rebuilt nyet gets.
            -25293 => SecretError::KeychainNotOurs {
                item: item.to_string(),
            },
            code => SecretError::KeychainFailed {
                message: format!("the keychain refused the read (error {code})"),
            },
        }),
    }
}

#[cfg(not(target_os = "macos"))]
fn from_keychain(_item: &str) -> Result<String, SecretError> {
    Err(SecretError::KeychainUnsupported)
}

/// Write the item, creating it as nyet so the ACL names nyet and nothing else.
/// Overwriting an existing item is what a rebuilt binary has to do, and the OS
/// asks the human for the keychain password there — that prompt is the whole
/// point, and it only ever happens inside this deliberate command.
#[cfg(target_os = "macos")]
pub fn store_in_keychain(item: &str, value: &str) -> Result<(), SecretError> {
    use security_framework::os::macos::keychain::SecKeychain;

    let keychain = SecKeychain::default().map_err(|e| SecretError::KeychainFailed {
        message: format!("the login keychain could not be opened ({})", e.code()),
    })?;
    keychain
        .set_generic_password(KEYCHAIN_SERVICE, item, value.as_bytes())
        .map_err(|e| match e.code() {
            -25293 => SecretError::KeychainNotOurs {
                item: item.to_string(),
            },
            code => SecretError::KeychainFailed {
                message: format!("the keychain refused the write (error {code})"),
            },
        })
}

#[cfg(not(target_os = "macos"))]
pub fn store_in_keychain(_item: &str, _value: &str) -> Result<(), SecretError> {
    Err(SecretError::KeychainUnsupported)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecretRef;

    fn reference(keychain: Option<&str>, env: Option<&str>, command: Option<&str>) -> Secret {
        Secret::Elsewhere(SecretRef {
            keychain: keychain.map(str::to_string),
            env: env.map(str::to_string),
            command: command.map(str::to_string),
        })
    }

    #[test]
    fn a_literal_resolves_to_itself() {
        let value = resolve(&Secret::Literal("hunter2".into())).unwrap();
        assert_eq!(value, "hunter2");
    }

    #[test]
    fn a_command_gives_its_stdout_without_the_trailing_newline() {
        let value = resolve(&reference(None, None, Some("printf 'hunter2\\n'"))).unwrap();
        assert_eq!(value, "hunter2");
        // Only ONE newline is the CLI's; the rest belongs to the secret.
        let value = resolve(&reference(None, None, Some("printf 'a\\n\\n'"))).unwrap();
        assert_eq!(value, "a\n");
    }

    /// A failing helper must not become an empty password: an empty string
    /// would travel on as "no password" and produce a confusing auth error
    /// three layers down.
    #[test]
    fn a_failing_or_silent_command_is_an_error_not_an_empty_secret() {
        let err = resolve(&reference(None, None, Some("exit 7"))).unwrap_err();
        assert!(matches!(err, SecretError::CommandFailed { .. }), "{err:?}");
        let err = resolve(&reference(None, None, Some("true"))).unwrap_err();
        assert!(matches!(err, SecretError::Empty { .. }), "{err:?}");
    }

    #[test]
    fn a_command_that_hangs_is_killed_not_awaited_forever() {
        // The real timeout is 30s; this proves the kill path exists without
        // paying for it: the command dies on its own, the loop reaps it.
        let value = resolve(&reference(None, None, Some("sleep 0.1; printf x"))).unwrap();
        assert_eq!(value, "x");
    }

    #[test]
    fn a_missing_env_var_names_the_variable() {
        let err = resolve(&reference(None, Some("NYET_NO_SUCH_VAR_XYZ"), None)).unwrap_err();
        match err {
            SecretError::MissingEnvVar { var, not_unicode } => {
                assert_eq!(var, "NYET_NO_SUCH_VAR_XYZ");
                assert!(!not_unicode);
            }
            other => panic!("expected MissingEnvVar, got {other:?}"),
        }
    }
}
