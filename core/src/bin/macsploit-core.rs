use macsploit_core::{
    database::Store,
    error::{CoreError, Result},
    orchestration::Engine,
    protocol::*,
};
use std::{
    io::{self, BufRead, Read, Write},
    path::PathBuf,
    time::Duration,
};

fn serve() -> Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let root = match arguments.as_slice() {
        [flag, path] if flag == "--data-dir" => PathBuf::from(path),
        [] => PathBuf::from(
            std::env::var_os("HOME")
                .ok_or_else(|| CoreError::new("StorageError", "Home directory is unavailable."))?,
        )
        .join("Library/Application Support/MACSPLOIT"),
        _ => {
            return Err(CoreError::new(
                "InvalidRequest",
                "Usage: macsploit-core [--data-dir ABSOLUTE_PATH]",
            ))
        }
    };
    let engine = Engine::open(Store::open(root)?, Duration::from_millis(250))?;
    eprintln!(
        "{}",
        serde_json::json!({"event":"CoreReady","protocol_version":VERSION})
    );
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    loop {
        let mut frame = Vec::new();
        let count = (&mut reader)
            .take((MAX_REQUEST_BYTES + 1) as u64)
            .read_until(b'\n', &mut frame)?;
        if count == 0 {
            break;
        }
        let oversized = frame.len() > MAX_REQUEST_BYTES;
        let response = if oversized {
            Response::failure(
                String::new(),
                CoreError::new("InvalidRequest", "Request exceeds the 64 KiB limit."),
            )
        } else {
            match serde_json::from_slice::<Request>(&frame) {
                Ok(request) => {
                    let method = request.command.name();
                    let response = handle(&engine, request);
                    // Empty polling is routine; keep long idle sessions out of the log.
                    if method != "events_after" || response.error.is_some() {
                        eprintln!(
                            "{}",
                            serde_json::json!({"timestamp":macsploit_core::now(),"event":"RequestCompleted","method":method,"success":response.error.is_none()})
                        );
                    }
                    response
                }
                Err(_) => Response::failure(
                    String::new(),
                    CoreError::new(
                        "InvalidRequest",
                        "Request does not match protocol version 1.",
                    ),
                ),
            }
        };
        let mut data = serde_json::to_vec(&response)?;
        if data.len() > MAX_RESPONSE_BYTES {
            data = serde_json::to_vec(&Response::failure(
                response.request_id,
                CoreError::new("BudgetExceeded", "Response exceeds the 8 MiB limit."),
            ))?;
        }
        data.push(b'\n');
        if writer
            .write_all(&data)
            .and_then(|_| writer.flush())
            .is_err()
        {
            break;
        }
        if oversized {
            break;
        }
    }
    engine.shutdown();
    eprintln!("{}", serde_json::json!({"event":"CoreStopped"}));
    Ok(())
}

fn main() {
    std::panic::set_hook(Box::new(|_| eprintln!("{{\"event\":\"CorePanic\"}}")));
    if let Err(error) = serve() {
        eprintln!(
            "{}",
            serde_json::json!({"event":"CoreFailed","code":error.code})
        );
        std::process::exit(1);
    }
}
