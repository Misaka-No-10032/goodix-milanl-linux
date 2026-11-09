mod check;

use goodix_milanl_engine::{
    engine::{Config, Engine},
    error::{Error, Result},
    lifecycle::{Modules, RequestControl, Shutdown, protect_process},
    server::{Listener, notify_ready, serve_connection},
};
use std::{env, path::PathBuf, process::ExitCode, rc::Rc};

const USAGE: &str = "Usage: goodix-milanl-engine --socket PATH --assets DIRECTORY [OPTIONS]
       goodix-milanl-engine --check [--assets DIRECTORY] [OPTIONS]

Native Goodix MilanL backend for libfprint. The service requires root.

  --check                  Read-only deployment checks; never opens the sensor
  --socket PATH            Unix socket in an existing private directory
  --assets DIRECTORY       Originally signed enclave assets and gfspi.dll
  --device PATH            Raw transport (default: /dev/goodix-milanl-raw)
  --state DIRECTORY        OEM calibration (default: /var/lib/goodix-milanl)
  --isgx-module PATH       Load a specific isgx.ko instead of modprobe
  --transport-module PATH  Load a specific transport .ko instead of modprobe
  -h, --help               Show this help
  -V, --version            Show the program version

Templates are stored by fprintd.";

struct Options {
    socket: PathBuf,
    config: Config,
    isgx: Option<PathBuf>,
    transport: Option<PathBuf>,
}

enum Arguments {
    Help,
    Version,
    Check(Options),
    Run(Options),
}

fn arguments() -> std::result::Result<Arguments, &'static str> {
    let mut args = env::args_os().skip(1);
    let (mut socket, mut assets, mut isgx, mut transport) = (None, None, None, None);
    let mut device = PathBuf::from("/dev/goodix-milanl-raw");
    let mut state = PathBuf::from("/var/lib/goodix-milanl");
    let mut check = false;
    while let Some(option) = args.next() {
        match option.to_str() {
            Some("-h" | "--help") => return Ok(Arguments::Help),
            Some("-V" | "--version") => return Ok(Arguments::Version),
            Some("--check") => check = true,
            Some("--socket") => {
                socket = Some(PathBuf::from(
                    args.next().ok_or("--socket requires a path")?,
                ))
            }
            Some("--assets") => {
                assets = Some(PathBuf::from(
                    args.next().ok_or("--assets requires a directory")?,
                ))
            }
            Some("--device") => {
                device = PathBuf::from(args.next().ok_or("--device requires a path")?)
            }
            Some("--state") => {
                state = PathBuf::from(args.next().ok_or("--state requires a directory")?)
            }
            Some("--isgx-module") => {
                isgx = Some(PathBuf::from(
                    args.next().ok_or("--isgx-module requires a path")?,
                ))
            }
            Some("--transport-module") => {
                transport = Some(PathBuf::from(
                    args.next().ok_or("--transport-module requires a path")?,
                ))
            }
            _ => return Err("unknown command-line option"),
        }
    }
    if check {
        socket.get_or_insert_with(|| PathBuf::from("/run/goodix-milanl/engine.sock"));
        assets.get_or_insert_with(|| PathBuf::from("/usr/lib/goodix-milanl/oem"));
    }
    let options = Options {
        socket: socket.ok_or("--socket is required")?,
        config: Config {
            assets: assets.ok_or("--assets is required")?,
            device,
            state,
        },
        isgx,
        transport,
    };
    Ok(if check {
        Arguments::Check(options)
    } else {
        Arguments::Run(options)
    })
}

fn run(options: Options) -> Result<()> {
    protect_process()?;
    if unsafe { libc::geteuid() } != 0 {
        return Err(Error::Device("the service must run as root"));
    }
    let shutdown = Rc::new(Shutdown::new()?);
    let mut modules = Modules::new(options.isgx, options.transport);
    let mut listener = Listener::bind(&options.socket)?;
    let result = (|| {
        eprintln!("goodix-milanl-engine: listening");
        notify_ready()?;
        loop {
            let peer = Rc::new(listener.accept(&shutdown)?);
            let control = Rc::new(RequestControl::new(shutdown.clone(), peer.clone()));
            let mut engine = Engine::new(&options.config, &mut modules, control.clone());
            serve_connection(peer, &shutdown, &control, &mut engine)?;
        }
    })();
    let socket_result = listener.close();
    let module_result = modules.close();
    let result = match result {
        Err(Error::Shutdown) => Ok(()),
        result => result,
    };
    socket_result.and(module_result).and(result)
}

fn main() -> ExitCode {
    let options = match arguments() {
        Ok(Arguments::Help) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Ok(Arguments::Version) => {
            println!("goodix-milanl-engine {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Ok(Arguments::Check(options)) => {
            return if check::run(&options) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            };
        }
        Ok(Arguments::Run(options)) => options,
        Err(error) => {
            eprintln!("{error}\n\n{USAGE}");
            return ExitCode::FAILURE;
        }
    };
    match run(options) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("goodix-milanl-engine: {error}");
            ExitCode::FAILURE
        }
    }
}
