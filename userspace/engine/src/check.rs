use super::Options;
use std::{arch::x86_64::__cpuid_count, fs, path::Path, process::Command};

type Check = Result<String, String>;

fn output(command: &mut Command) -> Check {
    let result = command
        .output()
        .map_err(|error| format!("{}: {error}", command.get_program().to_string_lossy()))?;
    if !result.status.success() {
        return Err(String::from_utf8_lossy(&result.stderr).trim().to_owned());
    }
    Ok(String::from_utf8_lossy(&result.stdout).trim().to_owned())
}

fn text(path: impl AsRef<Path>) -> Check {
    let path = path.as_ref();
    fs::read_to_string(path)
        .map(|value| value.trim().to_owned())
        .map_err(|error| format!("{}: {error}", path.display()))
}

fn cpu() -> Check {
    // Rust 1.85 declares this intrinsic unsafe.
    #[allow(unused_unsafe)]
    let available = unsafe {
        __cpuid_count(0, 0).eax >= 0x12
            && __cpuid_count(7, 0).ebx & (1 << 2) != 0
            && __cpuid_count(0x12, 0).eax & 1 != 0
            && __cpuid_count(0x12, 2).eax & 15 == 1
    };
    if available {
        Ok("SGX1 and an enabled EPC section".into())
    } else {
        Err("OEM enclaves require SGX1 with EPC enabled in firmware".into())
    }
}

fn platform() -> Check {
    let model = text("/sys/class/dmi/id/product_name")?;
    if model != "MACHR-WX9" {
        return Err(format!("transport targets MACHR-WX9; found {model}"));
    }
    let devices = fs::read_dir("/sys/bus/acpi/devices").map_err(|error| error.to_string())?;
    for device in devices {
        let device = device.map_err(|error| error.to_string())?;
        if device
            .file_name()
            .to_string_lossy()
            .starts_with("GXFP51B7:")
        {
            return Ok("MACHR-WX9 / GXFP51B7".into());
        }
    }
    Err("GXFP51B7 ACPI device is absent".into())
}

fn module(kernel: &str, name: &str, explicit: Option<&Path>) -> Check {
    let target = explicit.unwrap_or_else(|| Path::new(name));
    let vermagic = output(
        Command::new("modinfo")
            .args(["-k", kernel, "-F", "vermagic"])
            .arg(target),
    )?;
    if vermagic.split_whitespace().next() != Some(kernel) {
        return Err(format!(
            "{name}: built for a different kernel; rebuild its DKMS package"
        ));
    }
    let filename = output(
        Command::new("modinfo")
            .args(["-k", kernel, "-F", "filename"])
            .arg(target),
    )?;
    Ok(filename)
}

fn assets(directory: &Path) -> Check {
    for name in [
        "windows-le.pages",
        "goodix.pages",
        "engine.pages",
        "goodix-mrenclave.bin",
        "goodix-mrsigner.bin",
        "engine-mrenclave.bin",
        "engine-mrsigner.bin",
        "goodix-whitelist.bin",
        "gfspi.dll",
    ] {
        let path = directory.join(name);
        let metadata =
            fs::metadata(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        if !metadata.is_file() || metadata.len() == 0 {
            return Err(format!(
                "{}: expected a nonempty regular file",
                path.display()
            ));
        }
        fs::File::open(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    }
    Ok(format!(
        "nine OEM assets readable in {}",
        directory.display()
    ))
}

fn secure_boot() -> Check {
    let efivars = Path::new("/sys/firmware/efi/efivars");
    let enabled = if efivars.exists() {
        let bytes = fs::read(efivars.join("SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"))
            .map_err(|error| format!("read SecureBoot EFI variable: {error}"))?;
        match bytes.get(4) {
            Some(0) => false,
            Some(1) => true,
            _ => return Err("invalid SecureBoot EFI variable".into()),
        }
    } else {
        false
    };
    let lockdown = Path::new("/sys/kernel/security/lockdown");
    let locked = lockdown.exists() && !text(lockdown)?.contains("[none]");
    let enforced = Path::new("/sys/module/module/parameters/sig_enforce");
    let enforced = enforced.exists() && matches!(text(enforced)?.as_str(), "Y" | "1");
    if enabled || locked || enforced {
        output(Command::new("/usr/bin/goodix-milanl-secure-boot").arg("check"))
    } else {
        Ok("Secure Boot, lockdown and forced module signatures are off".into())
    }
}

fn selinux() -> Check {
    let enforce = Path::new("/sys/fs/selinux/enforce");
    if !enforce.exists() {
        return Ok("disabled; no policy installation needed".into());
    }
    let mode = if text(enforce)? == "1" {
        "enforcing"
    } else {
        "permissive"
    };
    let policies = output(Command::new("semodule").arg("-l"))?;
    if !policies
        .lines()
        .any(|line| line.split_whitespace().next() == Some("goodix_milanl"))
    {
        return Err(format!(
            "{mode}; install the packaged goodix_milanl SELinux policy"
        ));
    }
    output(Command::new("matchpathcon").args([
        "-V",
        "/usr/bin/goodix-milanl-engine",
        "/usr/lib/goodix-milanl/oem",
    ]))?;
    if Path::new("/var/lib/goodix-milanl").exists() {
        output(Command::new("matchpathcon").args(["-V", "/var/lib/goodix-milanl"]))?;
    }
    Ok(format!(
        "{mode}; goodix_milanl policy installed and persistent paths labeled"
    ))
}

fn integration() -> Check {
    let dependencies = output(Command::new("systemctl").args([
        "show",
        "fprintd.service",
        "--property=Requires",
        "--value",
    ]))?;
    if !dependencies
        .split_whitespace()
        .any(|unit| unit == "goodix-milanl-engine.service")
    {
        return Err("fprintd.service is missing its goodix-milanl-engine dependency".into());
    }
    let environment = output(Command::new("systemctl").args([
        "show",
        "fprintd.service",
        "--property=Environment",
        "--value",
    ]))?;
    if !environment
        .split_whitespace()
        .any(|entry| entry == "GOODIX_MILANL_ENGINE=/run/goodix-milanl/engine.sock")
    {
        return Err(
            "fprintd.service is missing GOODIX_MILANL_ENGINE; install the engine drop-in".into(),
        );
    }
    Ok("fprintd dependency and engine socket configured".into())
}

pub(super) fn run(options: &Options) -> bool {
    println!("Goodix MilanL deployment check (read-only)");
    let mut passed = true;
    let mut report = |name: &str, result: Check| match result {
        Ok(detail) => println!("OK   {name}: {detail}"),
        Err(detail) => {
            println!("FAIL {name}: {detail}");
            passed = false;
        }
    };
    report("CPU", cpu());
    report("Platform", platform());
    match text("/proc/sys/kernel/osrelease") {
        Ok(kernel) => {
            let headers = format!("/usr/lib/modules/{kernel}/build/Makefile");
            report(
                "DKMS headers",
                if Path::new(&headers).is_file() {
                    Ok(kernel.clone())
                } else {
                    Err(format!("install headers for {kernel}"))
                },
            );
            report("isgx", module(&kernel, "isgx", options.isgx.as_deref()));
            report(
                "Transport",
                module(
                    &kernel,
                    "goodix_milanl_transport",
                    options.transport.as_deref(),
                ),
            );
        }
        Err(error) => report("Kernel", Err(error)),
    }
    report("OEM assets", assets(&options.config.assets));
    report("Module trust", secure_boot());
    report("SELinux", selinux());
    report("Service integration", integration());
    println!("Sensor untouched; no modules loaded, services started or settings changed.");
    passed
}
