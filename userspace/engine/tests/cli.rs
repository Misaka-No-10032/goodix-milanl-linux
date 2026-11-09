use std::process::Command;

const BINARY: &str = env!("CARGO_BIN_EXE_goodix-milanl-engine");

#[test]
fn help_is_native_and_does_not_need_hardware_or_root() {
    let output = Command::new(BINARY).arg("--help").output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("goodix-milanl-engine --socket PATH --assets DIRECTORY"));
    assert!(help.contains("--device PATH"));
    assert!(help.contains("--check"));
    assert!(help.contains("/dev/goodix-milanl-raw"));
}

#[test]
fn version_identifies_sensor_family() {
    let output = Command::new(BINARY).arg("--version").output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("goodix-milanl-engine {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn check_reports_missing_assets_without_starting_the_service() {
    let output = Command::new(BINARY)
        .args(["--check", "--assets", "/nonexistent/goodix-milanl-oem"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    let report = String::from_utf8(output.stdout).unwrap();
    assert!(report.starts_with("Goodix MilanL deployment check (read-only)"));
    assert!(report.contains("FAIL OEM assets:"));
    assert!(
        report
            .contains("Sensor untouched; no modules loaded, services started or settings changed.")
    );
}

#[test]
fn invalid_arguments_fail_before_hardware_access() {
    for args in [
        vec!["--invalid"],
        vec!["--socket"],
        vec!["--assets", "/nonexistent"],
        vec!["--device"],
    ] {
        let output = Command::new(BINARY).args(args).output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("Usage: goodix-milanl-engine")
        );
    }
}
