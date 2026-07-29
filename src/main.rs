use std::collections::HashMap;
use std::fs;
#[cfg(windows)]
use std::io::Read;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crossterm::cursor::MoveTo;
use crossterm::event::{read, Event, KeyCode};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, Clear, ClearType};
use crossterm::ExecutableCommand;
use sha2::{Digest, Sha256};

use crustacian::edr_transport;

#[cfg(windows)]
const DEFAULT_CLAM_DIR: &str = r"C:\Program Files\ClamAV";
#[cfg(unix)]
const DEFAULT_CLAM_DIR: &str = "/etc/clamav";

fn main() {
    loop {
        let selected = select_from_menu(
            "Main Console",
            "Operational menu",
            "choose a ClamAV task or endpoint telemetry preview",
            &[
                "Initialize / repair ClamAV environment",
                "Run a new scan",
                "View previous scans",
                "Endpoint EDR R&D preview",
                "Exit",
            ],
        );

        match selected {
            Some(0) => init_cmd(),
            Some(1) => scan_cmd(),
            Some(2) => history_menu(),
            Some(3) => endpoint_rd_menu(),
            Some(4) | None => {
                println!("Goodbye.");
                break;
            }
            _ => {}
        }
    }
}

fn init_cmd() {
    let clamdir = String::from(DEFAULT_CLAM_DIR);
    println!("=== Initialize / Repair ClamAV Environment ===");

    #[cfg(unix)]
    {
        println!("[+] Detecting Linux environment...");
        if let Err(e) = init_linux(&clamdir) {
            eprintln!("[!] Linux initialization failed: {e}");
            wait_for_enter();
            return;
        }
    }

    #[cfg(windows)]
    {
        if let Err(e) = make_dirs(&clamdir) {
            eprintln!("[!] Failed to create base directories: {e}");
            wait_for_enter();
            return;
        }

        // 1) Ensure binaries exist (clamd.exe / freshclam.exe)
        if let Err(e) = ensure_clam_binaries(&clamdir) {
            eprintln!("[!] Could not ensure ClamAV binaries: {e}");
            println!("    Please verify manual install and try again.");
            wait_for_enter();
            return;
        }

        // 2) Write config files (clamd.conf / freshclam.conf)
        println!("[+] Writing config files...");
        if let Err(e) = write_clam_confs(&clamdir) {
            eprintln!("[!] Failed writing config files: {e}");
            wait_for_enter();
            return;
        }

        // 3) Ensure DB is updated and present
        println!("[+] Ensuring signature database is present and up to date...");
        if let Err(e) = ensure_db_updated(&clamdir) {
            eprintln!("[!] Failed to update/download signatures: {e}");
            println!("    Check your network/DNS (database.clamav.net) and try again.");
            wait_for_enter();
            return;
        }

        // 4) Ensure clamd service installed and running
        println!("[+] Ensuring clamd service is installed and running...");
        if let Err(e) = ensure_service_installed_and_running(&clamdir) {
            eprintln!("[!] Failed to start clamd service: {e}");
            println!("    Check clamd.log for details and try again.");
            wait_for_enter();
            return;
        }
    }

    println!("\n✅ Environment looks good. You should be able to run scans now.");
    println!("Press Enter to continue...");
    wait_for_enter();
}

#[cfg(unix)]
fn init_linux(_clamdir: &str) -> io::Result<()> {
    // 1) Check if clamav is installed
    if !cmd_exists("clamscan") {
        println!("[+] ClamAV not found. Installing via apt...");
        run("sudo", &["apt-get", "update"])?;
        run(
            "sudo",
            &["apt-get", "install", "-y", "clamav", "clamav-daemon"],
        )?;
    } else {
        println!("[+] ClamAV is already installed.");
    }

    // 2) Ensure freshclam is running/updated
    println!("[+] Ensuring freshclam service is active...");
    let _ = run("sudo", &["systemctl", "enable", "clamav-freshclam"]);
    let _ = run("sudo", &["systemctl", "start", "clamav-freshclam"]);

    // 3) Ensure clamd is running
    println!("[+] Ensuring clamav-daemon is active...");
    run("sudo", &["systemctl", "enable", "clamav-daemon"])?;
    run("sudo", &["systemctl", "start", "clamav-daemon"])?;

    Ok(())
}

fn scan_cmd() {
    let clamdir = String::from(DEFAULT_CLAM_DIR);

    let sel = select_from_menu(
        "Scan Target",
        "Nested scan menu",
        "choose what Crustacian should inspect",
        &[
            "Quick scan (Home, Documents, Downloads, Desktop, Temp)",
            "Full scan (Root / system drive)",
            "Custom paths",
            "Back",
        ],
    );
    let mut scan_targets: Vec<String> = Vec::new();

    match sel {
        Some(0) => {
            #[cfg(windows)]
            {
                let userprof = std::env::var("USERPROFILE")
                    .unwrap_or_else(|_| String::from(r"C:\Users\Public"));
                scan_targets.push(
                    Path::new(&userprof)
                        .join("Documents")
                        .to_string_lossy()
                        .into_owned(),
                );
                scan_targets.push(
                    Path::new(&userprof)
                        .join("Downloads")
                        .to_string_lossy()
                        .into_owned(),
                );
                scan_targets.push(
                    Path::new(&userprof)
                        .join("Desktop")
                        .to_string_lossy()
                        .into_owned(),
                );
                scan_targets.push(r"C:\Windows\Temp".to_string());
            }
            #[cfg(unix)]
            {
                let home = std::env::var("HOME").unwrap_or_else(|_| String::from("/home/cladmin"));
                scan_targets.push(
                    Path::new(&home)
                        .join("Documents")
                        .to_string_lossy()
                        .into_owned(),
                );
                scan_targets.push(
                    Path::new(&home)
                        .join("Downloads")
                        .to_string_lossy()
                        .into_owned(),
                );
                scan_targets.push(
                    Path::new(&home)
                        .join("Desktop")
                        .to_string_lossy()
                        .into_owned(),
                );
                scan_targets.push("/tmp".to_string());
            }
        }
        Some(1) => {
            #[cfg(windows)]
            scan_targets.push("C:\\".to_string());
            #[cfg(unix)]
            scan_targets.push("/".to_string());
        }
        Some(2) => {
            print!("Enter semicolon-separated paths: ");
            flush_stdout();
            let p = read_line();
            for s in p.split(';') {
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    scan_targets.push(trimmed.to_string());
                }
            }
        }
        _ => return,
    }

    let act = select_from_menu(
        "Infected File Action",
        "Nested scan menu",
        "destructive actions require an explicit selection",
        &["Report only", "Move to quarantine", "Delete", "Back"],
    );
    let mut mode = "report";
    if act == Some(1) {
        mode = "quarantine";
    } else if act == Some(2) {
        mode = "remove";
    } else if act.is_none() || act == Some(3) {
        return;
    }

    print!("\nDo a quick pre-count of files for better ETA? (Y/n): ");
    flush_stdout();
    let do_count = read_line().to_lowercase();
    let want_count = do_count.is_empty() || do_count == "y" || do_count == "yes";

    let mut total_files: i64 = 0;
    if want_count {
        println!("Counting files (this is fast and improves ETA)...");
        let start_count = Instant::now();
        match pre_count_files(&scan_targets) {
            Ok(count) => {
                total_files = count;
                println!(
                    "Found ~{} files in {:?}.",
                    total_files,
                    start_count.elapsed()
                );
            }
            Err(e) => {
                println!("[!] Pre-count failed, falling back to adaptive ETA: {e}");
                total_files = 0;
            }
        }
    }

    let stamp = chrono_stamp();
    let report_dir = ensure_scan_dir(&stamp);
    println!("Saving results in: {}", report_dir.display());

    let mut args: Vec<String> = vec!["--fdpass".into(), "--recursive".into()];
    if mode == "quarantine" {
        #[cfg(windows)]
        let q_dir = r"C:\Quarantine";
        #[cfg(unix)]
        let q_dir = "/var/lib/crustacian/quarantine";

        let _ = fs::create_dir_all(q_dir);
        args.push(format!("--move={}", q_dir));
    } else if mode == "remove" {
        args.push("--remove".into());
    }
    for t in &scan_targets {
        args.push(t.clone());
    }

    println!("\nStarting scan... progress shows below.");

    #[cfg(windows)]
    let clamdscan_bin = "clamdscan.exe";
    #[cfg(unix)]
    let clamdscan_bin = "clamdscan";

    let clamdscan_path = Path::new(&clamdir).join(clamdscan_bin);
    // On Linux, clamdscan is usually in /usr/bin, so we might just use the name
    let mut cmd = if cfg!(unix) {
        Command::new(clamdscan_bin)
    } else {
        Command::new(clamdscan_path)
    };

    cmd.args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[!] Failed to start clamdscan: {e}");
            wait_for_enter();
            return;
        }
    };

    let stdout = child.stdout.take();
    let mut infected_lines: Vec<String> = Vec::new();
    let mut summary_lines: Vec<String> = Vec::new();

    let mut processed: i64 = 0;
    let spinner_chars: [char; 4] = ['|', '/', '-', '\\'];
    let mut spin_idx: usize = 0;
    let start = Instant::now();

    let mut rate_ema: f64 = 0.0;
    const EMA_ALPHA: f64 = 0.15;
    let mut adaptive_total: f64 = 0.0;

    if let Some(out) = stdout {
        let reader = io::BufReader::new(out);
        for line_res in reader.lines() {
            let ln = match line_res {
                Ok(l) => l,
                Err(_) => continue,
            };

            if ln.ends_with(": OK") || ln.contains(" FOUND") {
                processed += 1;
            }
            if ln.contains(" FOUND") {
                infected_lines.push(ln.clone());
                println!("\n⚠️  {}", ln);
            }

            if ln.starts_with("----------- SCAN SUMMARY -----------")
                || ln.starts_with("Infected files:")
                || ln.starts_with("Total errors:")
                || ln.starts_with("Time:")
                || ln.starts_with("Scanned files:")
                || ln.starts_with("Scanned directories:")
                || ln.starts_with("Known viruses:")
                || ln.starts_with("Engine version:")
            {
                summary_lines.push(ln.clone());
            }

            if processed % 200 == 0 {
                let elapsed = start.elapsed().as_secs_f64();
                if elapsed > 0.0 {
                    let inst_rate = processed as f64 / elapsed;
                    if rate_ema == 0.0 {
                        rate_ema = inst_rate;
                    } else {
                        rate_ema = EMA_ALPHA * inst_rate + (1.0 - EMA_ALPHA) * rate_ema;
                    }
                }

                let denom: f64 = if total_files > 0 {
                    total_files as f64
                } else {
                    let factor = if processed > 200_000 {
                        1.8
                    } else if processed > 50_000 {
                        2.0
                    } else {
                        2.5
                    };
                    adaptive_total = adaptive_total.max(processed as f64 * factor);
                    adaptive_total
                };

                let mut pct = 0.0;
                if denom > 0.0 {
                    pct = (processed as f64 / denom) * 100.0;
                    if pct > 99.9 && total_files == 0 {
                        pct = 99.9;
                    }
                }

                let eta = if rate_ema > 0.0 && denom > 0.0 {
                    let mut remaining = denom - processed as f64;
                    if remaining < 0.0 {
                        remaining = 0.0;
                    }
                    let mut secs = remaining / rate_ema;
                    secs = secs * 1.25 + 30.0;
                    fmt_duration(Duration::from_secs_f64(secs))
                } else {
                    "…".to_string()
                };

                print!(
                    "\r{} Scanning… {:5.1}% | {} files | {:.0} f/s | ETA ~ {}",
                    spinner_chars[spin_idx],
                    pct,
                    human_count(
                        processed,
                        (if total_files > 0 {
                            total_files as f64
                        } else {
                            adaptive_total
                        }) as i64
                    ),
                    rate_ema,
                    eta
                );
                flush_stdout();
                spin_idx = (spin_idx + 1) % spinner_chars.len();
            }
        }
    }

    let _ = child.wait();
    let elapsed = start.elapsed();
    println!(
        "\r✓ Scanning… 100.0% | {} files | done in {}",
        processed,
        fmt_duration(elapsed)
    );

    let infected_list = report_dir.join("infected.txt");
    let summary_file = report_dir.join("summary.txt");
    let _ = fs::write(&infected_list, infected_lines.join("\n"));
    let _ = fs::write(&summary_file, summary_lines.join("\n"));
    if let Err(e) = write_scan_telemetry(&report_dir, &scan_targets, mode, &infected_lines) {
        eprintln!("[!] Failed to write endpoint telemetry preview: {e}");
    }

    println!("\nSummary:");
    for s in &summary_lines {
        println!(" {}", s);
    }
    if !infected_lines.is_empty() {
        println!(
            "\n⚠️  {} infections found. Details saved to {}",
            infected_lines.len(),
            infected_list.display()
        );
    } else {
        println!("No infections found.");
    }

    println!("\nPress Enter to return to main menu...");
    wait_for_enter();
}

fn endpoint_rd_menu() {
    loop {
        let selected = select_from_menu(
            "Endpoint EDR Preview",
            "R&D telemetry menu",
            "generate local-only endpoint artifacts or ship the spool",
            &[
                "Write SIEM telemetry config template",
                "Generate local endpoint telemetry snapshot",
                "Generate response action plan",
                "Run first-stage integration dry run",
                "Show local telemetry spool status",
                "Ship telemetry spool to ingest server",
                "Back",
            ],
        );

        match selected {
            Some(0) => match write_endpoint_config_template() {
                Ok(path) => println!("Wrote template: {}", path.display()),
                Err(e) => eprintln!("[!] Failed to write template: {e}"),
            },
            Some(1) => match write_endpoint_snapshot("manual_snapshot") {
                Ok((path, hash)) => {
                    println!("Wrote snapshot: {}", path.display());
                    println!("Snapshot SHA-256: {hash}");
                }
                Err(e) => eprintln!("[!] Failed to write snapshot: {e}"),
            },
            Some(2) => match write_response_action_plan("manual_rd_review", true, true, true) {
                Ok(path) => println!("Wrote disabled response plan: {}", path.display()),
                Err(e) => eprintln!("[!] Failed to write response plan: {e}"),
            },
            Some(3) => match write_integration_dry_run("manual_integration_check") {
                Ok(path) => println!("Wrote integration dry-run record: {}", path.display()),
                Err(e) => eprintln!("[!] Failed to write integration dry-run record: {e}"),
            },
            Some(4) => show_telemetry_spool_status(),
            Some(5) => ship_telemetry_spool_menu(),
            _ => return,
        }

        println!("\nPress Enter to return to the endpoint menu...");
        wait_for_enter();
    }
}

fn history_menu() {
    let scans = list_scan_dirs();
    if scans.is_empty() {
        println!("No scans found.");
        wait_for_enter();
        return;
    }

    let mut options: Vec<String> = scans
        .iter()
        .map(|d| {
            d.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    options.push("Back".to_string());
    let option_refs: Vec<&str> = options.iter().map(String::as_str).collect();

    let selected = select_from_menu(
        "Scan History",
        "Nested history menu",
        "choose a previous scan report to view",
        &option_refs,
    );
    let Some(idx) = selected else {
        return;
    };
    if idx >= scans.len() {
        return;
    }

    let d = &scans[idx];
    println!(
        "===== {} =====",
        d.file_name().unwrap_or_default().to_string_lossy()
    );
    show_if_exists(&d.join("summary.txt"));
    println!("--- Infected ---");
    show_if_exists(&d.join("infected.txt"));
    println!("Press Enter to return...");
    wait_for_enter();
}

// ========== NEW / IMPROVED INIT HELPERS ==========

#[cfg(windows)]
fn ensure_clam_binaries(clamdir: &str) -> io::Result<()> {
    println!("[+] Checking for clamd.exe and freshclam.exe...");

    let clamd = Path::new(clamdir).join("clamd.exe");
    let fresh = Path::new(clamdir).join("freshclam.exe");

    if file_exists(clamd.clone()) && file_exists(fresh.clone()) {
        println!("    Found existing ClamAV binaries.");
        return Ok(());
    }

    println!("    ClamAV binaries not found. Trying winget/choco install...");
    try_install_clamav()?;

    // Re-check after install attempt
    let clamd = Path::new(clamdir).join("clamd.exe");
    let fresh = Path::new(clamdir).join("freshclam.exe");

    if file_exists(clamd) && file_exists(fresh) {
        println!("    ClamAV installation detected.");
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "clamd.exe / freshclam.exe not found after install attempt",
        ))
    }
}

#[cfg(windows)]
fn ensure_db_updated(clamdir: &str) -> io::Result<()> {
    let max_attempts = 3;
    let freshclam_path = Path::new(clamdir).join("freshclam.exe");
    for attempt in 1..=max_attempts {
        println!(
            "    [Attempt {}/{}] Running freshclam...",
            attempt, max_attempts
        );
        let status = Command::new(&freshclam_path)
            .arg("-v")
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if status && db_is_present(clamdir) {
            println!("    Signatures present and freshclam succeeded.");
            return Ok(());
        }

        if db_is_present(clamdir) {
            println!("    Signatures present; continuing despite freshclam status.");
            return Ok(());
        }

        println!("    freshclam did not complete successfully or DB missing. Retrying in 10s...");
        std::thread::sleep(Duration::from_secs(10));
    }

    if db_is_present(clamdir) {
        println!("    DB appears present after retries; proceeding cautiously.");
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "signature DB not present after multiple freshclam attempts",
        ))
    }
}

#[cfg(windows)]
fn db_is_present(clamdir: &str) -> bool {
    let mut candidates = vec![
        Path::new(clamdir).join("db"),
        Path::new(clamdir).join("database"),
    ];

    candidates.push(PathBuf::from(r"C:\ProgramData\.clamwin\db"));
    candidates.push(PathBuf::from(r"C:\ProgramData\clamav-db"));

    for dir in candidates {
        if let Ok(entries) = fs::read_dir(&dir) {
            let mut seen_main = false;
            let mut seen_daily = false;
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_lowercase();
                if name.starts_with("main.") {
                    seen_main = true;
                }
                if name.starts_with("daily.") {
                    seen_daily = true;
                }
                if seen_main && seen_daily {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(windows)]
fn ensure_service_installed_and_running(clamdir: &str) -> io::Result<()> {
    let clamd_exe = Path::new(clamdir).join("clamd.exe");

    // 1) Ensure service exists
    if !service_exists("clamd") {
        println!("    clamd service not found; installing...");
        let status = Command::new(&clamd_exe).arg("--install").status();
        if !status.map(|s| s.success()).unwrap_or(false) {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "failed to run clamd.exe --install",
            ));
        }
    } else {
        println!("    clamd service already installed.");
    }

    // 2) Make sure the service is not disabled
    if service_is_disabled("clamd") {
        println!("    clamd service is disabled; re-enabling (start = demand)...");
        let status = Command::new("sc")
            .args(["config", "clamd", "start=", "demand"])
            .status();
        if !status.map(|s| s.success()).unwrap_or(false) {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "failed to re-enable clamd service (sc config clamd start= demand)",
            ));
        }
    }

    // 3) Try to start the service and capture output if it fails
    println!("    Starting clamd service...");
    let output = Command::new("cmd")
        .args(["/c", "net", "start", "clamd"])
        .output()?;

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("    net start clamd failed.");
        if !stdout.trim().is_empty() {
            println!("    --- net start output ---");
            println!("{stdout}");
        }
        if !stderr.trim().is_empty() {
            println!("    --- net start error ---");
            println!("{stderr}");
        }
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "failed to start clamd service (service may be disabled by policy or misconfigured)",
        ));
    }

    // 4) Wait for "daemon ready" in the log
    let log_path = Path::new(clamdir).join("clamd.log");
    println!("    Waiting for clamd to report ready (up to 60s)...");
    if wait_for_clam_ready(&log_path, Duration::from_secs(60)) {
        println!("    clamd reported ready.");
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "clamd did not report ready in time",
        ))
    }
}

#[cfg(windows)]
fn service_exists(name: &str) -> bool {
    Command::new("sc")
        .args(["query", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(windows)]
fn service_is_disabled(name: &str) -> bool {
    if let Ok(output) = Command::new("sc").args(["qc", name]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
        stdout
            .lines()
            .any(|line| line.contains("start_type") && line.contains("disabled"))
    } else {
        false
    }
}

// ========== GENERIC HELPERS (unchanged / lightly tweaked) ==========

const MENU_WIDTH: usize = 78;

struct RawModeGuard;

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}

fn select_from_menu(title: &str, stage: &str, reason: &str, options: &[&str]) -> Option<usize> {
    if options.is_empty() {
        return None;
    }

    if enable_raw_mode().is_err() {
        return fallback_select_from_menu(title, options);
    }
    let raw_guard = RawModeGuard;

    let mut selected: usize = 0;
    render_menu(title, stage, reason, options, selected);

    loop {
        match read() {
            Ok(Event::Key(event)) => match event.code {
                KeyCode::Up | KeyCode::Char('k') | KeyCode::Char('K') => {
                    selected = selected.checked_sub(1).unwrap_or(options.len() - 1);
                    render_menu(title, stage, reason, options, selected);
                }
                KeyCode::Down | KeyCode::Char('j') | KeyCode::Char('J') => {
                    selected = (selected + 1) % options.len();
                    render_menu(title, stage, reason, options, selected);
                }
                KeyCode::Enter => {
                    clear_terminal();
                    return Some(selected);
                }
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q') => {
                    clear_terminal();
                    return None;
                }
                _ => {}
            },
            Ok(_) => {}
            Err(_) => {
                clear_terminal();
                drop(raw_guard);
                return fallback_select_from_menu(title, options);
            }
        }
    }
}

fn render_menu(title: &str, stage: &str, reason: &str, options: &[&str], selected: usize) {
    clear_terminal();
    println!("{}", "=".repeat(MENU_WIDTH));
    for line in [
        "",
        "    ______                __             _",
        "   / ____/______  _______/ /_____ ______(_)___ _____",
        "  / /   / ___/ / / / ___/ __/ __ `/ ___/ / __ `/ __ \\",
        " / /___/ /  / /_/ (__  ) /_/ /_/ / /__/ / /_/ / / / /",
        " \\____/_/   \\__,_/____/\\__/\\__,_/\\___/_/\\__,_/_/ /_/",
        "",
        "                     Protecting those who protect.",
        "",
    ] {
        println!("{}", menu_box_line(line));
    }
    println!("={}=", "-".repeat(MENU_WIDTH - 2));
    println!("{}", menu_box_line(&format!("menu     {title}")));
    println!(
        "{}",
        menu_box_line(&format!("repo     {}", current_repo_display()))
    );
    println!(
        "{}",
        menu_box_line(&format!("clamav   {}", DEFAULT_CLAM_DIR))
    );
    println!("{}", menu_box_line(&format!("stage    {stage}")));
    println!("{}", menu_box_line(&format!("reason   {reason}")));
    println!("{}", menu_box_line(""));
    println!("{}", menu_box_line("Status"));
    println!(
        "{}",
        menu_box_line(&format!("  platform  {}", std::env::consts::OS))
    );
    println!(
        "{}",
        menu_box_line(&format!("  reports   {}", base_scans_dir().display()))
    );
    println!(
        "{}",
        menu_box_line(&format!("  scans     {}", list_scan_dirs().len()))
    );
    println!(
        "{}",
        menu_box_line(&format!("  edr spool {}", telemetry_spool_status_label()))
    );
    println!(
        "{}",
        menu_box_line(&format!("  git       {}", git_dirty_label()))
    );
    println!("{}", "=".repeat(MENU_WIDTH));
    println!();
    println!("? Select (Up/Down, Enter, q to back) >");
    for (idx, option) in options.iter().enumerate() {
        let cursor = if idx == selected { "❯" } else { " " };
        println!("{cursor} {option}");
    }
    flush_stdout();
}

fn menu_box_line(content: &str) -> String {
    let inner_width = MENU_WIDTH - 4;
    let mut inner = content.to_string();
    if inner.chars().count() > inner_width {
        inner = truncate_to_width(&inner, inner_width);
    }
    format!("= {inner:<inner_width$} =")
}

fn truncate_to_width(value: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }

    let mut out: String = value.chars().take(width.saturating_sub(1)).collect();
    out.push('~');
    out
}

fn current_repo_display() -> String {
    std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| String::from("unknown"))
}

fn git_dirty_label() -> &'static str {
    match Command::new("git")
        .args(["status", "--porcelain"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
    {
        Ok(output) if output.status.success() && output.stdout.is_empty() => "clean",
        Ok(output) if output.status.success() => "dirty",
        _ => "unknown",
    }
}

fn telemetry_spool_status_label() -> String {
    let path = siem_spool_path();
    match fs::metadata(path) {
        Ok(meta) => format!("present ({} bytes)", meta.len()),
        Err(_) => String::from("empty"),
    }
}

fn clear_terminal() {
    let mut stdout = io::stdout();
    let _ = stdout.execute(Clear(ClearType::All));
    let _ = stdout.execute(MoveTo(0, 0));
}

fn fallback_select_from_menu(title: &str, options: &[&str]) -> Option<usize> {
    loop {
        println!("================ Crustacian {title} ================");
        for (idx, option) in options.iter().enumerate() {
            println!("{}. {}", idx + 1, option);
        }
        print!("Select option (1-{}), or Enter to go back: ", options.len());
        flush_stdout();

        let sel = read_line();
        if sel.trim().is_empty() {
            return None;
        }
        if let Ok(idx) = sel.trim().parse::<usize>() {
            if (1..=options.len()).contains(&idx) {
                return Some(idx - 1);
            }
        }
        println!("Invalid choice.");
    }
}

fn flush_stdout() {
    let _ = io::stdout().flush();
}

fn wait_for_enter() {
    let mut buf = String::new();
    let _ = io::stdin().read_line(&mut buf);
}

fn read_line() -> String {
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).unwrap_or(0);
    buf.trim_end_matches(&['\n', '\r'][..]).to_string()
}

#[cfg(windows)]
fn file_exists(path: PathBuf) -> bool {
    fs::metadata(path).map(|m| m.is_file()).unwrap_or(false)
}

#[cfg(windows)]
fn make_dirs(clamdir: &str) -> io::Result<()> {
    fs::create_dir_all(clamdir)?;
    let d = base_scans_dir();
    fs::create_dir_all(d)?;
    Ok(())
}

fn base_scans_dir() -> PathBuf {
    #[cfg(windows)]
    {
        let user =
            std::env::var("USERPROFILE").unwrap_or_else(|_| String::from(r"C:\Users\Public"));
        Path::new(&user).join("Documents").join("cyberplexs-scans")
    }
    #[cfg(unix)]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| String::from("/home/cladmin"));
        Path::new(&home).join("Documents").join("cyberplexs-scans")
    }
}

fn ensure_scan_dir(stamp: &str) -> PathBuf {
    let d = base_scans_dir().join(stamp);
    let _ = fs::create_dir_all(&d);
    d
}

fn list_scan_dirs() -> Vec<PathBuf> {
    let base = base_scans_dir();
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = fs::read_dir(&base) {
        for e in entries.flatten() {
            if let Ok(ft) = e.file_type() {
                if ft.is_dir() {
                    dirs.push(e.path());
                }
            }
        }
    }
    dirs.sort_by(|a, b| {
        a.file_name()
            .unwrap_or_default()
            .cmp(b.file_name().unwrap_or_default())
    });
    dirs
}

fn run(name: &str, args: &[&str]) -> io::Result<()> {
    Command::new(name).args(args).status().map(|_| ())
}

#[cfg(windows)]
fn run_silent(name: &str, args: &[&str]) -> io::Result<()> {
    Command::new(name)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|_| ())
}

fn cmd_exists(name: &str) -> bool {
    #[cfg(windows)]
    {
        Command::new("cmd")
            .args(["/C", "where", name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(unix)]
    {
        Command::new("which")
            .arg(name)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

#[cfg(windows)]
fn try_install_clamav() -> io::Result<()> {
    if cmd_exists("winget") {
        println!("    [winget] Searching for ClamAV...");
        let _ = run("winget", &["search", "clamav"]);
        println!("    [winget] Trying install... (may require admin approval)");
        if run(
            "winget",
            &[
                "install",
                "--id",
                "ClamAV.ClamAV",
                "-e",
                "--accept-source-agreements",
                "--accept-package-agreements",
            ],
        )
        .is_ok()
        {
            return Ok(());
        }
    }

    if cmd_exists("choco") {
        println!("    [choco] Trying install clamav...");
        if run("choco", &["install", "clamav", "-y"]).is_ok() {
            return Ok(());
        }
    }

    Err(io::Error::new(
        io::ErrorKind::Other,
        "no package manager succeeded (winget/choco)",
    ))
}

#[cfg(windows)]
fn write_clam_confs(clamdir: &str) -> io::Result<()> {
    let clamd_conf =
        CLAMD_CONF_TEMPLATE.replace("\nExample\n", "\n# Example (disabled)\n# Example\n");
    let fresh_conf =
        FRESHCLAM_CONF_TEMPLATE.replace("\nExample\n", "\n# Example (disabled)\n# Example\n");

    fs::write(Path::new(clamdir).join("clamd.conf"), clamd_conf)?;
    fs::write(Path::new(clamdir).join("freshclam.conf"), fresh_conf)?;
    Ok(())
}

#[cfg(windows)]
fn wait_for_clam_ready(log_path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(mut f) = fs::File::open(log_path) {
            let mut buf = Vec::new();
            if f.read_to_end(&mut buf).is_ok()
                && (buf
                    .windows("daemon ready".len())
                    .any(|w| w == b"daemon ready")
                    || buf
                        .windows("clamd daemon ready".len())
                        .any(|w| w == b"clamd daemon ready"))
            {
                return true;
            }
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    false
}

// Walk the targets and count files for ETA; skip some heavy OS dirs.
fn pre_count_files(targets: &[String]) -> io::Result<i64> {
    let mut total: i64 = 0;
    let mut skip: HashMap<String, bool> = HashMap::new();

    #[cfg(windows)]
    for s in &[
        r"c:\windows\winsxs",
        r"c:\windows\softwaredistribution",
        r"c:\windows\system32\driverstore",
        r"c:\$recycle.bin",
        r"c:\system volume information",
    ] {
        skip.insert(s.to_string(), true);
    }
    #[cfg(unix)]
    for s in &[
        "/proc",
        "/sys",
        "/dev",
        "/run",
        "/var/cache",
        "/var/lib/apt",
    ] {
        skip.insert(s.to_string(), true);
    }

    for root in targets {
        let root_path = Path::new(root);
        if !root_path.exists() {
            continue;
        }
        walk_and_count(root_path, &skip, &mut total);
    }

    Ok(total)
}

fn walk_and_count(path: &Path, skip: &HashMap<String, bool>, total: &mut i64) {
    if let Ok(meta) = fs::metadata(path) {
        if meta.is_dir() {
            let lower = path
                .to_string_lossy()
                .to_lowercase()
                .trim_end_matches('\\')
                .trim_end_matches('/')
                .to_string();
            if skip.get(&lower).copied().unwrap_or(false) {
                return;
            }
            if let Ok(entries) = fs::read_dir(path) {
                for e in entries.flatten() {
                    walk_and_count(&e.path(), skip, total);
                }
            }
        } else {
            *total += 1;
        }
    }
}

fn fmt_duration(d: Duration) -> String {
    if d < Duration::from_secs(60) {
        return format!("{}s", (d.as_secs_f64() + 0.5) as u64);
    }
    let secs = d.as_secs();
    let h = secs / 3600;
    let m = (secs / 60) % 60;
    if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m")
    }
}

fn human_count(processed: i64, total: i64) -> String {
    if total > 0 {
        format!("{processed}/{total}")
    } else {
        format!("{processed}")
    }
}

fn show_if_exists(p: &Path) {
    match fs::read_to_string(p) {
        Ok(content) => println!("{content}"),
        Err(_) => println!("(missing: {})", p.display()),
    }
}

fn chrono_stamp() -> String {
    let now = chrono::Local::now();
    now.format("%Y%m%d_%H%M%S").to_string()
}

fn endpoint_state_dir() -> PathBuf {
    let dir = base_scans_dir().join("endpoint-rd");
    let _ = fs::create_dir_all(&dir);
    dir
}

fn endpoint_id() -> String {
    if let Ok(value) = std::env::var("CRUSTACIAN_ENDPOINT_ID") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    let host = hostname();
    let seed = format!("crustacian:{host}:{}", std::env::consts::OS);
    format!("crustacian-{}", short_sha256(&seed, 12))
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| String::from("unknown-host"))
}

fn write_scan_telemetry(
    report_dir: &Path,
    scan_targets: &[String],
    mode: &str,
    infected_lines: &[String],
) -> io::Result<()> {
    let severity = if infected_lines.is_empty() {
        "informational"
    } else {
        "high"
    };
    let classifier = if infected_lines.is_empty() {
        "clamav.scan.clean"
    } else {
        "clamav.scan.infected"
    };
    let confidence = if infected_lines.is_empty() {
        0.72
    } else {
        0.94
    };
    let (snapshot_path, snapshot_hash) = write_endpoint_snapshot("scan_complete")?;
    let payload = endpoint_event_json(EndpointEvent {
        event_kind: "scan_complete",
        severity,
        classifier,
        confidence,
        actor: "local_cli",
        auth_provider: "none",
        evidence: &format!(
            "mode={mode}; targets={}; infected_count={}; report_dir={}; snapshot={}",
            scan_targets.join("|"),
            infected_lines.len(),
            report_dir.display(),
            snapshot_path.display()
        ),
        lockout_recommended: !infected_lines.is_empty(),
        isolation_recommended: !infected_lines.is_empty(),
        snapshot_hash: &snapshot_hash,
    });
    append_siem_spool(&payload)?;
    fs::write(
        report_dir.join("endpoint_event.ndjson"),
        format!("{payload}\n"),
    )?;

    if !infected_lines.is_empty() {
        let _ = write_response_action_plan("clamav_infection", true, true, true);
    }

    Ok(())
}

fn write_endpoint_config_template() -> io::Result<PathBuf> {
    let path = endpoint_state_dir().join("endpoint-rd-config.toml");
    fs::write(&path, ENDPOINT_RD_CONFIG_TEMPLATE)?;
    Ok(path)
}

fn write_endpoint_snapshot(reason: &str) -> io::Result<(PathBuf, String)> {
    let stamp = chrono_stamp();
    let path = endpoint_state_dir().join(format!("snapshot-{stamp}.json"));
    let content = endpoint_snapshot_json(reason);
    fs::write(&path, &content)?;
    Ok((path, sha256_hex(content.as_bytes())))
}

fn write_response_action_plan(
    reason: &str,
    lockout_recommended: bool,
    isolation_recommended: bool,
    recovery_required: bool,
) -> io::Result<PathBuf> {
    let stamp = chrono_stamp();
    let path = endpoint_state_dir().join(format!("response-plan-{stamp}.json"));
    let content = format!(
        concat!(
            "{{\n",
            "  \"schema_version\": \"crustacian.response.v0\",\n",
            "  \"created_at\": \"{}\",\n",
            "  \"endpoint_id\": \"{}\",\n",
            "  \"reason\": \"{}\",\n",
            "  \"status\": \"planned_disabled\",\n",
            "  \"authentik_ldap\": {{\n",
            "    \"enabled\": false,\n",
            "    \"intended_action\": \"disable_or_lock_account_after_approval\",\n",
            "    \"required_controls\": [\"mTLS\", \"least_privilege_bind\", \"change_ticket\", \"break_glass_exclusion\"]\n",
            "  }},\n",
            "  \"network_containment\": {{\n",
            "    \"enabled\": false,\n",
            "    \"recommended\": {},\n",
            "    \"intended_action\": \"isolate_to_siem_and_recovery_network_only\"\n",
            "  }},\n",
            "  \"asset_lockdown\": {{\n",
            "    \"enabled\": false,\n",
            "    \"recommended\": {},\n",
            "    \"recovery_required\": {},\n",
            "    \"destructive_shutdown\": false\n",
            "  }},\n",
            "  \"operator_message\": \"Containment actions are R&D placeholders and require security-team approval before implementation.\"\n",
            "}}\n"
        ),
        json_escape(&chrono::Utc::now().to_rfc3339()),
        json_escape(&endpoint_id()),
        json_escape(reason),
        isolation_recommended,
        lockout_recommended,
        recovery_required
    );
    fs::write(&path, content)?;
    Ok(path)
}

fn write_integration_dry_run(reason: &str) -> io::Result<PathBuf> {
    let (snapshot_path, snapshot_hash) = write_endpoint_snapshot(reason)?;
    let payload = endpoint_event_json(EndpointEvent {
        event_kind: "integration_dry_run",
        severity: "informational",
        classifier: "endpoint.integration.plan",
        confidence: 0.61,
        actor: "local_cli",
        auth_provider: auth_provider_hint(),
        evidence: &format!(
            "siem_configured={}; authentik_configured={}; ldap_configured={}; snapshot={}",
            env_is_set("CRUSTACIAN_SIEM_URL"),
            env_is_set("CRUSTACIAN_AUTHENTIK_URL"),
            env_is_set("CRUSTACIAN_LDAP_URL"),
            snapshot_path.display()
        ),
        lockout_recommended: false,
        isolation_recommended: false,
        snapshot_hash: &snapshot_hash,
    });
    append_siem_spool(&payload)?;

    let stamp = chrono_stamp();
    let path = endpoint_state_dir().join(format!("integration-dry-run-{stamp}.json"));
    let content = format!(
        concat!(
            "{{\n",
            "  \"schema_version\": \"crustacian.integration_attempt.v0\",\n",
            "  \"created_at\": \"{}\",\n",
            "  \"endpoint_id\": \"{}\",\n",
            "  \"reason\": \"{}\",\n",
            "  \"mode\": \"dry_run\",\n",
            "  \"siem\": {{\n",
            "    \"configured\": {},\n",
            "    \"url_env\": \"CRUSTACIAN_SIEM_URL\",\n",
            "    \"transport_attempted\": false,\n",
            "    \"next_stage\": \"implement authenticated HTTPS/syslog sender with queue limits\"\n",
            "  }},\n",
            "  \"authentik\": {{\n",
            "    \"configured\": {},\n",
            "    \"url_env\": \"CRUSTACIAN_AUTHENTIK_URL\",\n",
            "    \"mutation_attempted\": false,\n",
            "    \"next_stage\": \"implement dry-run API client with ticket and allowlist validation\"\n",
            "  }},\n",
            "  \"ldap\": {{\n",
            "    \"configured\": {},\n",
            "    \"url_env\": \"CRUSTACIAN_LDAP_URL\",\n",
            "    \"mutation_attempted\": false,\n",
            "    \"next_stage\": \"implement LDAPS bind test and planned account-state diff only\"\n",
            "  }},\n",
            "  \"containment\": {{\n",
            "    \"configured\": {},\n",
            "    \"approval_env\": \"CRUSTACIAN_RESPONSE_APPROVAL_TOKEN\",\n",
            "    \"network_change_attempted\": false,\n",
            "    \"destructive_shutdown_attempted\": false,\n",
            "    \"next_stage\": \"define reversible isolation policy and recovery test harness\"\n",
            "  }},\n",
            "  \"forensic_snapshot\": {{\n",
            "    \"path\": \"{}\",\n",
            "    \"sha256\": \"{}\",\n",
            "    \"hash_ready_for_siem\": true\n",
            "  }},\n",
            "  \"telemetry_event_written\": true\n",
            "}}\n"
        ),
        json_escape(&chrono::Utc::now().to_rfc3339()),
        json_escape(&endpoint_id()),
        json_escape(reason),
        env_is_set("CRUSTACIAN_SIEM_URL"),
        env_is_set("CRUSTACIAN_AUTHENTIK_URL"),
        env_is_set("CRUSTACIAN_LDAP_URL"),
        env_is_set("CRUSTACIAN_RESPONSE_APPROVAL_TOKEN"),
        json_escape(&snapshot_path.display().to_string()),
        json_escape(&snapshot_hash)
    );
    fs::write(&path, content)?;
    Ok(path)
}

fn append_siem_spool(payload: &str) -> io::Result<()> {
    let path = endpoint_state_dir().join("siem-spool.ndjson");
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{payload}")?;
    Ok(())
}

fn siem_spool_path() -> PathBuf {
    endpoint_state_dir().join("siem-spool.ndjson")
}

fn siem_retry_state_path() -> PathBuf {
    endpoint_state_dir().join("siem-spool-retry.json")
}

fn show_telemetry_spool_status() {
    match edr_transport::spool_stats(&siem_spool_path()) {
        Ok(stats) => {
            println!("Telemetry spool: {}", siem_spool_path().display());
            println!("Queued events: {}", stats.queued_events);
            println!("Disk bytes: {}", stats.disk_bytes);
            println!(
                "Dropped low-priority events: {}",
                stats.dropped_low_priority_events
            );
        }
        Err(e) => eprintln!("[!] Failed to inspect telemetry spool: {e}"),
    }
}

fn ship_telemetry_spool_menu() {
    let default_url = std::env::var("CRUSTACIAN_INGEST_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8080/v1/ingest".to_string());
    println!("Ingest URL [{default_url}]: ");
    flush_stdout();
    let input_url = read_line();
    let ingest_url = if input_url.trim().is_empty() {
        default_url
    } else {
        input_url
    };

    println!("Max batch events [100]: ");
    flush_stdout();
    let max_batch_events = read_line().parse::<usize>().unwrap_or(100);
    let token = std::env::var("CRUSTACIAN_INGEST_TOKEN").ok();

    match edr_transport::send_spool_with_durable_retry(
        &siem_spool_path(),
        &siem_retry_state_path(),
        &endpoint_id(),
        &ingest_url,
        token.as_deref(),
        max_batch_events,
        &edr_transport::RetryPolicy::default(),
    ) {
        Ok(report) => {
            println!("Ingest status: HTTP {}", report.status_code);
            println!("Attempted events: {}", report.attempted_events);
            println!("Delivered events: {}", report.delivered_events);
            println!("Retained events: {}", report.retained_events);
            println!("Transport attempts: {}", report.transport_attempts);
            println!("Retry attempts: {}", report.retry_attempts);
            println!("Retry delay: {} ms", report.retry_delay_millis);
            if let Some(retry_after_seconds) = report.retry_after_seconds {
                println!("Retry after hint: {retry_after_seconds}s");
            }
            if let Some(next_retry_at) = report.next_retry_at {
                println!("Next retry: {next_retry_at}");
            }
            println!("Message: {}", report.message);
        }
        Err(e) => eprintln!("[!] Failed to ship telemetry spool: {e}"),
    }
}

fn env_is_set(name: &str) -> bool {
    std::env::var(name)
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
}

fn auth_provider_hint() -> &'static str {
    if env_is_set("CRUSTACIAN_AUTHENTIK_URL") {
        "authentik"
    } else if env_is_set("CRUSTACIAN_LDAP_URL") {
        "ldap"
    } else {
        "none"
    }
}

struct EndpointEvent<'a> {
    event_kind: &'a str,
    severity: &'a str,
    classifier: &'a str,
    confidence: f64,
    actor: &'a str,
    auth_provider: &'a str,
    evidence: &'a str,
    lockout_recommended: bool,
    isolation_recommended: bool,
    snapshot_hash: &'a str,
}

fn endpoint_event_json(event: EndpointEvent<'_>) -> String {
    let timestamp = chrono::Utc::now().to_rfc3339();
    let event_id = short_sha256(
        &format!(
            "{}:{}:{}:{}",
            endpoint_id(),
            timestamp,
            event.event_kind,
            event.evidence
        ),
        16,
    );

    format!(
        concat!(
            "{{",
            "\"schema_version\":\"crustacian.endpoint.telemetry.v0\",",
            "\"event_id\":\"{}\",",
            "\"timestamp\":\"{}\",",
            "\"endpoint_id\":\"{}\",",
            "\"asset_hostname\":\"{}\",",
            "\"platform\":\"{}\",",
            "\"event_kind\":\"{}\",",
            "\"severity\":\"{}\",",
            "\"classifier\":\"{}\",",
            "\"confidence\":{:.2},",
            "\"actor\":\"{}\",",
            "\"auth_provider\":\"{}\",",
            "\"lockout_recommended\":{},",
            "\"isolation_recommended\":{},",
            "\"forensic_snapshot_sha256\":\"{}\",",
            "\"evidence\":\"{}\"",
            "}}"
        ),
        event_id,
        json_escape(&timestamp),
        json_escape(&endpoint_id()),
        json_escape(&hostname()),
        json_escape(std::env::consts::OS),
        json_escape(event.event_kind),
        json_escape(event.severity),
        json_escape(event.classifier),
        event.confidence,
        json_escape(event.actor),
        json_escape(event.auth_provider),
        event.lockout_recommended,
        event.isolation_recommended,
        json_escape(event.snapshot_hash),
        json_escape(event.evidence)
    )
}

fn endpoint_snapshot_json(reason: &str) -> String {
    let scans = list_scan_dirs();
    let latest_scan = scans
        .last()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| String::from("none"));

    format!(
        concat!(
            "{{\n",
            "  \"schema_version\": \"crustacian.endpoint.snapshot.v0\",\n",
            "  \"created_at\": \"{}\",\n",
            "  \"reason\": \"{}\",\n",
            "  \"endpoint_id\": \"{}\",\n",
            "  \"asset_hostname\": \"{}\",\n",
            "  \"platform\": \"{}\",\n",
            "  \"architecture\": \"{}\",\n",
            "  \"scan_history_dir\": \"{}\",\n",
            "  \"latest_scan_dir\": \"{}\",\n",
            "  \"collection_scope\": \"local_metadata_only\",\n",
            "  \"network_collection\": \"planned_not_collected\",\n",
            "  \"forensic_collection\": \"planned_manifest_only\"\n",
            "}}\n"
        ),
        json_escape(&chrono::Utc::now().to_rfc3339()),
        json_escape(reason),
        json_escape(&endpoint_id()),
        json_escape(&hostname()),
        json_escape(std::env::consts::OS),
        json_escape(std::env::consts::ARCH),
        json_escape(&base_scans_dir().display().to_string()),
        json_escape(&latest_scan),
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn short_sha256(value: &str, len: usize) -> String {
    sha256_hex(value.as_bytes()).chars().take(len).collect()
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c if c.is_control() => escaped.push_str(&format!("\\u{:04x}", c as u32)),
            c => escaped.push(c),
        }
    }
    escaped
}

const ENDPOINT_RD_CONFIG_TEMPLATE: &str = r#"# Crustacian Endpoint R&D configuration template.
# No network delivery, account lockout, host isolation, or shutdown action is
# enabled by this template. Treat all response blocks as design-stage controls.

[identity]
# Override this per asset through CRUSTACIAN_ENDPOINT_ID or fleet enrollment.
endpoint_id_source = "CRUSTACIAN_ENDPOINT_ID"
schema_version = "crustacian.endpoint.telemetry.v0"

[telemetry]
format = "ndjson"
local_spool = "Documents/cyberplexs-scans/endpoint-rd/siem-spool.ndjson"
required_fields = [
  "schema_version",
  "event_id",
  "timestamp",
  "endpoint_id",
  "asset_hostname",
  "platform",
  "event_kind",
  "severity",
  "classifier",
  "confidence",
  "actor",
  "auth_provider",
  "lockout_recommended",
  "isolation_recommended",
  "forensic_snapshot_sha256",
  "evidence",
]

[siem]
enabled = false
transport = "https"
endpoint_url = "https://siem.example.invalid/ingest/crustacian"
endpoint_url_env = "CRUSTACIAN_SIEM_URL"
auth_mode = "bearer_token"
auth_token_env = "CRUSTACIAN_SIEM_TOKEN"
timeout_seconds = 10
retry_backoff_seconds = [5, 30, 120]

[authentik_ldap]
enabled = false
authentik_url_env = "CRUSTACIAN_AUTHENTIK_URL"
ldap_url_env = "CRUSTACIAN_LDAP_URL"
server_url = "ldaps://ldap.example.invalid"
bind_identity = "crustacian-edr-response"
action_mode = "plan_only"
allowed_actions = ["recommend_lockout", "write_response_plan"]

[containment]
enabled = false
action_mode = "plan_only"
approval_token_env = "CRUSTACIAN_RESPONSE_APPROVAL_TOKEN"
allowed_actions = ["recommend_network_isolation", "write_local_recovery_plan"]
destructive_shutdown_enabled = false
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escape_handles_control_characters() {
        assert_eq!(json_escape("a\"b\\c\n"), "a\\\"b\\\\c\\n");
    }

    #[test]
    fn telemetry_event_contains_required_schema_fields() {
        let event = endpoint_event_json(EndpointEvent {
            event_kind: "unit_test",
            severity: "informational",
            classifier: "test.classifier",
            confidence: 0.5,
            actor: "test",
            auth_provider: "none",
            evidence: "sample",
            lockout_recommended: false,
            isolation_recommended: false,
            snapshot_hash: "abc123",
        });

        assert!(event.contains("\"schema_version\":\"crustacian.endpoint.telemetry.v0\""));
        assert!(event.contains("\"endpoint_id\":\""));
        assert!(event.contains("\"forensic_snapshot_sha256\":\"abc123\""));
    }

    #[test]
    fn sha256_hex_is_stable() {
        assert_eq!(
            sha256_hex(b"crustacian"),
            "6318dff62e076651a94d98215372148ed0fc9dbbf95db9956ace5bc077e852f9"
        );
    }

    #[test]
    fn auth_provider_defaults_to_none_without_env() {
        std::env::remove_var("CRUSTACIAN_AUTHENTIK_URL");
        std::env::remove_var("CRUSTACIAN_LDAP_URL");
        assert_eq!(auth_provider_hint(), "none");
    }
}

// --- Config templates ---

#[cfg(windows)]
const CLAMD_CONF_TEMPLATE: &str = r#"# Crustacian tuned clamd.conf (Windows)
LogFile "C:\\Program Files\\ClamAV\\clamd.log"
LogTime yes
LogRotate yes
LogFileMaxSize 10M
FailIfCvdOlderThan 7
TCPSocket 3310
TCPAddr localhost
EnableShutdownCommand no
EnableReloadCommand yes
EnableStatsCommand no
EnableVersionCommand no
MaxThreads 20
ReadTimeout 300
CommandReadTimeout 30
SendBufTimeout 200
IdleTimeout 60
MaxConnectionQueueLength 200
StreamMaxLength 50M
StreamMinPort 30000
StreamMaxPort 32000
ScanMail yes
PhishingSignatures yes
PhishingScanURLs yes
ScanPDF yes
ScanOLE2 yes
ScanXMLDOCS yes
ScanOneNote yes
ScanSWF no
ScanImage yes
ScanImageFuzzyHash yes
DetectPUA yes
ExcludePUA NetTool
ExcludePUA PWTool
HeuristicAlerts yes
HeuristicScanPrecedence no
AlertPhishingSSLMismatch yes
AlertPhishingCloak yes
AlertEncrypted yes
AlertEncryptedArchive yes
AlertEncryptedDoc yes
AlertOLE2Macros yes
PartitionIntersection yes
MaxScanTime 300000
MaxScanSize 800M
MaxFileSize 250M
MaxRecursion 20
MaxFiles 20000
MaxEmbeddedPE 100M
MaxHTMLNormalize 50M
MaxHTMLNoTags 32M
MaxScriptNormalize 50M
MaxZipTypeRcg 1M
MaxPartitions 128
MaxIconsPE 200
MaxRecHWP3 16
PCREMatchLimit 100000
PCRERecMatchLimit 20000
PCREMaxFileSize 200M
AlertExceedsMax yes
AllowAllMatchScan yes
BytecodeSecurity TrustSigned
BytecodeTimeout 10000
ConcurrentDatabaseReload yes
DisableCache no
CacheSize 65536
"#;

#[cfg(windows)]
const FRESHCLAM_CONF_TEMPLATE: &str = r#"# Crustacian tuned freshclam.conf (Windows)
UpdateLogFile "C:\\Program Files\\ClamAV\\freshclam.log"
LogTime yes
LogRotate yes
LogFileMaxSize 10M
DatabaseMirror database.clamav.net
Checks 24
MaxAttempts 5
ConnectTimeout 60
ReceiveTimeout 300
NotifyClamd "C:\\Program Files\\ClamAV\\clamd.conf"
TestDatabases yes
Bytecode yes
"#;
