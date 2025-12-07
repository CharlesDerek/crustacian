// Crustacian Antivirus CLI (Interactive)
// Platform: Windows 10/11
// Purpose: One-stop bootstrapper for ClamAV (service + configs), interactive scan runner,
//          results archiver, and history viewer.
//
// Build (in repo root):
//   cargo build --release
// Usage:
//   Run target\release\crustacian.exe (no args). It will ask everything interactively.

use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const DEFAULT_CLAM_DIR: &str = r"C:\Program Files\ClamAV";

fn main() {
    if std::env::consts::OS != "windows" {
        println!("This tool currently targets Windows only.");
        std::process::exit(1);
    }

    loop {
        println!("================ Crustacian Antivirus CLI ================");
        println!("1. Initialize / repair ClamAV environment");
        println!("2. Run a new scan");
        println!("3. View previous scans");
        println!("4. Exit");
        print!("Select option (1-4): ");
        flush_stdout();

        let sel = read_line();
        match sel.as_str() {
            "1" => init_cmd(),
            "2" => scan_cmd(),
            "3" => history_menu(),
            "4" => {
                println!("Goodbye.");
                break;
            }
            _ => println!("Invalid choice."),
        }
    }
}

fn init_cmd() {
    let clamdir = String::from(DEFAULT_CLAM_DIR);
    println!("Initializing ClamAV setup...");

    if let Err(e) = make_dirs(&clamdir) {
        eprintln!("[!] Failed to create directories: {e}");
        wait_for_enter();
        return;
    }

    if !file_exists(Path::new(&clamdir).join("clamd.exe")) {
        println!("ClamAV not found; installing via winget/choco if possible...");
        let _ = try_install_clamav();
    }

    println!("Writing config files...");
    if let Err(e) = write_clam_confs(&clamdir) {
        eprintln!("[!] Failed writing config files: {e}");
    }

    println!("Installing and starting clamd service...");
    let _ = run_silent("cmd", &["/c", &format!(r#"{} --install"#, Path::new(&clamdir).join("clamd.exe").display())]);
    let _ = run("cmd", &["/c", "net", "start", "clamd"]);

    println!("Running initial update (freshclam)...");
    let freshclam_path = Path::new(&clamdir).join("freshclam.exe");
    let _ = run(freshclam_path.to_string_lossy().as_ref(), &["-v"]);

    println!("Done. Press Enter to continue...");
    wait_for_enter();
}

fn scan_cmd() {
    let clamdir = String::from(DEFAULT_CLAM_DIR);

    println!("\nSelect scan type:");
    println!("1. Quick (Documents, Downloads, Desktop, Temp)");
    println!("2. Full (C:\\)");
    println!("3. Custom paths");
    print!("Choice: ");
    flush_stdout();

    let sel = read_line();
    let mut scan_targets: Vec<String> = Vec::new();

    match sel.as_str() {
        "1" => {
            let userprof = std::env::var("USERPROFILE").unwrap_or_else(|_| String::from(r"C:\Users\Public"));
            scan_targets.push(Path::new(&userprof).join("Documents").to_string_lossy().into_owned());
            scan_targets.push(Path::new(&userprof).join("Downloads").to_string_lossy().into_owned());
            scan_targets.push(Path::new(&userprof).join("Desktop").to_string_lossy().into_owned());
            scan_targets.push(r"C:\Windows\Temp".to_string());
        }
        "2" => {
            scan_targets.push("C:\\".to_string());
        }
        "3" => {
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
        _ => {
            println!("Invalid option. Returning to main menu.");
            return;
        }
    }

    println!("\nWhat should be done with infected files?");
    println!("1. Report only (default)");
    println!("2. Move to Quarantine");
    println!("3. Delete");
    print!("Choice: ");
    flush_stdout();

    let act = read_line();
    let mut mode = "report";
    if act == "2" {
        mode = "quarantine";
    } else if act == "3" {
        mode = "remove";
    }

    print!("\nDo a quick pre-count of files for better ETA? (Y/n): ");
    flush_stdout();
    let do_count = read_line().to_lowercase();
    let want_count = do_count.is_empty() || do_count == "y" || do_count == "yes";

    let mut total_files: i64 = 0;
    if want_count {
        println!("Counting files (this is fast and improves ETA)…");
        let start_count = Instant::now();
        match pre_count_files(&scan_targets) {
            Ok(count) => {
                total_files = count;
                println!("Found ~{} files in {:?}.", total_files, start_count.elapsed());
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
        let _ = fs::create_dir_all(r"C:\Quarantine");
        args.push("--move=C:\\Quarantine".into());
    } else if mode == "remove" {
        args.push("--remove".into());
    }
    for t in &scan_targets {
        args.push(t.clone());
    }

    println!("\nStarting scan… progress shows below.");

    let clamdscan_path = Path::new(&clamdir).join("clamdscan.exe");
    let mut cmd = Command::new(clamdscan_path);
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
                    human_count(processed, (if total_files > 0 { total_files as f64 } else { adaptive_total }) as i64),
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

    println!("\nPress Enter to return to main menu…");
    wait_for_enter();
}

fn history_menu() {
    let scans = list_scan_dirs();
    if scans.is_empty() {
        println!("No scans found.");
        wait_for_enter();
        return;
    }

    for (i, d) in scans.iter().enumerate() {
        println!("[{}] {}", i + 1, d.file_name().unwrap_or_default().to_string_lossy());
    }
    print!("Enter # to view or Enter to go back: ");
    flush_stdout();
    let c = read_line();
    if c.trim().is_empty() {
        return;
    }

    let idx: usize = c.trim().parse().unwrap_or(0);
    if idx == 0 || idx > scans.len() {
        return;
    }

    let d = &scans[idx - 1];
    println!("===== {} =====", d.file_name().unwrap_or_default().to_string_lossy());
    show_if_exists(&d.join("summary.txt"));
    println!("--- Infected ---");
    show_if_exists(&d.join("infected.txt"));
    println!("Press Enter to return...");
    wait_for_enter();
}

// Optional repair function, equivalent to repairCmd in Go
#[allow(dead_code)]
fn repair_cmd() {
    let mut clamdir = String::from(DEFAULT_CLAM_DIR);

    println!("\n=== Repair ClamAV Environment ===");
    println!("Current ClamAV directory: {}", clamdir);
    print!("Use this directory? (Y/n): ");
    flush_stdout();
    let yn = read_line().to_lowercase();
    if yn == "n" || yn == "no" {
        print!("Enter full ClamAV directory (e.g., C:\\\\Program Files\\\\ClamAV): ");
        flush_stdout();
        let p = read_line().trim().to_string();
        if !p.is_empty() {
            clamdir = p;
        }
    }

    if !file_exists(Path::new(&clamdir).join("freshclam.exe"))
        || !file_exists(Path::new(&clamdir).join("clamd.exe"))
    {
        println!("[!] Could not find clamd.exe/freshclam.exe in: {}", clamdir);
        println!("    Run 'Initialize / repair' first from the main menu (option 1).");
        println!("Press Enter to continue...");
        wait_for_enter();
        return;
    }

    println!("[+] Restarting clamd service…");
    let _ = run("cmd", &["/c", "net", "stop", "clamd"]);
    let _ = run("cmd", &["/c", "net", "start", "clamd"]);

    println!("[+] Running freshclam…");
    let freshclam_path = Path::new(&clamdir).join("freshclam.exe");
    let _ = run(freshclam_path.to_string_lossy().as_ref(), &["-v"]);

    println!("[+] Checking readiness… (up to 60s)");
    let log_path = Path::new(&clamdir).join("clamd.log");
    if wait_for_clam_ready(&log_path, Duration::from_secs(60)) {
        println!("✅ clamd ready.");
    } else {
        println!("[!] clamd did not report ready in time. Check logs.");
    }

    println!("Press Enter to return to the main menu...");
    wait_for_enter();
}

// --- Helpers ---

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

fn file_exists(path: PathBuf) -> bool {
    fs::metadata(path).map(|m| m.is_file()).unwrap_or(false)
}

fn make_dirs(clamdir: &str) -> io::Result<()> {
    fs::create_dir_all(clamdir)?;
    let d = base_scans_dir();
    fs::create_dir_all(d)?;
    Ok(())
}

fn base_scans_dir() -> PathBuf {
    let user = std::env::var("USERPROFILE").unwrap_or_else(|_| String::from(r"C:\Users\Public"));
    Path::new(&user).join("Documents").join("cyberplexs-scans")
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

fn run_silent(name: &str, args: &[&str]) -> io::Result<()> {
    Command::new(name)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|_| ())
}

fn cmd_exists(name: &str) -> bool {
    Command::new("cmd")
        .args(["/C", "where", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn try_install_clamav() -> io::Result<()> {
    if cmd_exists("winget") {
        println!("[winget] Searching for ClamAV…");
        let _ = run("winget", &["search", "clamav"]);
        println!("[winget] Trying install… (may require admin approval)");
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
        println!("[choco] Trying install clamav…");
        if run("choco", &["install", "clamav", "-y"]).is_ok() {
            return Ok(());
        }
    }

    Err(io::Error::new(
        io::ErrorKind::Other,
        "no package manager success",
    ))
}

fn write_clam_confs(clamdir: &str) -> io::Result<()> {
    let clamd_conf = CLAMD_CONF_TEMPLATE.replace("\nExample\n", "\n# Example (disabled)\n# Example\n");
    let fresh_conf =
        FRESHCLAM_CONF_TEMPLATE.replace("\nExample\n", "\n# Example (disabled)\n# Example\n");

    fs::write(Path::new(clamdir).join("clamd.conf"), clamd_conf)?;
    fs::write(Path::new(clamdir).join("freshclam.conf"), fresh_conf)?;
    Ok(())
}

fn wait_for_clam_ready(log_path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(mut f) = fs::File::open(log_path) {
            let mut buf = Vec::new();
            if f.read_to_end(&mut buf).is_ok() {
                if buf.windows("daemon ready".len()).any(|w| w == b"daemon ready")
                    || buf
                        .windows("clamd daemon ready".len())
                        .any(|w| w == b"clamd daemon ready")
                {
                    return true;
                }
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
    for s in &[
        r"c:\windows\winsxs",
        r"c:\windows\softwaredistribution",
        r"c:\windows\system32\driverstore",
        r"c:\$recycle.bin",
        r"c:\system volume information",
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
    // 20250102_150405 style timestamp
    let now = chrono::Local::now();
    now.format("%Y%m%d_%H%M%S").to_string()
}

// --- Config Templates ---
// You can tweak/comment these to be less opinionated if you want.

const CLAMD_CONF_TEMPLATE: &str = r#"# Crustacian tuned clamd.conf (Windows)
# Logging
LogFile "C:\\Program Files\\ClamAV\\clamd.log"
LogTime yes
LogRotate yes
LogFileMaxSize 10M
#LogVerbose yes

# Database health
FailIfCvdOlderThan 7

# TCP listener (local only)
TCPSocket 3310
TCPAddr localhost

# Harden protocol surface
EnableShutdownCommand no
EnableReloadCommand yes
EnableStatsCommand no
EnableVersionCommand no

# Performance / timeouts
MaxThreads 20
ReadTimeout 300
CommandReadTimeout 30
SendBufTimeout 200
IdleTimeout 60
MaxConnectionQueueLength 200

# Stream / attachments
StreamMaxLength 50M
StreamMinPort 30000
StreamMaxPort 32000

# File type scanning
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

# PUA policy
DetectPUA yes
ExcludePUA NetTool
ExcludePUA PWTool

# Heuristics
HeuristicAlerts yes
HeuristicScanPrecedence no
AlertPhishingSSLMismatch yes
AlertPhishingCloak yes
AlertEncrypted yes
AlertEncryptedArchive yes
AlertEncryptedDoc yes
AlertOLE2Macros yes
PartitionIntersection yes

# Limits / bombs
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

# Bytecode / engine
AllowAllMatchScan yes
BytecodeSecurity TrustSigned
BytecodeTimeout 10000
ConcurrentDatabaseReload yes
DisableCache no
CacheSize 65536
"#;

const FRESHCLAM_CONF_TEMPLATE: &str = r#"# Crustacian tuned freshclam.conf (Windows)
# Logging
UpdateLogFile "C:\\Program Files\\ClamAV\\freshclam.log"
LogTime yes
LogRotate yes
LogFileMaxSize 10M
#LogVerbose yes

DatabaseMirror database.clamav.net
Checks 24
MaxAttempts 5
ConnectTimeout 60
ReceiveTimeout 300

NotifyClamd "C:\\Program Files\\ClamAV\\clamd.conf"
TestDatabases yes
Bytecode yes
"#;
