use kuna_console::engine::{bootstrap_from_image_with_isa, bootstrap_from_raw, ArmIsa, EntrySelector};
use kuna_console::project::decompile_targets;

fn address(text: &str) -> Result<u64, String> {
    u64::from_str_radix(text.trim_start_matches("0x"), 16).map_err(|e| e.to_string())
}

fn run() -> Result<String, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        return Err("usage: igf-kuna <file|raw> <target> <base> <address> <auto|arm|thumb>".into());
    }
    let target = match args[2].as_str() {
        "x86" => "x86:LE:32:default:gcc",
        "x64" => "x86:LE:64:default:gcc",
        "arm" | "thumb" => "ARM:LE:32:v8:default",
        "arm64e" => "AARCH64:LE:64:AppleSilicon:default",
        "arm64" => "AARCH64:LE:64:v8A:default",
        _ => return Err("Unsupported architecture; expected x86, x64, ARM, Thumb, ARM64 or ARM64e".into()),
    };
    let isa = ArmIsa::parse(&args[5])?;
    let entry = address(&args[4])?;
    let roots = vec!["/specs".to_string()];
    std::env::set_var("KUNA_MACHO_ARM64E", "1");
    let mut prog = match args[1].as_str() {
        "file" => bootstrap_from_image_with_isa("/work/input", "", &roots, isa),
        "raw" => bootstrap_from_raw("/work/input", target, address(&args[3])?, &[entry], isa, &roots),
        _ => return Err("Unsupported input mode".into()),
    }.map_err(|e| e.explain().to_string())?;
    for (name, value) in [("ctypes", "on"), ("partialaccess", "on"), ("listing", "off"), ("fast_funcdisc", "off")] {
        prog.arch_mut().set_kuna_option(name, value).map_err(|e| e.explain().to_string())?;
    }
    prog.arch_mut().kuna_fn_budget = Some(std::time::Duration::from_secs(15));
    prog.commit_pending_analysis().map_err(|e| e.explain().to_string())?;
    let target = prog.resolve_entry(&EntrySelector::Numeric(entry)).map_err(|e| e.to_string())?;
    let result = decompile_targets(&mut prog, vec![target], true, false, false)
        .pop().ok_or("No function returned")?;
    result.code.ok_or_else(|| result.error.unwrap_or_else(|| "Decompilation failed".into()))
}

fn main() {
    match run() {
        Ok(code) => print!("{code}"),
        Err(error) => { eprintln!("{error}"); std::process::exit(1); }
    }
}
