use std::sync::{Arc, Mutex};
use ddc_dec::{classdec::decompile_class, ClassOptions, DexPool};
use ddc_dex::DexFile;

fn run() -> Result<String, String> {
    let arg = std::env::args().nth(1).ok_or("Missing DEX instruction offset")?;
    let offset = u32::from_str_radix(arg.trim_start_matches("0x"), 16)
        .map_err(|_| "Invalid DEX instruction offset")?;
    let dex = DexFile::parse(std::fs::read("/work/input").map_err(|e| e.to_string())?)?;
    let class = dex.class_defs.iter().find_map(|class| {
        let data = dex.class_data(class);
        data.direct_methods.iter().chain(data.virtual_methods.iter())
            .any(|method| method.code_off != 0 && method.code_off.checked_add(16) == Some(offset))
            .then(|| dex.class_name(class.class_idx))
    }).ok_or("No DEX method body at this instruction offset")?;
    let mut pool = DexPool::new();
    pool.add_dex(dex);
    let pool = Arc::new(pool);
    let class = pool.get(&class).ok_or("Class has no definition in this DEX")?;
    let opts = ClassOptions { provenance: false, ..Default::default() };
    decompile_class(&pool, class, &opts, &Mutex::new(Vec::new())).map_err(|e| e.to_string())
}

fn main() {
    match run() {
        Ok(code) => println!("{code}"),
        Err(error) => { eprintln!("{error}"); std::process::exit(1); }
    }
}
