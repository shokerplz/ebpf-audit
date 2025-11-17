use libbpf_cargo::SkeletonBuilder;
use std::{env, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let bpf_dir = PathBuf::from("src-bpf");

    for entry in fs::read_dir(&bpf_dir)? {
        let path = entry?.path();
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.ends_with(".bpf.c") {
                let base = &name[..name.len() - 6]; // remove ".bpf.c"
                let skel = out_dir.join(format!("{}_skel.rs", base));

                SkeletonBuilder::new()
                    .source(&path)
                    .build_and_generate(&skel)?;

                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }

    Ok(())
}
