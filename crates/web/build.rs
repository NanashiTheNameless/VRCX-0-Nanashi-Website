use std::{env, fs, path::Path};

fn main() {
    let root = Path::new("../../web/dist");
    println!("cargo:rerun-if-changed={}", root.display());
    let mut files = Vec::new();
    walk(root, root, &mut files);
    files.sort();
    assert!(
        files.iter().any(|(name, _)| name == "index.html"),
        "run `npm --prefix web run build` before building remotesync-web"
    );
    assert!(
        files.iter().any(|(name, _)| name == "web-manifest.json"),
        "web build is missing web-manifest.json"
    );

    let mut generated = String::from("pub static ASSETS: &[(&str, &[u8])] = &[\n");
    for (name, path) in files {
        let path = path.canonicalize().expect("canonical asset path");
        generated.push_str(&format!(
            "    ({name:?}, include_bytes!({:?})),\n",
            path.to_string_lossy()
        ));
    }
    generated.push_str("];\n");
    fs::write(
        Path::new(&env::var_os("OUT_DIR").unwrap()).join("assets.rs"),
        generated,
    )
    .unwrap();
}

fn walk(root: &Path, dir: &Path, files: &mut Vec<(String, std::path::PathBuf)>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let entry = entry.expect("asset directory entry");
        let path = entry.path();
        if path.is_dir() {
            walk(root, &path, files);
        } else if path.is_file() {
            let name = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            files.push((name, path));
        }
    }
}
