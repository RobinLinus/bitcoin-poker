//! Enumerate public browser assets for immutable, content-versioned routes.
use std::{env, fs, path::{Path, PathBuf}};

fn collect(directory: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).expect("web asset directory") {
        let path = entry.expect("web asset entry").path();
        if path.is_dir() { collect(&path, files); }
        else if matches!(path.extension().and_then(|s|s.to_str()), Some("js"|"css"|"wasm"|"json")) { files.push(path); }
    }
}
fn main() {
    let web=PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../web").canonicalize().unwrap();
    let mut files=Vec::new();
    for root in [web.join("src"),web.join("public/wasm")] {
        println!("cargo:rerun-if-changed={}",root.display());collect(&root,&mut files);
    }
    files.sort();
    let mut generated=String::from("const VERSIONED_ASSETS: &[(&str, &str, &[u8])] = &[\n");
    for path in files {
        let relative=path.strip_prefix(&web).unwrap().to_str().unwrap().replace('\\',"/");
        let url=relative.strip_prefix("public/").unwrap_or(&relative);
        let mime=match path.extension().and_then(|s|s.to_str()).unwrap() {
            "js"=>"text/javascript; charset=utf-8", "css"=>"text/css; charset=utf-8",
            "wasm"=>"application/wasm", "json"=>"application/json; charset=utf-8", _=>unreachable!(),
        };
        generated.push_str(&format!("({url:?}, {mime:?}, include_bytes!({:?})),\n",path.to_str().unwrap()));
    }
    generated.push_str("];\n");
    fs::write(PathBuf::from(env::var("OUT_DIR").unwrap()).join("web-assets.rs"),generated).unwrap();
}
