fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        // Rebuild resources when manifest/icon changes.
        println!("cargo:rerun-if-changed=app.manifest");
        println!("cargo:rerun-if-changed=crates/sshwarden-ui/assets/sshwarden.ico");

        let mut res = winresource::WindowsResource::new();
        res.set_manifest_file("app.manifest");
        res.set_icon("crates/sshwarden-ui/assets/sshwarden.ico");
        res.compile().expect("Failed to compile Windows resources");
    }
}
