fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        println!("cargo:rerun-if-changed=app.manifest");
        println!("cargo:rerun-if-changed=assets/SSHWarden.ico");

        let mut res = winresource::WindowsResource::new();
        res.set_manifest_file("app.manifest");
        res.set_icon("assets/SSHWarden.ico");
        if let Err(e) = res.compile() {
            // Don't fail the build for the library itself, only for examples/bins
            println!("cargo:warning=Failed to compile Windows resources: {}", e);
        }
    }
}
