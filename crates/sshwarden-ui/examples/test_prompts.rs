/// Quick test for Windows TaskDialog authorization and Windows Hello unlock prompts.
///
/// Run with: cargo run -p sshwarden-ui --example test_prompts

#[tokio::main]
async fn main() {
    sshwarden_ui::init();
    tracing_subscriber::fmt::init();

    println!("=== Test 1: TaskDialog Authorization Prompt ===");
    println!("UAC-style dialog with shield icon and Yes/No buttons.\n");

    let info = sshwarden_ui::SignRequestInfo {
        key_name: "id_ed25519 (test key)".to_string(),
        process_name: "ssh.exe (PID: 12345)".to_string(),
        namespace: Some("git".to_string()),
        is_forwarding: false,
    };

    let result = sshwarden_ui::notify::prompt_authorization(&info).await;
    println!("Authorization result: {:?}\n", result);

    println!("=== Test 2: TaskDialog with forwarding warning ===");
    let info_fwd = sshwarden_ui::SignRequestInfo {
        key_name: "server-key".to_string(),
        process_name: "unknown".to_string(),
        namespace: None,
        is_forwarding: true,
    };

    let result2 = sshwarden_ui::notify::prompt_authorization(&info_fwd).await;
    println!("Authorization result (forwarding): {:?}\n", result2);

    println!("=== Test 3: Windows Hello Unlock ===");
    println!("Biometric prompt, falls back to CredUI if unavailable.\n");

    let unlock_result = sshwarden_ui::unlock::prompt_windows_hello().await;
    println!("Unlock result: {:?}", unlock_result);
}
