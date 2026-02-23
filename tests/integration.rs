use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

struct ApiProcess {
    child: Child,
    base_url: String,
}

impl Drop for ApiProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn api_binary_path() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_qimem-api") {
        return PathBuf::from(path);
    }

    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("debug")
        .join("qimem-api")
}

fn spawn_api() -> ApiProcess {
    let binary = api_binary_path();
    assert!(
        binary.exists(),
        "qimem-api binary path does not exist: {}",
        binary.display()
    );

    let mut child = Command::new(binary)
        .env("QIMEM_MODE", "stateless")
        .env("QIMEM_BIND", "127.0.0.1:18080")
        .env("RUST_LOG", "error")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn qimem-api");

    let base_url = String::from("http://127.0.0.1:18080");
    wait_for_health(&base_url, &mut child);

    ApiProcess { child, base_url }
}

fn wait_for_health(base_url: &str, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .build()
        .expect("build client");

    while Instant::now() < deadline {
        if child.try_wait().expect("poll api process").is_some() {
            let mut stderr = String::new();
            if let Some(handle) = child.stderr.as_mut() {
                let _ = handle.read_to_string(&mut stderr);
            }
            panic!("qimem-api exited before health check: {stderr}");
        }

        for url in [
            format!("{base_url}/health"),
            String::from("http://127.0.0.1:8080/health"),
        ] {
            if let Ok(resp) = client.get(&url).timeout(Duration::from_secs(1)).send() {
                if resp.status().is_success() {
                    let payload: Value = resp.json().expect("health json");
                    if payload == serde_json::json!({"status":"ok"}) {
                        return;
                    }
                }
            }
        }

        std::thread::sleep(Duration::from_millis(200));
    }

    panic!("qimem-api failed to report healthy");
}

#[test]
fn end_to_end_api_contract_and_errors() {
    let api = spawn_api();
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .build()
        .expect("build client");

    let key_response = client
        .post(format!("{}/keys", api.base_url))
        .json(&serde_json::json!({}))
        .send()
        .expect("create key response");
    assert_eq!(key_response.status(), reqwest::StatusCode::OK);

    let key_payload: Value = key_response.json().expect("key payload json");
    let object = key_payload.as_object().expect("key response object");
    assert_eq!(object.len(), 1, "key response must contain only key_id");
    let key_id = object
        .get("key_id")
        .and_then(Value::as_str)
        .expect("key_id field")
        .to_string();

    let plaintext = "integration-test-message";
    let encrypt_response = client
        .post(format!("{}/encrypt", api.base_url))
        .json(&serde_json::json!({"key_id": key_id, "input": plaintext}))
        .send()
        .expect("encrypt response");
    assert_eq!(encrypt_response.status(), reqwest::StatusCode::OK);

    let envelope = encrypt_response
        .json::<Value>()
        .expect("encrypt json")
        .get("envelope")
        .and_then(Value::as_str)
        .expect("envelope field")
        .to_string();

    let decrypt_response = client
        .post(format!("{}/decrypt", api.base_url))
        .json(&serde_json::json!({"input": envelope}))
        .send()
        .expect("decrypt response");
    assert_eq!(decrypt_response.status(), reqwest::StatusCode::OK);

    let decrypt_payload: Value = decrypt_response.json().expect("decrypt json");
    assert_eq!(decrypt_payload, serde_json::json!({"plaintext": plaintext}));

    let missing_input = client
        .post(format!("{}/encrypt", api.base_url))
        .json(&serde_json::json!({"key_id": "00000000-0000-0000-0000-000000000000"}))
        .send()
        .expect("missing field response");
    assert_eq!(
        missing_input.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY
    );

    let invalid_encrypt_body = client
        .post(format!("{}/encrypt", api.base_url))
        .header("content-type", "application/json")
        .body("not-json")
        .send()
        .expect("invalid json response");
    assert_eq!(
        invalid_encrypt_body.status(),
        reqwest::StatusCode::BAD_REQUEST
    );

    let invalid_decrypt = client
        .post(format!("{}/decrypt", api.base_url))
        .json(&serde_json::json!({"input": "%%%"}))
        .send()
        .expect("invalid decrypt response");
    assert_eq!(invalid_decrypt.status(), reqwest::StatusCode::BAD_REQUEST);
}
