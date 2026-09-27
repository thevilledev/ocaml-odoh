// A differential-testing peer over cloudflare/odoh-rs, speaking the line
// protocol of ../go/main.go. odoh-rs provides only the mandatory suite,
// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and AES-128-GCM.

use bytes::Bytes;
use odoh_rs::*;
use rand::RngExt;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{self, BufRead, Write};

const REV: &str = "91f079f404de70562eee7c56d86b9e2576b70ef9";

fn unhex(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(v[k].as_str().unwrap_or("")).expect("invalid hex from the driver")
}

fn int(v: &Value, k: &str) -> usize {
    v[k].as_u64().unwrap_or(0) as usize
}

type Contexts = HashMap<u64, (ObliviousDoHMessagePlaintext, OdohSecret)>;

fn target(r: &Value) -> Result<Value, String> {
    let kem = r["kem"].as_u64().unwrap_or(0) as u16;
    let kdf = r["kdf"].as_u64().unwrap_or(0) as u16;
    let aead = r["aead"].as_u64().unwrap_or(0) as u16;
    if (kem, kdf, aead) != (0x20, 1, 1) {
        return Err("unsupported suite".into());
    }
    let key_pair = ObliviousDoHKeyPair::from_parameters(kem, kdf, aead, &unhex(r, "seed"));
    let configs: ObliviousDoHConfigs =
        vec![ObliviousDoHConfig::from(key_pair.public().clone())].into();
    let configs = compose(&configs).map_err(|e| e.to_string())?;
    let key_id = key_pair.public().identifier().map_err(|e| e.to_string())?;
    let message: ObliviousDoHMessage =
        parse(&mut Bytes::from(unhex(r, "query"))).map_err(|e| e.to_string())?;
    let (query, secret) = decrypt_query(&message, &key_pair).map_err(|e| e.to_string())?;
    let padding = query.padding_len();
    let response =
        ObliviousDoHMessagePlaintext::new(unhex(r, "response"), int(r, "response_padding"));
    let nonce: ResponseNonce = rand::rng().random();
    let encrypted =
        encrypt_response(&query, &response, secret, nonce).map_err(|e| e.to_string())?;
    let encrypted = compose(&encrypted).map_err(|e| e.to_string())?;
    Ok(json!({
        "configs": hex::encode(&configs),
        "key_id": hex::encode(&key_id),
        "query": hex::encode(query.into_msg()),
        "query_padding": padding,
        "response": hex::encode(&encrypted),
    }))
}

fn query(r: &Value, contexts: &mut Contexts) -> Result<Value, String> {
    let configs: ObliviousDoHConfigs =
        parse(&mut Bytes::from(unhex(r, "configs"))).map_err(|e| e.to_string())?;
    let config = configs
        .supported()
        .into_iter()
        .next()
        .ok_or("no supported configuration")?;
    let contents = ObliviousDoHConfigContents::from(config);
    let plaintext = ObliviousDoHMessagePlaintext::new(unhex(r, "query"), int(r, "padding"));
    let (message, secret) =
        encrypt_query(&plaintext, &contents, &mut rand::rng()).map_err(|e| e.to_string())?;
    let message = compose(&message).map_err(|e| e.to_string())?;
    contexts.insert(r["handle"].as_u64().unwrap_or(0), (plaintext, secret));
    Ok(json!({ "query": hex::encode(&message) }))
}

fn open(r: &Value, contexts: &mut Contexts) -> Result<Value, String> {
    let (plaintext, secret) = contexts
        .remove(&r["handle"].as_u64().unwrap_or(0))
        .ok_or("no such context")?;
    let message: ObliviousDoHMessage =
        parse(&mut Bytes::from(unhex(r, "response"))).map_err(|e| e.to_string())?;
    let response = decrypt_response(&plaintext, &message, secret).map_err(|e| e.to_string())?;
    Ok(json!({ "response": hex::encode(response.into_msg()) }))
}

fn main() {
    let mut contexts = Contexts::new();
    let stdout = io::stdout();
    for line in io::stdin().lock().lines() {
        let r: Value = serde_json::from_str(&line.expect("stdin")).expect("JSON from the driver");
        let answer = match r["op"].as_str().unwrap_or("") {
            "hello" => Ok(json!({
                "implementation": "github.com/cloudflare/odoh-rs",
                "version": REV,
            })),
            "target" => target(&r),
            "query" => query(&r, &mut contexts),
            "open" => open(&r, &mut contexts),
            op => Err(format!("unknown operation {op:?}")),
        };
        let answer = match answer {
            Ok(mut v) => {
                v["ok"] = json!(true);
                v
            }
            Err(e) => json!({ "ok": false, "error": e }),
        };
        let mut out = stdout.lock();
        writeln!(out, "{answer}").expect("stdout");
        out.flush().expect("stdout");
    }
}
