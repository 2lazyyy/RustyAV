use sha2::{Sha256, Digest};
use std::{fs, io};
use reqwest::blocking::Client;
use std::collections::HashMap;
use serde_json::Value;

pub fn hash(path: &str) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)?;
    let hash = hasher.finalize();
    Ok(format!("{:x}", hash))
}

pub fn query_api(sha256: &str, api_key: &str) -> Result<String, Box<dyn std::error::Error>> {
    let client = Client::new();

    let mut params = HashMap::new();
    params.insert("query", "get_info");
    params.insert("hash", sha256);

    let response = client
        .post("https://mb-api.abuse.ch/api/v1/")
        .header("Auth-Key", api_key)
        .header("Accept-Encoding", "identity")
        .form(&params)
        .send()?;

    Ok(response.text()?)
}

pub fn response(json_str: &str) -> String {
    let json: Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return "Failed to parse response".to_string(),
    };

    if json["query_status"] != "ok" {
        return "File not found in MalwareBazaar — likely clean or unknown".to_string();
    }

    let entry = &json["data"][0];

    let family   = entry["signature"].as_str().unwrap_or("Unknown");
    let score    = entry["vendor_intel"]["ReversingLabs"]["scanner_percent"]
                       .as_str().unwrap_or("0");
    let verdict  = entry["vendor_intel"]["ReversingLabs"]["status"]
                       .as_str().unwrap_or("Unknown");
    let tags     = entry["tags"].as_array()
                       .map(|t| t.iter()
                           .filter_map(|v| v.as_str())
                           .collect::<Vec<_>>()
                           .join(", "))
                       .unwrap_or_default();
    let yara     = entry["yara_rules"].as_array()
                       .map(|y| y.iter()
                           .filter_map(|r| r["rule_name"].as_str())
                           .collect::<Vec<_>>()
                           .join(", "))
                       .unwrap_or_default();
    let delivery = entry["delivery_method"].as_str().unwrap_or("Unknown");

    format!(
        "\n=== Scan Result ===\nFamily:   {}\nVerdict:  {}\nScore:    {}% of scanners\nTags:     {}\nDelivery: {}\nYARA:     {}\n",
        family, verdict, score, tags, delivery, yara
    )
}
