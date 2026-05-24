use sha2::{Sha256, Digest};
use std::{fs, io};
use reqwest::blocking::Client;
use std::collections::HashMap;

pub fn hash_file(path: &str) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)?;
    let hash = hasher.finalize();
    Ok(format!("{:x}", hash))
}

pub fn query_malwarebazaar(sha256: &str, api_key: &str) -> Result<String, Box<dyn std::error::Error>> {
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
