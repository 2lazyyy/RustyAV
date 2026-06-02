use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Default)]
struct Config {
    api_key: Option<String>,
}

pub fn path() -> PathBuf {
    let mut path = dirs::home_dir().expect("Could not find home directory");
    path.push(".rustyav");
    fs::create_dir_all(&path).expect("Could not create config directory");
    path.push("config.json");
    path
}

fn load() -> Config {
    let path = path();
    if !path.exists() {
        return Config::default();
    }
    let content = fs::read_to_string(path).expect("Could not read config file");
    serde_json::from_str(&content).unwrap_or_default()
}

fn save(config: &Config) {
    let content = serde_json::to_string_pretty(config).expect("Could not serialize config");
    fs::write(path(), content).expect("Could not save config");
}

pub fn load_key() -> Option<String> {
    load().api_key.filter(|s| !s.is_empty())
}

pub fn save_key(key: &str) {
    let mut config = load();
    config.api_key = Some(key.trim().to_string());
    save(&config);
    println!("API key saved to {:?}", path());
}

pub fn delete_key() {
    let mut config = load();
    if config.api_key.is_some() {
        config.api_key = None;
        save(&config);
        println!("API key removed.");
    } else {
        println!("No API key found.");
    }
}

pub fn prompt() -> String {
    println!();
    println!("WARNING: No MalwareBazaar API key found.");
    println!();
    print!("Enter your API key: ");
    io::stdout().flush().unwrap();

    let mut key = String::new();
    io::stdin().read_line(&mut key).expect("Failed to read input");
    key.trim().to_string()
}

pub fn prompt_key() -> String {
    match load_key() {
        Some(key) => key,
        None => {
            let key = prompt();
            save_key(&key);
            key
        }
    }
}
