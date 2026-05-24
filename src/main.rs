mod config;
mod file2sha256;

use clap::Parser;

#[derive(Parser)]
#[command(name = "RustyAV", about = "A signature-based antivirus engine")]
struct Cli {
    #[arg(short, long)]
    file: Option<String>,

    #[arg(short = 'x', long)]
    hash: Option<String>,

    #[arg(short, long)]
    reset_key: bool,

    #[arg(short, long)]
    config_path: bool,
    }

fn main() {
    let cli = Cli::parse();

    if cli.reset_key {
        config::delete_api_key();
        let key = config::prompt_for_api_key();
        config::save_api_key(&key);
        return;
    }

    if cli.config_path {
        println!("{:?}", config::config_path());
        return;
    }

    if let Some(path) = cli.file {
        let api_key = config::get_or_prompt_api_key();

        let hash = file2sha256::hash_file(&path)
            .expect("Could not hash file");
        println!("SHA-256: {}", hash);

        match file2sha256::query_malwarebazaar(&hash, &api_key) {
            Ok(result) => println!("MalwareBazaar response:\n{}", result),
            Err(e) => eprintln!("API error: {}", e),
        }
        return;
    }

    if let Some(hash) = cli.hash {
    let api_key = config::get_or_prompt_api_key();

    let clean_hash = hash
        .strip_prefix("sha256:")
        .unwrap_or(&hash)
        .to_string();

    match file2sha256::query_malwarebazaar(&hash, &api_key) {
        Ok(result) => {
            if result.trim().is_empty() {
                println!("No response from API — hash may not be in MalwareBazaar");
            } else {
                println!("{}", result);
            }
        }
        Err(e) => eprintln!("API error: {}", e),
    }
    return;
}

    println!("No arguments provided. Use --help for usage.");
}
