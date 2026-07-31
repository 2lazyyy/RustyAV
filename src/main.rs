use scanner::file2sha256;
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
        config::delete_key();
        let key = config::prompt();
        config::save_key(&key);
        return;
    }

    if cli.config_path {
        println!("{:?}", config::path());
        return;
    }

    if let Some(path) = cli.file {
        let api_key = config::prompt_key();
        heuristic::display(&path);

        let hash = file2sha256::hash(&path)
            .expect("Could not hash file");
        println!("SHA-256: {}", hash);

        match file2sha256::query_api(&hash, &api_key) {
            Ok(result) => println!("{}", file2sha256::response(&result)),
            Err(e) => eprintln!("API error: {}", e),
        }
        return;
    }

    if let Some(hash) = cli.hash {
    let api_key = config::prompt_key();
    
    match file2sha256::query_api(&hash, &api_key) {
        Ok(result) => println!("{}", file2sha256::response(&result)),
        Err(e) => eprintln!("API error: {}", e),
    }
    return;
    
}
    println!("No arguments provided. Use --help for usage.");
}
