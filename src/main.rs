use clap::Parser;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rayon::prelude::*;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

type HmacSha256 = Hmac<Sha256>;

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    token: String,

    #[arg(short, long)]
    wordlist: Option<String>,

    #[arg(short, long)]
    mask: Option<String>,
}

fn main() {
    let args = Args::parse();

    let parts: Vec<&str> = args.token.split('.').collect();
    let message = format!("{}.{}", parts[0], parts[1]);
    let signature = parts[2].to_string();

    let found = Arc::new(AtomicBool::new(false));

    if let Some(wordlist) = args.wordlist {
        let file = File::open(wordlist).unwrap();
        let reader = BufReader::new(file);

        let secrets: Vec<String> = reader.lines().map(|l| l.unwrap()).collect();

        secrets.par_iter().for_each(|secret| {
            if found.load(Ordering::Relaxed) {
                return;
            }

            if check(secret, &message, &signature) {
                println!("[+] Secret found: {}", secret);
                found.store(true, Ordering::Relaxed);
            }
        });
    }

    if let Some(mask) = args.mask {
        let charset = build_charset(&mask);

        charset.par_iter().for_each(|candidate| {
            if found.load(Ordering::Relaxed) {
                return;
            }

            if check(candidate, &message, &signature) {
                println!("[+] Secret found: {}", candidate);
                found.store(true, Ordering::Relaxed);
            }
        });
    }
}

fn check(secret: &str, message: &str, signature: &str) -> bool {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(message.as_bytes());
    let result = mac.finalize().into_bytes();

    let encoded = URL_SAFE_NO_PAD.encode(result);

    encoded == signature
}

fn build_charset(mask: &str) -> Vec<String> {
    let mut sets = Vec::new();

    for chunk in mask.split('?').skip(1) {
        match chunk.chars().next().unwrap() {
            'l' => sets.push(('a'..='z').collect::<Vec<char>>()),
            'd' => sets.push(('0'..='9').collect::<Vec<char>>()),
            _ => panic!("Unsupported mask"),
        }
    }

    let mut results = vec![String::new()];

    for set in sets {
        let mut new_results = Vec::new();
        for prefix in &results {
            for c in &set {
                new_results.push(format!("{}{}", prefix, c));
            }
        }
        results = new_results;
    }

    results
}