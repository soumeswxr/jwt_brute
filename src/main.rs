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
    if parts.len() != 3 {
        eprintln!("Invalid JWT");
        return;
    }

    let message = format!("{}.{}", parts[0], parts[1]);
    let msg_bytes = message.into_bytes();
    let signature = parts[2].to_string();

    let found = Arc::new(AtomicBool::new(false));

    if let Some(wordlist) = args.wordlist {
        if let Ok(file) = File::open(wordlist) {
            let reader = BufReader::new(file);
            let secrets: Vec<String> = reader.lines().filter_map(Result::ok).collect();

            secrets.par_iter().for_each(|secret| {
                if found.load(Ordering::Relaxed) {
                    return;
                }

                if check(secret.as_bytes(), &msg_bytes, &signature) {
                    println!("[+] Secret found: {}", secret);
                    found.store(true, Ordering::Relaxed);
                }
            });
        }
    }

    if let Some(mask) = args.mask {
        let sets = parse_mask(&mask);

        generate_and_check(
            &sets,
            &msg_bytes,
            &signature,
            &found,
            String::new(),
        );
    }
}

fn check(secret: &[u8], message: &[u8], signature: &str) -> bool {
    if let Ok(mut mac) = HmacSha256::new_from_slice(secret) {
        mac.update(message);
        let result = mac.finalize().into_bytes();
        let encoded = URL_SAFE_NO_PAD.encode(result);
        return encoded == signature;
    }
    false
}

fn parse_mask(mask: &str) -> Vec<Vec<char>> {
    mask.split('?')
        .skip(1)
        .map(|chunk| match chunk.chars().next().unwrap_or(' ') {
            'l' => ('a'..='z').collect(),
            'd' => ('0'..='9').collect(),
            _ => Vec::new(),
        })
        .collect()
}

fn generate_and_check(
    sets: &[Vec<char>],
    message: &[u8],
    signature: &str,
    found: &Arc<AtomicBool>,
    prefix: String,
) {
    if found.load(Ordering::Relaxed) {
        return;
    }

    if sets.is_empty() {
        if check(prefix.as_bytes(), message, signature) {
            println!("[+] Secret found: {}", prefix);
            found.store(true, Ordering::Relaxed);
        }
        return;
    }

    let (first, rest) = sets.split_first().unwrap();

    first.par_iter().for_each(|c| {
        if found.load(Ordering::Relaxed) {
            return;
        }

        let mut new_prefix = prefix.clone();
        new_prefix.push(*c);

        generate_and_check(rest, message, signature, found, new_prefix);
    });
}
