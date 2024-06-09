use clap::Parser;
use crypto::{chacha20::ChaCha20, symmetriccipher::SynchronousStreamCipher};
use rand::{prelude::*, rngs::OsRng};
use rand_chacha::ChaCha20Core;
use std::{fmt::Write, str, iter::repeat};
use rustc_serialize::hex::FromHex;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Message
    message: Option<String>,

    /// Key
    #[arg(short, long)]
    key: Option<String>,

    /// IV
    #[arg(short, long)]
    iv: Option<String>,

    /// Decrypt
    #[arg(short, long)]
    decrypt: bool,
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    log::debug!("hex to bytes({:#?})", s);
    s.from_hex().unwrap()
}

fn get_rand(len: usize) -> Vec<u8> {
    let prng = ChaCha20Core::from_entropy();
    let _ = rand::rngs::adapter::ReseedingRng::new(prng, 0, OsRng);
    (0..len).map(|_| rand::random::<u8>()).collect()
}

fn bytes_to_hex(a: &[u8]) -> String {
    let mut s = String::with_capacity(2 * a.len());
    for byte in a {
        write!(s, "{:02X}", byte).unwrap();
    }
    s
}

fn main() {
    env_logger::init();

    let cli = Cli::parse();

    let msg = cli.message
            .as_deref()
            .expect("Missing message. Provide a message.");

    let (key, iv) = if let Some(key) = cli.key.as_deref() {
        (hex_to_bytes(key), hex_to_bytes(&cli.iv.unwrap_or_else(|| String::new())))
    } else {
        let key = get_rand(32);
        let iv = get_rand(24);
        (key, iv)
    };

    log::debug!("== XChaCha20 ==");
    log::debug!("Message: {:?}", msg);
    log::debug!("Key: {:?}", bytes_to_hex(&key));
    log::debug!("IV: {:?}", bytes_to_hex(&iv));

    if !cli.decrypt {
        // Encrypt
        let mut cipher = ChaCha20::new_xchacha20(&key, &iv);
        let plaintext = msg.as_bytes();
        let mut output = vec![0; plaintext.len()];
        cipher.process(plaintext, &mut output);

        println!(
            "{{ \"key\": \"{}\", \"iv\": \"{}\", \"data\": \"{}\" }}",
            bytes_to_hex(&key).to_lowercase(),
            bytes_to_hex(&iv).to_lowercase(),
            hex::encode(output)
        );
    } else {
        // Decrypt
        let encrypted = &hex_to_bytes(&msg)[..];
        let mut c = ChaCha20::new_xchacha20(&key, &iv);
        let mut output: Vec<u8> = repeat(0).take(encrypted.len()).collect();

        c.process(&encrypted[..], &mut output[..]);

        print!("{}", str::from_utf8(&output[..]).unwrap());
    }
}
