extern crate base64;
extern crate hex;
extern crate crypto;

use clap::Parser;
use crypto::{symmetriccipher::{ SynchronousStreamCipher}};
use rustc_serialize::hex::FromHex;
use core::str;
use std::iter::repeat;
use core::fmt::Write;
use log::{debug, error};

use rand::rngs::OsRng;
use rand::rngs::adapter::ReseedingRng;
use rand::prelude::*;
use rand_chacha::ChaCha20Core;

fn hex_to_bytes(s: &str) -> Vec<u8> {
  debug!("hex to bytes({:#?})", s);
  s.from_hex().unwrap()
}


#[derive(Parser)]
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
}

fn get_rand(len: i32) -> Vec<u8> {
  let prng = ChaCha20Core::from_entropy();
  let _ = ReseedingRng::new(prng, 0, OsRng);
  let random_bytes: Vec<u8> = (0..len).map(|_| { rand::random::<u8>() }).collect();

  random_bytes
}

fn bytes_to_hex(a: Vec<u8>) -> Result<String, std::fmt::Error> {
  let mut s = String::with_capacity(2 * a.len());
  for byte in a {
    write!(s, "{:02X}", byte)?;
  }

  Ok(s)
}

fn main() -> () {
  env_logger::init();

  let msg;
  let mut decrypt: bool = false;
  let mut mykey = String::new();
  let mut myiv = String::new();

  let cli = Cli::parse();

  if let Some(message) = cli.message.as_deref() {
    msg = message;
  } else {
    error!("Missing message");
    std::process::exit(1);
  }

  if let Some(key) = cli.key.as_deref() {
    mykey = key.to_string();
    decrypt = true;
  } else {
    let r = get_rand(32);
    let b = bytes_to_hex(r).unwrap();

    for c in b.chars() {
      mykey.push(c);
    }
  }

  if let Some(iv) = cli.iv.as_deref() {
    myiv = iv.to_string();
  } else {
    let r = get_rand(24);
    let b = bytes_to_hex(r).unwrap();

    for c in b.chars() {
      myiv.push(c);
    }
  }

  debug!("== XChaCha20 ==");
  debug!("Message: {:?}", msg);
  debug!("Key: {:?}", mykey);
  debug!("IV: {:?}", myiv);

  let key = &hex_to_bytes(&mykey)[..];
  let iv = &hex_to_bytes(&myiv)[..];

  if !decrypt {
    // Encrypt
    let plain = msg.as_bytes();
    let mut c = crypto::chacha20::ChaCha20::new_xchacha20(&key, iv);
    let mut output: Vec<u8> = repeat(0).take(plain.len()).collect();

    c.process(&plain[..], &mut output[..]);

    println!("{{ \"key\": \"{}\", \"iv\": \"{}\", \"data\": \"{}\" }}", mykey.to_lowercase(), myiv.to_lowercase(), hex::encode(output.clone()));
  } else {
    // Decrypt
    let encrypted = &hex_to_bytes(&msg)[..];
    let mut c = crypto::chacha20::ChaCha20::new_xchacha20(&key, iv);
    let mut output: Vec<u8> = repeat(0).take(encrypted.len()).collect();

    c.process(&encrypted[..], &mut output[..]);

    print!("{}", str::from_utf8(&output[..]).unwrap());
  }
}
