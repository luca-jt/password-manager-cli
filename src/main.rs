use copypasta::{ClipboardContext, ClipboardProvider};
use orion::pwhash::*;
use serde::{Deserialize, Serialize};
use serde_json::{Result, Value};
use std::fs::{self, File};
use std::io::BufReader;

const PASSKEY: &[u8] = b"jasjkfankjdafv";
const FILE: &str = "passwords.json";

#[derive(Serialize, Deserialize, Debug)]
struct Entry {
    platform: String,
    user_name: String,
    email: String,
    password: String,
}

fn main() {
    let mut clipboard = ClipboardContext::new().unwrap();

    let file = if !fs::exists(FILE).unwrap() {
        File::create_new(FILE).unwrap()
    } else {
        File::open(FILE).unwrap()
    };

    let reader = BufReader::new(file);
    let json: Vec<Entry> = serde_json::from_reader(reader).unwrap();

    let new_file_contents = serde_json::to_string_pretty(&json).unwrap();
}
