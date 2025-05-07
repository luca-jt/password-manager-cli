use copypasta::{ClipboardContext, ClipboardProvider};
use orion::aead;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write, stdin, stdout};
use std::path::PathBuf;

const PASSKEY: &[u8] = b"lajgnrkeksnckvdpsymvki1ha67g0aa2"; // set that to a random value of 32 bytes
const FILE: &str = "passwords.json";

fn full_file_path() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.set_file_name(FILE);
    path
}

fn encode(s: &str) -> Vec<u8> {
    let secret = aead::SecretKey::from_slice(PASSKEY).unwrap();
    aead::seal(&secret, s.as_bytes()).unwrap()
}

fn decode(s: &[u8]) -> String {
    let secret = aead::SecretKey::from_slice(PASSKEY).unwrap();
    String::from_utf8(aead::open(&secret, s).unwrap()).unwrap()
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct Entry {
    platform: String,
    user_name: Vec<u8>,
    email: Vec<u8>,
    password: Vec<u8>,
}

fn print_entry(entry: &Entry) {
    println!("PLATFORM:\t {}", entry.platform);
    stdout().flush().unwrap();
    println!("USER NAME:\t {}", decode(&entry.user_name));
    stdout().flush().unwrap();
    println!("EMAIL:\t\t {}", decode(&entry.email));
    stdout().flush().unwrap();
    println!("PASSWORD:\t {}", decode(&entry.password));
    stdout().flush().unwrap();
}

struct Manager {
    clipboard: ClipboardContext,
    entries: Vec<Entry>,
    file_path: PathBuf,
}

impl Manager {
    fn new() -> Self {
        let file_path = full_file_path();

        let mut file = if !fs::exists(&file_path).unwrap() {
            File::create_new(&file_path).unwrap()
        } else {
            File::open(&file_path).unwrap()
        };

        let mut contents = String::new();
        let num_bytes = file.read_to_string(&mut contents).unwrap();

        let entries = if num_bytes == 0 {
            Vec::new()
        } else {
            serde_json::from_str(&contents).unwrap()
        };

        Self {
            clipboard: ClipboardContext::new().unwrap(),
            entries,
            file_path,
        }
    }

    fn new_entry(&mut self) {
        let mut buffer = String::new();
        print!("Enter platform: ");
        stdout().flush().unwrap();
        stdin().read_line(&mut buffer).unwrap();
        buffer.pop();

        if self.entries.iter_mut().any(|s| s.platform == buffer) {
            println!(
                "Account information already stored for that platform. Delete it first to overwrite."
            );
            stdout().flush().unwrap();
            return;
        }

        let mut new_entry = Entry {
            platform: buffer.clone(),
            ..Default::default()
        };

        buffer.clear();

        print!("Enter user name: ");
        stdout().flush().unwrap();
        stdin().read_line(&mut buffer).unwrap();
        buffer.pop();
        new_entry.user_name = encode(buffer.as_str());
        buffer.clear();

        print!("Enter email: ");
        stdout().flush().unwrap();
        stdin().read_line(&mut buffer).unwrap();
        buffer.pop();
        new_entry.email = encode(buffer.as_str());
        buffer.clear();

        print!("Enter password: ");
        stdout().flush().unwrap();
        stdin().read_line(&mut buffer).unwrap();
        buffer.pop();
        new_entry.password = encode(buffer.as_str());
        buffer.clear();

        self.entries.push(new_entry);
    }

    fn delete_entry(&mut self) {
        let mut buffer = String::new();
        print!("Enter platform: ");
        stdout().flush().unwrap();
        stdin().read_line(&mut buffer).unwrap();
        buffer.pop();
        print!("\n");
        stdout().flush().unwrap();

        let mut found_entry = false;

        self.entries.retain(|entry| {
            let keep = entry.platform != buffer;
            if !keep {
                println!("Deleted account information:\n");
                stdout().flush().unwrap();
                print_entry(entry);
                found_entry = true;
            }
            keep
        });

        if !found_entry {
            println!("No account information stored for that platform.");
            stdout().flush().unwrap();
        }
        print!("\n");
        stdout().flush().unwrap();
    }

    fn get_entry(&mut self) {
        let mut buffer = String::new();
        print!("Enter platform: ");
        stdout().flush().unwrap();
        stdin().read_line(&mut buffer).unwrap();
        buffer.pop();
        print!("\n");
        stdout().flush().unwrap();

        for entry in self.entries.iter() {
            if entry.platform == buffer {
                print_entry(entry);

                self.clipboard
                    .set_contents(decode(&entry.password))
                    .unwrap();

                print!("\n");
                stdout().flush().unwrap();
                println!("Copied password to clipboard.");
                stdout().flush().unwrap();
                print!("\n");
                stdout().flush().unwrap();

                return;
            }
        }
        println!("No account information stored for that platform.");
        stdout().flush().unwrap();
    }

    fn view_all(&self) {
        if self.entries.is_empty() {
            println!("No account information stored.");
            stdout().flush().unwrap();
            return;
        }
        print!("\n");
        stdout().flush().unwrap();
        println!("---------------------------------------------------");
        stdout().flush().unwrap();
        for entry in self.entries.iter() {
            print_entry(entry);
            println!("---------------------------------------------------");
            stdout().flush().unwrap();
        }
        print!("\n");
        stdout().flush().unwrap();
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        if self.entries.is_empty() {
            if let Err(e) = fs::remove_file(&self.file_path) {
                dbg!(e);
            }
            return;
        }
        let new_file_contents = serde_json::to_string(&self.entries).unwrap();
        fs::write(&self.file_path, new_file_contents.as_bytes()).unwrap();
    }
}

fn main() {
    let mut manager = Manager::new();
    let mut command = String::new();

    loop {
        print!("Enter a command. [new, del, get, view, close]: ");
        stdout().flush().unwrap();
        stdin().read_line(&mut command).unwrap();
        command.pop();

        match command.as_str() {
            "new" => manager.new_entry(),
            "del" => manager.delete_entry(),
            "get" => manager.get_entry(),
            "view" => manager.view_all(),
            "close" => {
                break;
            }
            _ => {
                println!("Unknown command.");
                stdout().flush().unwrap();
            }
        }

        command.clear();
    }
}
