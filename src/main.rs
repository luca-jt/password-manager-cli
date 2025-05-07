use copypasta::{ClipboardContext, ClipboardProvider};
use orion::aead;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write, stdin, stdout};

const PASSKEY: &[u8] = b"lajgnrkeksnckvdpsymvki1ha67g0aa2"; // set that to a random value of 32 bytes
const FILE: &str = "passwords.json";

fn encode(s: &str) -> String {
    let secret = aead::SecretKey::from_slice(PASSKEY).unwrap();
    String::from_utf8(aead::seal(&secret, s.as_bytes()).unwrap()).unwrap()
}

fn decode(s: &str) -> String {
    let secret = aead::SecretKey::from_slice(PASSKEY).unwrap();
    String::from_utf8(aead::open(&secret, s.as_bytes()).unwrap()).unwrap()
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct Entry {
    platform: String,
    user_name: String,
    email: String,
    password: String,
}

fn print_entry(entry: &Entry) {
    println!("PLATFORM:\t {}", entry.platform);
    println!("USER NAME:\t {}", decode(entry.user_name.as_str()));
    println!("EMAIL:\t {}", decode(entry.email.as_str()));
    println!("PASSWORD:\t {}", decode(entry.password.as_str()));
    stdout().flush().unwrap();
}

struct Manager {
    clipboard: ClipboardContext,
    entries: Vec<Entry>,
}

impl Manager {
    fn new() -> Self {
        let mut file = if !fs::exists(FILE).unwrap() {
            File::create_new(FILE).unwrap()
        } else {
            File::open(FILE).unwrap()
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
        new_entry.user_name = encode(buffer.as_str());
        buffer.clear();

        print!("Enter password: ");
        stdout().flush().unwrap();
        stdin().read_line(&mut buffer).unwrap();
        buffer.pop();
        new_entry.user_name = encode(buffer.as_str());
        buffer.clear();

        self.entries.push(new_entry);
    }

    fn delete_entry(&mut self) {
        let mut buffer = String::new();
        print!("Enter platform: ");
        stdout().flush().unwrap();
        stdin().read_line(&mut buffer).unwrap();
        buffer.pop();

        let mut found_entry = false;

        self.entries.retain(|entry| {
            let keep = entry.platform == buffer;
            if !keep {
                println!("Deleted account information:");
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
    }

    fn get_entry(&mut self) {
        let mut buffer = String::new();
        print!("Enter platform: ");
        stdout().flush().unwrap();
        stdin().read_line(&mut buffer).unwrap();
        buffer.pop();

        for entry in self.entries.iter() {
            if entry.platform == buffer {
                print_entry(entry);

                self.clipboard
                    .set_contents(decode(entry.password.as_str()))
                    .unwrap();

                println!("Copied password to clipboard.");
                stdout().flush().unwrap();

                return;
            }
            println!("No account information stored for that platform.");
            stdout().flush().unwrap();
        }
    }

    fn view_all(&self) {
        for entry in self.entries.iter() {
            print_entry(entry);
            println!("---------------------------------------------------");
            stdout().flush().unwrap();
        }
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        let mut file = File::open(FILE).unwrap();
        let new_file_contents = serde_json::to_string_pretty(&self.entries).unwrap();
        file.write_all(new_file_contents.as_bytes()).unwrap();
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
