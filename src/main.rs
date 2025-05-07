use copypasta::{ClipboardContext, ClipboardProvider};
use orion::aead::{self, SecretKey};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write, stdin, stdout};
use std::path::PathBuf;

const PASSKEY: &[u8] = b"lajgnrkeksnckvdpsymvki1ha67g0aa2"; // set that to a random value of 32 bytes
const FILE: &str = "passwords.json";

macro_rules! flushed_print {
    ($($arg:tt)*) => {
        print!($($arg)*);
        stdout().flush().unwrap();
    };
}

fn read_input_popped(buffer: &mut String) {
    stdin().read_line(buffer).unwrap();
    buffer.pop();
}

fn encode(s: &str) -> Vec<u8> {
    let secret = SecretKey::from_slice(PASSKEY).unwrap();
    aead::seal(&secret, s.as_bytes()).unwrap()
}

fn decode(s: &[u8]) -> String {
    let secret = SecretKey::from_slice(PASSKEY).unwrap();
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
    flushed_print!("PLATFORM:\t {}\n", entry.platform);
    flushed_print!("USER NAME:\t {}\n", decode(&entry.user_name));
    flushed_print!("EMAIL:\t\t {}\n", decode(&entry.email));
    flushed_print!("PASSWORD:\t {}\n", decode(&entry.password));
}

struct Manager {
    clipboard: ClipboardContext,
    entries: Vec<Entry>,
    file_path: PathBuf,
}

impl Manager {
    fn new() -> Self {
        let mut file_path = std::env::current_exe().unwrap();
        file_path.set_file_name(FILE);

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
        flushed_print!("Enter platform: ");
        read_input_popped(&mut buffer);

        if self.entries.iter_mut().any(|s| s.platform == buffer) {
            flushed_print!(
                "Account information already stored for that platform. Delete it first to overwrite.\n"
            );
            return;
        }

        let mut new_entry = Entry {
            platform: buffer.clone(),
            ..Default::default()
        };

        buffer.clear();

        flushed_print!("Enter user name: ");
        read_input_popped(&mut buffer);
        new_entry.user_name = encode(buffer.as_str());
        buffer.clear();

        flushed_print!("Enter email: ");
        read_input_popped(&mut buffer);
        new_entry.email = encode(buffer.as_str());
        buffer.clear();

        flushed_print!("Enter password: ");
        read_input_popped(&mut buffer);
        new_entry.password = encode(buffer.as_str());
        buffer.clear();

        self.entries.push(new_entry);
    }

    fn delete_entry(&mut self) {
        let mut buffer = String::new();
        flushed_print!("Enter platform: ");
        read_input_popped(&mut buffer);
        flushed_print!("\n");

        let mut found_entry = false;

        self.entries.retain(|entry| {
            let keep = entry.platform != buffer;
            if !keep {
                flushed_print!("Deleted account information:\n\n");
                print_entry(entry);
                found_entry = true;
            }
            keep
        });

        if !found_entry {
            flushed_print!("No account information stored for that platform.\n");
        }
        flushed_print!("\n");
    }

    fn get_entry(&mut self) {
        let mut buffer = String::new();
        flushed_print!("Enter platform: ");
        read_input_popped(&mut buffer);
        flushed_print!("\n");

        for entry in self.entries.iter() {
            if entry.platform == buffer {
                print_entry(entry);

                self.clipboard
                    .set_contents(decode(&entry.password))
                    .unwrap();

                flushed_print!("\nCopied password to clipboard.\n\n");
                return;
            }
        }

        flushed_print!("No account information stored for that platform.\n");
    }

    fn view_all(&self) {
        if self.entries.is_empty() {
            flushed_print!("No account information stored.\n");
            return;
        }
        flushed_print!("\n");
        flushed_print!("---------------------------------------------------\n");
        for entry in self.entries.iter() {
            print_entry(entry);
            flushed_print!("---------------------------------------------------\n");
        }
        flushed_print!("\n");
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
        flushed_print!("Enter a command. [new, del, get, view, close]: ");
        read_input_popped(&mut command);

        match command.as_str() {
            "new" => manager.new_entry(),
            "del" => manager.delete_entry(),
            "get" => manager.get_entry(),
            "view" => manager.view_all(),
            "close" => {
                break;
            }
            _ => {
                flushed_print!("Unknown command.\n");
            }
        }

        command.clear();
    }
}
