use copypasta::{ClipboardContext, ClipboardProvider};
use orion::aead::{self, SecretKey};
use orion::pwhash::{self, PasswordHash};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write, stdin, stdout};
use std::path::PathBuf;

const STORAGE_FILE: &str = "passwords.json";
const PASSWORD_HASH_FILE: &str = "used.pwhash";
const ITERATIONS: u32 = 3;
const MEMORY: u32 = 1 << 16;

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

fn encode(s: &str, secret_key: &SecretKey) -> Vec<u8> {
    aead::seal(secret_key, s.as_bytes()).unwrap()
}

fn decode(s: &[u8], secret_key: &SecretKey) -> String {
    String::from_utf8(aead::open(secret_key, s).unwrap()).unwrap()
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct Entry {
    platform: String,
    user_name: Vec<u8>,
    email: Vec<u8>,
    password: Vec<u8>,
}

fn print_entry(entry: &Entry, secret_key: &SecretKey) {
    flushed_print!("PLATFORM:\t {}\n", entry.platform);
    flushed_print!("USER NAME:\t {}\n", decode(&entry.user_name, secret_key));
    flushed_print!("EMAIL:\t\t {}\n", decode(&entry.email, secret_key));
    flushed_print!("PASSWORD:\t {}\n", decode(&entry.password, secret_key));
}

struct Manager {
    clipboard: ClipboardContext,
    entries: Vec<Entry>,
    storage_file_path: PathBuf,
    hash_file_path: PathBuf,
    secret_key: SecretKey,
    password_hash: PasswordHash,
}

impl Manager {
    fn new() -> Self {
        let mut storage_file_path = std::env::current_exe().unwrap();
        storage_file_path.set_file_name(STORAGE_FILE);

        let mut file = if !fs::exists(&storage_file_path).unwrap() {
            File::create_new(&storage_file_path).unwrap()
        } else {
            File::open(&storage_file_path).unwrap()
        };

        let mut contents = String::new();
        let num_bytes = file.read_to_string(&mut contents).unwrap();

        let entries = if num_bytes == 0 {
            Vec::new()
        } else {
            serde_json::from_str(&contents).unwrap()
        };

        let mut hash_file_path = std::env::current_exe().unwrap();
        hash_file_path.set_file_name(PASSWORD_HASH_FILE);
        let mut password_string = String::new();

        let password_hash = if !fs::exists(&hash_file_path).unwrap() {
            loop {
                flushed_print!("Choose a master password (8-32 chars): ");
                read_input_popped(&mut password_string);
                if password_string.len() >= 8 && password_string.len() <= 32 {
                    while password_string.len() < 32 {
                        password_string.push('0');
                    }
                    break;
                }
                flushed_print!("The password is not the correct lenght.\n");
                password_string.clear();
            }

            let password = pwhash::Password::from_slice(password_string.as_bytes()).unwrap();
            let password_hash = pwhash::hash_password(&password, ITERATIONS, MEMORY).unwrap();
            let new_file_contents = serde_json::to_string(&password_hash).unwrap();
            fs::write(&hash_file_path, new_file_contents.as_bytes()).unwrap();

            password_hash
        } else {
            let hash_file_contents = fs::read(&hash_file_path).unwrap();
            let password_hash = serde_json::from_slice(&hash_file_contents).unwrap();

            loop {
                flushed_print!("Enter your master password: ");
                read_input_popped(&mut password_string);
                while password_string.len() < 32 {
                    password_string.push('0');
                }
                let password = pwhash::Password::from_slice(password_string.as_bytes()).unwrap();
                let is_correct_pw = pwhash::hash_password_verify(&password_hash, &password).is_ok();

                if is_correct_pw {
                    break password_hash;
                }

                flushed_print!("Entered password is not correct.\n");
                password_string.clear();
            }
        };

        let secret_key = SecretKey::from_slice(password_string.as_bytes()).unwrap();

        Self {
            clipboard: ClipboardContext::new().unwrap(),
            entries,
            storage_file_path,
            hash_file_path,
            secret_key,
            password_hash,
        }
    }

    fn new_entry(&mut self) {
        let mut buffer = String::new();
        flushed_print!("Enter platform: ");
        read_input_popped(&mut buffer);

        if self
            .entries
            .iter_mut()
            .any(|s| s.platform.as_str().to_lowercase() == buffer.as_str().to_lowercase())
        {
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
        new_entry.user_name = encode(buffer.as_str(), &self.secret_key);
        buffer.clear();

        flushed_print!("Enter email: ");
        read_input_popped(&mut buffer);
        new_entry.email = encode(buffer.as_str(), &self.secret_key);
        buffer.clear();

        flushed_print!("Enter password: ");
        read_input_popped(&mut buffer);
        new_entry.password = encode(buffer.as_str(), &self.secret_key);
        buffer.clear();

        self.entries.push(new_entry);
        flushed_print!("Success!\n");
    }

    fn delete_entry(&mut self) {
        let mut buffer = String::new();
        flushed_print!("Enter platform: ");
        read_input_popped(&mut buffer);
        flushed_print!("\n");

        let mut found_entry = false;

        self.entries.retain(|entry| {
            let keep = entry.platform.as_str().to_lowercase() != buffer.as_str().to_lowercase();
            if !keep {
                flushed_print!("Deleted account information:\n\n");
                print_entry(entry, &self.secret_key);
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
            if entry.platform.as_str().to_lowercase() == buffer.as_str().to_lowercase() {
                print_entry(entry, &self.secret_key);

                self.clipboard
                    .set_contents(decode(&entry.password, &self.secret_key))
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
            print_entry(entry, &self.secret_key);
            flushed_print!("---------------------------------------------------\n");
        }
        flushed_print!("\n");
    }

    fn change_password(&mut self) {
        let mut new_password_string = String::new();

        loop {
            flushed_print!("Enter the new master password (8-32 chars): ");
            read_input_popped(&mut new_password_string);
            if new_password_string.len() >= 8 && new_password_string.len() <= 32 {
                while new_password_string.len() < 32 {
                    new_password_string.push('0');
                }
                break;
            }
            flushed_print!("The password is not the correct lenght.\n");
            new_password_string.clear();
        }

        let password = pwhash::Password::from_slice(new_password_string.as_bytes()).unwrap();
        let password_hash = pwhash::hash_password(&password, ITERATIONS, MEMORY).unwrap();
        let new_file_contents = serde_json::to_string(&password_hash).unwrap();
        fs::write(&self.hash_file_path, new_file_contents.as_bytes()).unwrap();
        let new_secret_key = SecretKey::from_slice(new_password_string.as_bytes()).unwrap();

        for entry in self.entries.iter_mut() {
            entry.user_name = encode(&decode(&entry.user_name, &self.secret_key), &new_secret_key);
            entry.email = encode(&decode(&entry.email, &self.secret_key), &new_secret_key);
            entry.password = encode(&decode(&entry.password, &self.secret_key), &new_secret_key);
        }

        self.password_hash = password_hash;
        self.secret_key = new_secret_key;
        flushed_print!("Success!\n");
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        if self.entries.is_empty() {
            if let Err(e) = fs::remove_file(&self.storage_file_path) {
                dbg!(e);
            }
            return;
        }
        let new_file_contents = serde_json::to_string(&self.entries).unwrap();
        fs::write(&self.storage_file_path, new_file_contents.as_bytes()).unwrap();
        let new_file_contents = serde_json::to_string(&self.password_hash).unwrap();
        fs::write(&self.hash_file_path, new_file_contents.as_bytes()).unwrap();
    }
}

fn main() {
    let mut manager = Manager::new();
    let mut command = String::new();

    loop {
        flushed_print!("Enter a command. [new, del, get, view, close, change_password]: ");
        read_input_popped(&mut command);

        match command.as_str() {
            "new" => manager.new_entry(),
            "del" => manager.delete_entry(),
            "get" => manager.get_entry(),
            "view" => manager.view_all(),
            "change_password" => manager.change_password(),
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
