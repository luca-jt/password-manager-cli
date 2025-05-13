# Usage
Compile from source with
```sh
cargo build --release
```
and then follow the instructions.\
You can store new account data, retrieve it by platform name, change the master password, delete entries by platform name, and view all stored entries.\
The account data is stored in a json file with all relevant data obfuscated using the master password. The validity of your master password is checked by comparing the entered password to a hash that is also stored on disk. When retrieving account data for a specific platform, the corresponding password is automatically copied to the clipboard.
