# rust-elgamal

Elgamal public key cryptography implementation in Rust.

**This library has been built as an exercise in implementing algorithms in Rust, and is not recommended for any production use requiring real security**

# API

#### Key generation
* **generate_keys** - Generate Elgamal keypair
```rust
fn generate_keys(bit_size: uint) -> (PublicKey, PrivateKey)
```

#### Elgamal Encryption and Signature scheme

* _PublicKey_ is an object representing the Elgamal public key with the following methods:
    * **encrypt** - Encryption
    ```rust
    fn encrypt(&self, m: &BigUint) -> (BigUint, BigUint)
    ```

    * **encrypt_string** - Encrypt a plaintext string
    ```rust
    fn encrypt_string(&self, m: &str) -> String
    ```

    * **verify** - Verify signature
    ```rust
    fn verify(&self, r: &BigUint, s: &BigUint, m: &BigUint) -> bool
    ```

    * **verify_string** - Verify signature for a string
    ```rust
    fn verify_string(&self, sig: &str, m: &str) -> bool
    ```


* _PrivateKey_ is an object representing the Elgamal private key with the following methods:
  * **decrypt** - Decryption
    ```rust
    fn decrypt(&self, c1: &BigUint, c2: &BigUint) -> BigUint
    ```

  * **decrypt_string** - Decrypt a ciphertext string
    ```rust
    fn decrypt_string(&self, m: &str) -> String
    ```

  * **sign** - Signature generation
    ```rust
    fn sign(&self, m: &BigUint) -> (BigUint, BigUint)
    ```

  * **sign_string** - Sign a string
    ```rust
    fn sign_string(&self, sig: &str, m: &str) -> bool
    ```


# Example

```rust
extern crate elgamal;

fn main() {

    let (public_key, private_key) = elgamal::generate_keys(1024);

    let plaintext = "Secret";

    let ciphertext = public_key.encrypt_string(plaintext);
    let signature = private_key.sign_string(ciphertext.as_slice());

    let decrytped_plaintext = private_key.decrypt_string(ciphertext.as_slice());
    let verified = public_key.verify_string(signature.as_slice(), ciphertext.as_slice());

    println!("Decrypted message: {}, Valid signature : {}", decrytped_plaintext, verified);
}
```

# Building the library

- Compile library:
   ```
   cargo build
   ```

- Run tests:
   ```
   cargo test
   ```
