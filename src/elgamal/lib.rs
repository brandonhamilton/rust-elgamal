/*!
* Elgamal public key cryptography implementation in Rust.
*
* - Key generation
* - Signature generation and verification (https://en.wikipedia.org/wiki/ElGamal_signature_scheme)
* - Encryption and Decryption (https://en.wikipedia.org/wiki/ElGamal_encryption)
* 
* Copyright (c) 2014, Brandon Hamilton
* All rights reserved.
* 
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
* 
* 1. Redistributions of source code must retain the above copyright notice, this
*    list of conditions and the following disclaimer. 
* 2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
* 
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
* ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#![desc = "Elgamal public key cryptography."]
#![license = "BSD"]
#![crate_name="elgamal"]
#![crate_type = "rlib"]

#![allow(deprecated)]

extern crate num;
extern crate serialize;

use std::rand;
use num::integer::Integer;
use num::bigint::{BigInt,BigUint,RandBigInt,ToBigInt};
use std::num::{Zero, One, FromStrRadix, ToStrRadix};
use serialize::hex::{ToHex, FromHex};

#[deriving(Show)]
pub struct PublicKey {
    g: BigUint, 
    p: BigUint,
    y: BigUint,
    bit_size: uint
}

#[deriving(Show)]
pub struct PrivateKey {
    g: BigUint, 
    p: BigUint,
    x: BigUint
}

// Modular exponentiation
// https://en.wikipedia.org/wiki/Modular_exponentiation
fn pow_mod(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
    let zero: BigUint = Zero::zero();
    let one: BigUint  = One::one();

    let mut result: BigUint = One::one();
    let mut e     : BigUint = exponent.clone();
    let mut b     : BigUint = base.clone();

    while e > zero {
        if e & one == one {
            result = ( result * b ) % (*modulus);
        }
        e = e >> 1;
        b = ( b * b ) % (*modulus);
    }
    result
}

// Modular multiplicative inverse using Extended Euclidean Algorithm
// https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
fn inv_mod(num: &BigUint, modulus: &BigUint) -> Option<BigUint> {
    let zero: BigInt = Zero::zero();
    let mut x: BigInt = Zero::zero();
    let mut y: BigInt = One::one();
    let mut u: BigInt = One::one();
    let mut v: BigInt = Zero::zero();

    let mut a: BigInt = num.to_bigint().unwrap();
    let mut b: BigInt = modulus.to_bigint().unwrap();

    while a != zero {
        let q = b / a;
        let r = b % a;
        let m = x - u*q;
        let n = y - v*q;
        b = a; a = r;
        x = u; y = v;
        u = m; v = n;
    }

    if b == One::one() {
        let result = if x.is_negative() {
            (x + modulus.to_bigint().unwrap()).to_biguint().unwrap()
        } else {
            x.to_biguint().unwrap() % *modulus
        };
        Some(result)
    } else {
        None
    }
}


// Miller-Rabin Primality Test
// https://en.wikipedia.org/wiki/Miller-Rabin_primality_test
fn is_prime_number(num: &BigUint, certainty: uint) -> bool {
    let zero: BigUint = Zero::zero();
    let one : BigUint = One::one();
    let two = one + one;

    if *num == two       { return true }
    if num % two == zero { return false }

    let num_less_one = num - one;

    // write n-1 as 2**s * d
    let mut d = num_less_one.clone();
    let mut s: BigUint = Zero::zero();
    while d % two == zero  {
        d = d / two;
        s = s + one;
    }

    let mut k = 0;
    let mut rng = rand::task_rng();

    // Test for probable prime
    while k < certainty {
        let a = rng.gen_biguint_range(&two, num);
        let mut x = pow_mod(&a, &d, num);
        if x != one && x != num_less_one {
            let mut r: BigUint = Zero::zero();
            loop {
                x = pow_mod(&x, &two, num);
                if x == num_less_one {
                    break;    
                } else if x == one || r == (s - one) {
                    return false
                }
                r = r + one;
            }
        }
        k += 2;
    }
    true
}

// Random Prime Generation
fn random_prime(bit_size: uint, certainty: uint) -> BigUint {
    let zero: BigUint = Zero::zero();
    let one : BigUint = One::one();
    let two = one + one;
    let mut rng = rand::task_rng();
    let mut target = rng.gen_biguint(bit_size);
    if target % two == zero { target = target + one }
    while !is_prime_number(&target, certainty) {
        target = target + two;
    }
    target
}

fn random_prime_default(bit_size: uint) -> BigUint {
    random_prime(bit_size, 128)
}

// Hex string padding
fn pad_hex_str(s: String, len: uint) -> String {
    if s.len() < len {
        let mut new_s = String::with_capacity(len);
        new_s.grow(len - s.len(), '0');
        new_s.push_str(s.as_slice());
        return new_s
    }
    s
}

// Key generation 
pub fn generate_keys(bit_size: uint) -> (PublicKey, PrivateKey) {

    let one: BigUint = One::one();
    let mut rng = rand::task_rng();

    // Create a random large prime number
    let p = random_prime_default(bit_size);

    // Randomly chose a generator of the multiplicative group of integers modulo p (Zp)
    let mut g = random_prime_default(bit_size);
    while p.gcd(&g) != one {
        g = random_prime_default(bit_size);
    }

    // Randomly choose a secret key x with 1 < x < p − 1
    let bound = p - one;
    let mut x: BigUint = rng.gen_biguint(bit_size);
    while x >= bound || x <= one {
        x = rng.gen_biguint(bit_size);
    };
    
    // Compute y = g^x mod p
    let y = pow_mod(&g, &x, &p);

    ( PublicKey{ p: p.clone(), g: g.clone(), y: y, bit_size: bit_size }, PrivateKey{ p: p.clone(), g: g.clone(), x: x } )
}

impl PrivateKey {
    // Signature generation
    pub fn sign(&self, m: &BigUint) -> (BigUint, BigUint) {
        let one: BigUint = One::one();
        let mut rng = rand::task_rng();
        let bound = self.p - one;
        let mut k: BigUint = rng.gen_biguint_range(&one, &self.p);
        while k >= bound || k <= one || k.gcd(&bound) != one {
            k = rng.gen_biguint_range(&one, &self.p);
        };
        let r = pow_mod(&self.g, &k, &self.p);
        let s = ( ( m - ( self.x * r ) ) * inv_mod( &k, &bound ).unwrap() ) % bound;
        (r, s)
    }

    // Signature generation (String encoding)
    pub fn sign_string(&self, m: &str) -> String {
        let (r, s) = self.sign( &FromStrRadix::from_str_radix( m.as_bytes().to_hex().as_slice(), 16).unwrap() );
        let r_hex   = r.to_str_radix(16);
        let s_hex   = s.to_str_radix(16);
        let max_len = std::cmp::max( r_hex.len(), s_hex.len() );
        format!("{}{}", pad_hex_str(r_hex, max_len), pad_hex_str(s_hex, max_len))
    }

    // Decryption
    pub fn decrypt(&self, c1: &BigUint, c2: &BigUint) -> BigUint {
        (c2 * inv_mod(&pow_mod(c1, &self.x, &self.p), &self.p).unwrap()) % self.p
    }

    // Decryption (String encoding)
    pub fn decrypt_string(&self, m: &str) -> String {
        let c1: BigUint = FromStrRadix::from_str_radix(m.slice_to(m.len() / 2), 16).unwrap();
        let c2: BigUint = FromStrRadix::from_str_radix(m.slice_from(m.len() / 2), 16).unwrap();
        let d = self.decrypt(&c1, &c2);
        String::from_utf8(d.to_str_radix(16).as_slice().from_hex().unwrap()).unwrap()
    }
}

impl PublicKey {
    // Signature verification
    pub fn verify(&self, r: &BigUint, s: &BigUint, m: &BigUint) -> bool {
        let zero: BigUint = Zero::zero();
        if *r < zero || *r >= self.p || *s < zero || *s >= self.p {
            return false
        }
        let left  = pow_mod(&self.g, m, &self.p);
        let right = ( pow_mod(&self.y, r, &self.p) * pow_mod(r, s, &self.p) ) % self.p;
        left == right
    }

    // Signature verification (String encoding)
    pub fn verify_string(&self, sig: &str, m: &str) -> bool {
        let r: BigUint = FromStrRadix::from_str_radix(sig.slice_to(sig.len() / 2), 16).unwrap();
        let s: BigUint = FromStrRadix::from_str_radix(sig.slice_from(sig.len() / 2), 16).unwrap();
        self.verify(&r, &s, &FromStrRadix::from_str_radix( m.as_bytes().to_hex().as_slice(), 16).unwrap() )
    }

    // Encryption
    pub fn encrypt(&self, m: &BigUint) -> (BigUint, BigUint) {
        let one: BigUint = One::one();
        let mut rng = rand::task_rng();
        let k: BigUint = rng.gen_biguint_range(&one, &(self.p - one));
        let c1 = pow_mod(&self.g, &k, &self.p);
        let c2 = ( pow_mod(&self.y, &k, &self.p) * (*m) ) % self.p;
        (c1, c2)
    }

    // Encryption (String encoding)
    pub fn encrypt_string(&self, m: &str) -> String {
        let maximum_len = self.bit_size / 8;
        assert!( m.char_len() <= maximum_len, "Message cannot be larger than key size ({} bytes)", maximum_len);
        let (c1, c2) = self.encrypt( &FromStrRadix::from_str_radix( m.as_bytes().to_hex().as_slice(), 16).unwrap() );
        format!("{}{}", pad_hex_str(c1.to_str_radix(16), maximum_len*2), pad_hex_str(c2.to_str_radix(16), maximum_len*2))
    }
}

#[cfg(test)]
mod test_elgamal {
    use super::{generate_keys, is_prime_number, pow_mod};
    use num::bigint::BigUint;
    use std::from_str::FromStr;

    #[test]
    fn test_miller_rabin() {
        let composite = "1298074214633706835075030044377085";
        let prime     = "1298074214633706835075030044377087";
        let known_composite: BigUint = FromStr::from_str(composite).unwrap();
        let known_prime: BigUint = FromStr::from_str(prime).unwrap();
        assert!(!is_prime_number(&known_composite, 128));
        assert!(is_prime_number(&known_prime, 128));
    }

    #[test]
    fn test_keygen() {
        let (public_key, private_key) = generate_keys(128);
        assert!(public_key.bit_size == 128)
        assert!(public_key.p == private_key.p && public_key.g == private_key.g)
        assert!(public_key.y == pow_mod(&public_key.g, &private_key.x, &public_key.p))
    }

    #[test]
    fn test_encryption() {
        let (public_key, private_key) = generate_keys(128);
        let plaintext = "Secret";
        let ciphertext = public_key.encrypt_string(plaintext);
        let decrytped_plaintext = private_key.decrypt_string(ciphertext.as_slice());
        assert!(plaintext == decrytped_plaintext.as_slice());
    }

    #[test]
    fn test_signature() {
        let (public_key, private_key) = generate_keys(128);
        let ciphertext = public_key.encrypt_string("Secret");
        let signature = private_key.sign_string(ciphertext.as_slice());
        let verified  = public_key.verify_string(signature.as_slice(), ciphertext.as_slice());
        assert!(verified);
    }
}