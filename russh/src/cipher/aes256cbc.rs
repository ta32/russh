// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

extern crate crypto;
use crypto::{ buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };
use super::super::Error;
use sodium::random::randombytes;

const TAG_LEN: usize = 0;
pub const CRYPTO_AES256CBC_KEYBYTES: u32 = 32;
pub const CRYPTO_AES256CBC_NSECBYTES: u32 = 16;

pub const NONCE_BYTES: usize = CRYPTO_AES256CBC_NSECBYTES as usize;
pub const KEY_BYTES: usize = CRYPTO_AES256CBC_KEYBYTES as usize;
pub struct Key(pub [u8; KEY_BYTES]);
pub struct Nonce(pub [u8; NONCE_BYTES]);

pub struct OpeningKey {
    key: Key,
    nonce: Nonce,
}
pub struct SealingKey {
    key: Key,
    nonce: Nonce,
}

pub static CIPHER: super::Cipher = super::Cipher {
    name: NAME,
    key_len: KEY_BYTES,
    nonce_len: NONCE_BYTES,
    make_sealing_cipher,
    make_opening_cipher,
};

pub const NAME: super::Name = super::Name("aes256-cbc");

fn make_sealing_cipher(k: &[u8], n: &[u8]) -> super::SealingCipher {
    let mut key = Key([0; KEY_BYTES]);
    let mut nonce = Nonce([0; NONCE_BYTES]);
    key.0.clone_from_slice(k);
    nonce.0.clone_from_slice(n);
    super::SealingCipher::AES256CBC(SealingKey { key, nonce })
}

fn make_opening_cipher(k: &[u8], n: &[u8]) -> super::OpeningCipher {
    let mut key = Key([0; KEY_BYTES]);
    let mut nonce = Nonce([0; NONCE_BYTES]);
    key.0.clone_from_slice(k);
    nonce.0.clone_from_slice(n);
    super::OpeningCipher::AES256CBC(OpeningKey { key, nonce })
}


impl super::OpeningKey for OpeningKey {
    fn decrypt_packet_length(
        &self,
        _sequence_number: u32,
        encrypted_packet_length: [u8; 4],
    ) -> [u8; 4] {
        encrypted_packet_length
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn open<'a>(
        &self,
        _: u32,
        ciphertext_in_plaintext_out: &'a mut [u8],
        _: &[u8],
    ) -> Result<&'a [u8], Error> {
        let iv = self.nonce.0;
        let mut decryptor = aes::cbc_decryptor(
            aes::KeySize::KeySize256,
            &self.key.0,
            &iv,
            blockmodes::PkcsPadding);

        let mut final_result = Vec::<u8>::new();
        let mut read_buffer = buffer::RefReadBuffer::new(ciphertext_in_plaintext_out);
        let mut buffer = [0; 4096];
        let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

        loop {
            let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true).unwrap();
            final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
            match result {
                BufferResult::BufferUnderflow => break,
                BufferResult::BufferOverflow => { }
            }
        }
        ciphertext_in_plaintext_out.copy_from_slice(&final_result);
        Ok(ciphertext_in_plaintext_out)
    }
}

impl super::SealingKey for SealingKey {
    fn padding_length(&self, payload: &[u8]) -> usize {
        let block_size = 16;
        let extra_len = super::PACKET_LENGTH_LEN + super::PADDING_LENGTH_LEN;
        let padding_len = if payload.len() + extra_len <= super::MINIMUM_PACKET_LEN {
            super::MINIMUM_PACKET_LEN - payload.len() - super::PADDING_LENGTH_LEN
        } else {
            block_size - ((super::PADDING_LENGTH_LEN + payload.len()) % block_size)
        };
        if padding_len < super::PACKET_LENGTH_LEN {
            padding_len + block_size
        } else {
            padding_len
        }
    }

    fn fill_padding(&self, padding_out: &mut [u8]) {
        randombytes(padding_out);
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn seal(
        &self,
        _: u32,
        plaintext_in_ciphertext_out: &mut [u8],
        _: &mut [u8],
    ) {
        let iv = self.nonce.0;
        let mut encryptor = aes::cbc_encryptor(
            aes::KeySize::KeySize256,
            &self.key.0,
            &iv,
            blockmodes::PkcsPadding);

        let mut final_result = Vec::<u8>::new();
        let mut read_buffer = buffer::RefReadBuffer::new(plaintext_in_ciphertext_out);
        let mut buffer = [0; 4096];
        let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

        loop {
            let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true).unwrap();

            final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

            match result {
                BufferResult::BufferUnderflow => break,
                BufferResult::BufferOverflow => { }
            }
        }
        plaintext_in_ciphertext_out.copy_from_slice(&final_result);
    }
}
