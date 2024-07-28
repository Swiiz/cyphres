#[cfg(feature = "aes")]
pub mod aes;

#[cfg(feature = "xor")]
pub mod xor;

pub trait EncryptedPayload: Payload {
    type Key;
    type InnerPayload: Payload;
    fn decrypt(self, key: &Self::Key) -> Self::InnerPayload;
}
impl<T: EncryptedPayload> Payload for T {}

pub type RawPayload = Vec<u8>;
pub trait Payload: From<RawPayload> {}
