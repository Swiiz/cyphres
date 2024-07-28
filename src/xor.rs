use crate::{EncryptedPayload, Payload, RawPayload};

pub struct XorCypher<T: Payload> {
    inner: RawPayload,
    _marker: std::marker::PhantomData<T>,
}

impl<P: Payload> From<RawPayload> for XorCypher<P> {
    fn from(inner: RawPayload) -> Self {
        Self {
            inner,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<'a, P: Payload> EncryptedPayload for XorCypher<P> {
    type Key = u8;
    type InnerPayload = P;

    fn decrypt(self, key: &Self::Key) -> P {
        let vec = self.inner.to_vec();
        vec.into_iter().map(|x| x ^ key).collect::<Vec<u8>>().into()
    }
}

pub trait XorCypherExt {
    fn xor_encrypt(self, key: &u8) -> RawPayload;
}

impl XorCypherExt for RawPayload {
    fn xor_encrypt(self, key: &u8) -> RawPayload {
        let mut inner = self.to_vec();
        for byte in inner.iter_mut() {
            *byte ^= key;
        }
        inner
    }
}
