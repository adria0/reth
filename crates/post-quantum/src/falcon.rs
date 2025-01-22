use alloy_primitives::Address;
use oqs::sig::{Algorithm, PublicKey, PublicKeyRef, SecretKey, Sig, SignatureRef};
use sha3::digest::ExtendableOutput;
use std::io::Write;

// Open questions here
// - it is the hash method correct?
// - is the address length correct as an identifier of the public key, or must be larger (>160 bits)
// - is the address hash (SHAKE256) ok? With grover it falls into 128 bits
//   - SHAKE256 offers 256 bits of security, interlally uses KECCAK512 (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
//   - But it falls into 128 bits of security on grover algorithm?

/// Hashed content for hash-and-sign
pub type Hash = [u8; 32];

/// create a pair of falcon keys
pub fn create_key_pair() -> (PublicKey, SecretKey) {
    let sigalg = Sig::new(Algorithm::Falcon512).unwrap();
    sigalg.keypair().unwrap()
}

/// get the address of a public key
pub fn address_of<'a>(pk: impl Into<PublicKeyRef<'a>>) -> Address {
    let mut address = [0u8; 20];

    let mut shake256 = sha3::Shake256::default();
    shake256.write_all(&pk.into()).unwrap();
    shake256.finalize_xof_into(&mut address);

    Address::from_slice(&address)
}

/// hash a message
pub fn hash(m: &[u8], pk: &PublicKey) -> Hash {
    // ala' ML-DSA SHAKE256(SHAKE256(pk, 64) || 0x00 || 0x00 || message)

    let mut pk_hash = [0u8; 64];
    let mut shake256 = sha3::Shake256::default();
    shake256.write_all(pk.as_ref()).unwrap();
    shake256.finalize_xof_into(&mut pk_hash);

    let mut message_hash = [0u8; 32];
    let mut shake256 = sha3::Shake256::default();
    shake256.write_all(&pk_hash).unwrap();
    shake256.write_all(&[0u8; 2]).unwrap();
    shake256.write_all(m).unwrap();
    shake256.finalize_xof_into(&mut message_hash);

    message_hash
}

/// sign
pub fn sign(m: &[u8], sk: &SecretKey) -> Vec<u8> {
    let sigalg = Sig::new(Algorithm::Falcon512).unwrap();
    sigalg.sign(m, sk).unwrap().into_vec()
}

/// verify a signature
pub fn verify(m: &[u8], sig: &[u8], pk: &PublicKey) -> bool {
    let sigalg = Sig::new(Algorithm::Falcon512).unwrap();
    let sig = SignatureRef::from_bytes_unsafe(sig);
    sigalg.verify(m, sig, pk).is_ok()
}

/// sign a hash
pub fn sign_hash(hash: &Hash, pk: &PublicKey, sk: &SecretKey) -> Vec<u8> {
    let sigalg = Sig::new(Algorithm::Falcon512).unwrap();
    let signature = sigalg.sign(hash, sk).unwrap();
    let mut r = Vec::new();

    r.append(&mut u16::to_le_bytes(pk.len() as u16).into());
    r.append(&mut pk.clone().into_vec());
    r.append(&mut signature.into_vec());
    r
}

/// verify hash signature
pub fn verify_hash(hash: &Hash, sig: &[u8]) -> Option<Address> {
    let len = u16::from_le_bytes([sig[0], sig[1]]) as usize;
    let pk = PublicKeyRef::from_bytes_unsafe(&sig[2..2 + len]);
    let signature = SignatureRef::from_bytes_unsafe(&sig[2 + len..]);

    let sigalg = Sig::new(Algorithm::Falcon512).unwrap();
    sigalg.verify(hash, signature, pk).is_ok().then(|| address_of(pk))
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_falcon_hash_and_sign() {
        let m = b"hello word";
        let (pk, sk) = create_key_pair();
        let hash = hash(m, &pk);
        let sig = sign_hash(&hash, &pk, &sk);

        let recover_addr = verify_hash(&hash, &sig).unwrap();

        assert_eq!(address_of(&pk), recover_addr);
    }

    #[test]
    fn test_falcon_sign() {
        let m = b"hello word";
        let (pk, sk) = create_key_pair();
        let sig = sign(m, &sk);
        assert!(verify(m, &sig, &pk));
    }
}
