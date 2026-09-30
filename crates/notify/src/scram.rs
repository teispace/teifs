//! SCRAM (RFC 5802), the client's side, with SHA-256 (RFC 7677) or SHA-512: the password
//! is never sent, and the server proves it knows it too. Without channel binding (`n,,`),
//! as Kafka takes it.

use aws_lc_rs::{constant_time, digest, hmac, pbkdf2};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use zeroize::Zeroizing;

/// The most iterations a server may ask for: more would only stall the sender.
const MAX_ITERATIONS: u32 = 1_000_000;

/// The hash SCRAM is done with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScramHash {
    /// `SCRAM-SHA-256`.
    Sha256,
    /// `SCRAM-SHA-512`.
    Sha512,
}

impl ScramHash {
    /// The mechanism's name.
    #[must_use]
    pub const fn mechanism(self) -> &'static str {
        match self {
            Self::Sha256 => "SCRAM-SHA-256",
            Self::Sha512 => "SCRAM-SHA-512",
        }
    }

    const fn algorithms(
        self,
    ) -> (
        pbkdf2::Algorithm,
        hmac::Algorithm,
        &'static digest::Algorithm,
    ) {
        match self {
            Self::Sha256 => (
                pbkdf2::PBKDF2_HMAC_SHA256,
                hmac::HMAC_SHA256,
                &digest::SHA256,
            ),
            Self::Sha512 => (
                pbkdf2::PBKDF2_HMAC_SHA512,
                hmac::HMAC_SHA512,
                &digest::SHA512,
            ),
        }
    }
}

/// One exchange: [`Scram::first`], then [`Scram::last`] with the server's first message,
/// then [`Scram::check`] with its last.
pub(crate) struct Scram {
    hash: ScramHash,
    password: Zeroizing<String>,
    nonce: String,
    /// The client's first message without its `n,,` header.
    first_bare: String,
    /// What the server must answer with, once the client's last message is made.
    server_signature: Option<Vec<u8>>,
}

impl Scram {
    /// An exchange for `user` with `password`, with a random nonce.
    pub(crate) fn new(hash: ScramHash, user: &str, password: &str) -> Result<Self, String> {
        let mut bytes = [0; 24];
        aws_lc_rs::rand::fill(&mut bytes).map_err(|_| "no randomness".to_owned())?;
        Ok(Self::with_nonce(
            hash,
            user,
            password,
            &BASE64.encode(bytes),
        ))
    }

    fn with_nonce(hash: ScramHash, user: &str, password: &str, nonce: &str) -> Self {
        let user = user.replace('=', "=3D").replace(',', "=2C");
        Self {
            hash,
            password: Zeroizing::new(password.to_owned()),
            nonce: nonce.to_owned(),
            first_bare: format!("n={user},r={nonce}"),
            server_signature: None,
        }
    }

    /// The client's first message.
    pub(crate) fn first(&self) -> String {
        format!("n,,{}", self.first_bare)
    }

    /// The client's last message, with its proof, for the server's first message.
    pub(crate) fn last(&mut self, server_first: &str) -> Result<Zeroizing<String>, String> {
        let refused = || "it answered with something that isn't SCRAM".to_owned();
        let (mut nonce, mut salt, mut iterations) = (None, None, None);
        for attribute in server_first.split(',') {
            match attribute.split_once('=') {
                Some(("r", value)) => nonce = Some(value),
                Some(("s", value)) => salt = Some(BASE64.decode(value).map_err(|_| refused())?),
                Some(("i", value)) => iterations = value.parse::<u32>().ok(),
                Some(("m", _)) => return Err("it asked for a SCRAM extension".to_owned()),
                _ => {}
            }
        }
        let (Some(nonce), Some(salt), Some(iterations)) = (nonce, salt, iterations) else {
            return Err(refused());
        };
        if !nonce.starts_with(&self.nonce) || nonce.len() == self.nonce.len() {
            return Err("its SCRAM nonce isn't one made from ours".to_owned());
        }
        let iterations = std::num::NonZeroU32::new(iterations)
            .filter(|n| n.get() <= MAX_ITERATIONS)
            .ok_or_else(|| format!("it asked for {iterations} SCRAM iterations"))?;
        let (derive, mac, sha) = self.hash.algorithms();
        let mut salted = Zeroizing::new(vec![0; sha.output_len()]);
        pbkdf2::derive(
            derive,
            iterations,
            &salt,
            self.password.as_bytes(),
            &mut salted,
        );
        let salted = hmac::Key::new(mac, &salted);
        let client_key = hmac::sign(&salted, b"Client Key");
        let stored_key = digest::digest(sha, client_key.as_ref());
        let without_proof = format!("c=biws,r={nonce}");
        let auth_message = format!("{},{server_first},{without_proof}", self.first_bare);
        let signature = hmac::sign(
            &hmac::Key::new(mac, stored_key.as_ref()),
            auth_message.as_bytes(),
        );
        let proof: Zeroizing<Vec<u8>> = Zeroizing::new(
            client_key
                .as_ref()
                .iter()
                .zip(signature.as_ref())
                .map(|(k, s)| k ^ s)
                .collect(),
        );
        let server_key = hmac::sign(&salted, b"Server Key");
        self.server_signature = Some(
            hmac::sign(
                &hmac::Key::new(mac, server_key.as_ref()),
                auth_message.as_bytes(),
            )
            .as_ref()
            .to_vec(),
        );
        Ok(Zeroizing::new(format!(
            "{without_proof},p={}",
            BASE64.encode(&proof[..])
        )))
    }

    /// Checks the server's last message: it proves the server knows the password.
    pub(crate) fn check(&self, server_final: &str) -> Result<(), String> {
        if let Some(error) = server_final.strip_prefix("e=") {
            return Err(format!("it refused the user or password ({error})"));
        }
        let expected = self
            .server_signature
            .as_deref()
            .ok_or("SCRAM's last message came first")?;
        let given = server_final
            .split(',')
            .find_map(|a| a.strip_prefix("v="))
            .and_then(|v| BASE64.decode(v).ok())
            .ok_or("it answered with something that isn't SCRAM")?;
        constant_time::verify_slices_are_equal(&given, expected)
            .map_err(|_| "it didn't prove it knows the password: it isn't the server".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER_FIRST: &str = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,\
                                s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";

    /// RFC 7677's example exchange.
    #[test]
    fn sha_256_is_done_as_rfc_7677_shows() {
        let mut scram =
            Scram::with_nonce(ScramHash::Sha256, "user", "pencil", "rOprNGfwEbeRWgbNEkqO");
        assert_eq!(scram.first(), "n,,n=user,r=rOprNGfwEbeRWgbNEkqO");
        assert!(
            scram
                .check("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")
                .is_err(),
            "not before the client's last message"
        );
        let last = scram.last(SERVER_FIRST).unwrap();
        assert_eq!(
            last.as_str(),
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,\
             p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );
        assert_eq!(
            scram.check("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="),
            Ok(())
        );
        assert!(
            scram
                .check("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G5=")
                .is_err(),
            "another server's signature"
        );
        let refused = scram.check("e=invalid-proof").unwrap_err();
        assert!(refused.contains("invalid-proof"), "{refused}");
    }

    #[test]
    fn sha_512_proves_with_its_own_hash() {
        let mut a = Scram::with_nonce(ScramHash::Sha512, "user", "pencil", "rOprNGfwEbeRWgbNEkqO");
        let mut b = Scram::with_nonce(ScramHash::Sha256, "user", "pencil", "rOprNGfwEbeRWgbNEkqO");
        let (a, b) = (a.last(SERVER_FIRST).unwrap(), b.last(SERVER_FIRST).unwrap());
        let proof = |last: &str| BASE64.decode(last.rsplit_once("p=").unwrap().1).unwrap();
        assert_eq!((proof(&a).len(), proof(&b).len()), (64, 32));
    }

    #[test]
    fn names_are_escaped_and_answers_checked() {
        let scram = Scram::with_nonce(ScramHash::Sha256, "a=b,c", "pw", "n0");
        assert_eq!(scram.first(), "n,,n=a=3Db=2Cc,r=n0");
        let last = |server_first: &str| {
            Scram::with_nonce(ScramHash::Sha256, "u", "pw", "n0").last(server_first)
        };
        assert!(last("r=n0x,s=c2FsdA==,i=4096").is_ok());
        for bad in [
            "r=other,s=c2FsdA==,i=4096",
            "r=n0,s=c2FsdA==,i=4096",
            "r=n0x,s=!!,i=4096",
            "r=n0x,s=c2FsdA==,i=0",
            "r=n0x,s=c2FsdA==,i=1000001",
            "r=n0x,s=c2FsdA==",
            "m=ext,r=n0x,s=c2FsdA==,i=4096",
            "",
        ] {
            assert!(last(bad).is_err(), "{bad}");
        }
        let a = Scram::new(ScramHash::Sha256, "u", "pw").unwrap();
        let b = Scram::new(ScramHash::Sha256, "u", "pw").unwrap();
        assert_ne!(a.first(), b.first(), "each nonce is new");
    }
}
