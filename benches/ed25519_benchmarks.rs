// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2018-2019 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#[macro_use]
extern crate criterion;
extern crate ed25519_dalek;
extern crate rand;

use criterion::Criterion;

mod ed25519_benches {
    use super::*;
    use ed25519_dalek::ExpandedSecretKey;
    use ed25519_dalek::Keypair;
    use ed25519_dalek::PublicKey;
    use ed25519_dalek::Signature;
    use ed25519_dalek::verify_batch;
    use rand::thread_rng;
    use rand::rngs::ThreadRng;

    fn sign(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let msg: &[u8] = b"";

        c.bench_function("Ed25519 signing", move |b| {
                         b.iter(| | keypair.sign(msg))
        });
    }

    fn sign_expanded_key(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let expanded: ExpandedSecretKey = (&keypair.secret).into();
        let msg: &[u8] = b"";

        c.bench_function("Ed25519 signing with an expanded secret key", move |b| {
                         b.iter(| | expanded.sign(msg, &keypair.public))
        });
    }

    fn verify(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let msg: &[u8] = b"";
        let sig: Signature = keypair.sign(msg);

        c.bench_function("Ed25519 signature verification", move |b| {
                         b.iter(| | keypair.verify(msg, &sig))
        });
    }

    fn verify_batch_signatures(c: &mut Criterion) {
        static BATCH_SIZES: [usize; 8] = [4, 8, 16, 32, 64, 96, 128, 256];

        c.bench_function_over_inputs(
            "Ed25519 batch signature verification",
            |b, &&size| {
                let mut csprng: ThreadRng = thread_rng();
                let keypairs: Vec<Keypair> = (0..size).map(|_| Keypair::generate(&mut csprng)).collect();
                let msg: &[u8] = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
                let messages: Vec<&[u8]> = (0..size).map(|_| msg).collect();
                let signatures:  Vec<Signature> = keypairs.iter().map(|key| key.sign(&msg)).collect();
                let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();

                b.iter(|| verify_batch(&messages[..], &signatures[..], &public_keys[..]));
            },
            &BATCH_SIZES,
        );
    }

    fn key_generation(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();

        c.bench_function("Ed25519 keypair generation", move |b| {
                         b.iter(| | Keypair::generate(&mut csprng))
        });
    }

    fn encrypt_decrypt_message(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        let raw_msg = b"Cook Robin killed by?".to_vec();

        c.bench_function("Ed25519 encrypt/decrypt",  move |b| {
            b.iter(| | {
                let pair0 = Keypair::generate(&mut csprng);
                let sec0 = ExpandedSecretKey::from(&pair0.secret);
                let pair1 = Keypair::generate(&mut csprng);
                let sec1 = ExpandedSecretKey::from(&pair1.secret);

                let mut ecdhe0 = sec0.shared_key(&pair1.public);
                let ecdhe1 = sec1.shared_key(&pair0.public);

                let enc_msg = ecdhe0.encrypt(&raw_msg);
                let dec_meg = ecdhe1.decrypt(&enc_msg);
                dec_meg
            })
        });
    }

    criterion_group!{
        name = ed25519_benches;
        config = Criterion::default();
        targets =
            sign,
            sign_expanded_key,
            verify,
            verify_batch_signatures,
            key_generation,
            encrypt_decrypt_message,
    }
}

criterion_main!(
    ed25519_benches::ed25519_benches,
);
