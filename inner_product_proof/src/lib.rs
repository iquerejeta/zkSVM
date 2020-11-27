#![cfg_attr(not(feature = "std"), no_std)]
#![feature(nll)]
#![feature(external_doc)]
#![feature(try_trait)]

extern crate alloc;
extern crate serde_derive;

mod util;

mod errors;
mod generators;
mod inner_product_proof;
mod ip_zk_proof;
mod range_proof;
mod transcript;

pub use crate::range_proof::dealer;
pub use crate::range_proof::messages;
pub use crate::range_proof::party;

pub use crate::errors::ProofError;
pub use crate::generators::{BulletproofGens, BulletproofGensShare, PedersenGens};
pub use crate::ip_zk_proof::InnerProductZKProof;
pub use crate::inner_product_proof::{InnerProductProof, inner_product, };
pub use crate::util::exp_iter;
pub use crate::range_proof::RangeProof;
