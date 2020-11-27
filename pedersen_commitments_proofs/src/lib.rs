#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#[macro_use]
extern crate zkp;
extern crate rand;

mod transcript;

pub(crate) mod generators;
pub mod algebraic_proofs;
pub mod svm_proof;
pub mod boolean_proofs;
pub mod utils;

pub use crate::generators::PedersenVecGens;
pub use crate::svm_proof::adhoc_proof::zkSVMProver;

