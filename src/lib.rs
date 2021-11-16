#![allow(dead_code)]

#[cfg(not(feature = "wasm"))]
pub use halo2_zcash as halo2;

#[cfg(feature = "wasm")]
pub use halo2_adria0 as halo2;

mod circuit;
pub mod franchise;
mod primitives;
pub mod utils;
