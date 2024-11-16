use std::collections::{HashMap, HashSet};

use curve25519_dalek::Scalar;

use crate::polynomial::{BivariatePolynomial, Polynomial};

pub struct FileSSS {}

static SCALAR_SIZE: usize = 32;

impl FileSSS {
    pub fn split(
        file: Vec<u8>,
        indices: HashSet<Scalar>,
        threshold: usize,
    ) -> HashMap<Scalar, Vec<Scalar>> {
        // each curve25519_dalek::Scalar can encode 376 bits = 47 bytes, use 32 bytes to make
        // Scalar conversion easier
        // however, Scalar conversion sometimes fails if the highest order bit is 1, so convert 31
        // bytes at a time
        let mut file_data: Vec<u8> = Vec::from(file.len().to_le_bytes());
        file_data.extend_from_slice(file.as_slice());
        let num_polynomials = file_data.len().div_ceil(SCALAR_SIZE - 1);
        file_data.resize(num_polynomials * (SCALAR_SIZE - 1), 0);

        let secrets: Vec<Scalar> = file_data
            .chunks(SCALAR_SIZE - 1)
            .map(|chunk| {
                let mut chunk_array = [0u8; 32];
                chunk_array[..31].copy_from_slice(chunk);
                Scalar::from_canonical_bytes(chunk_array)
                    .into_option()
                    .unwrap()
            })
            .collect();

        let polynomials: Vec<Polynomial> = secrets
            .iter()
            .map(|secret| Polynomial::new_w_secret(threshold, secret.clone()))
            .collect();
        indices
            .iter()
            .map(|i| {
                (
                    i.clone(),
                    polynomials
                        .iter()
                        .map(|poly| poly.at_scalar(i.clone()))
                        .collect(),
                )
            })
            .collect()
    }

    pub fn reconstruct(shares: HashMap<Scalar, Vec<Scalar>>) -> Vec<u8> {
        if shares.len() == 0 {
            return Vec::new();
        }
        let num_polynomials = shares.iter().next().unwrap().1.len();

        let mut result = Vec::new();
        for poly_i in 0..num_polynomials {
            let index_shares: HashMap<Scalar, Scalar> = shares
                .iter()
                .map(|(index, vec)| (index.clone(), vec.get(poly_i).unwrap().clone()))
                .collect();
            let result_scalar = BivariatePolynomial::interpolate_0(index_shares);
            let result_array = result_scalar.to_bytes();
            let trunc_result_array = &result_array[..result_array.len() - 1];
            result.extend_from_slice(&trunc_result_array);
        }

        let (size, result_bytes) = result.split_at(std::mem::size_of::<usize>());
        let size: [u8; 8] = size.try_into().unwrap();
        let length = usize::from_le_bytes(size);
        println!("{:?}", result_bytes.len());

        let mut result = Vec::from(result_bytes);
        result.truncate(length);
        result
    }
}

#[cfg(test)]
#[path = "file_sss_tests.rs"]
mod file_sss_test;
