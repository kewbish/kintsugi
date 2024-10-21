use std::collections::{HashMap, HashSet};

use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::opaque::P2POpaqueError;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Polynomial {
    pub(crate) coeffs: Vec<Scalar>,
}

fn usize_to_scalar(i: usize) -> Scalar {
    let mut i_bytes = [0u8; 32];
    i_bytes[..8].copy_from_slice(&i.to_le_bytes());
    Scalar::from_bytes_mod_order(i_bytes)
}

impl Polynomial {
    pub fn new(degree: usize) -> Self {
        let mut polynomial = vec![Scalar::ZERO; degree + 1];
        for i in 0..(degree + 1) {
            polynomial[i] = Scalar::random(&mut OsRng)
        }
        Polynomial { coeffs: polynomial }
    }
    pub fn new_w_secret(degree: usize, secret: Scalar) -> Self {
        let mut polynomial = Polynomial::new(degree);
        polynomial.coeffs[0] = secret;
        polynomial
    }
    pub fn to_bytes(self) -> Result<Vec<u8>, P2POpaqueError> {
        let string_res = serde_json::to_string(&self);
        if let Err(e) = string_res {
            return Err(P2POpaqueError::SerializationError(
                "JSON serialization of polynomial failed: ".to_string() + &e.to_string(),
            ));
        }
        Ok(string_res.unwrap().into_bytes())
    }
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, P2POpaqueError> {
        let res: Result<Self, _> = serde_json::from_slice(&bytes);
        if let Err(e) = res {
            return Err(P2POpaqueError::SerializationError(
                "JSON deserialization of polynomial failed: ".to_string() + &e.to_string(),
            ));
        }
        Ok(res.unwrap())
    }
    fn pow(base: Scalar, index: usize) -> Scalar {
        let mut acc = Scalar::ONE;
        for _ in 0..index {
            acc *= base;
        }
        acc
    }
    pub fn at(&self, i: usize) -> Scalar {
        let i_scalar = usize_to_scalar(i);
        let mut value = Scalar::ZERO;
        for index in 0..self.coeffs.len() {
            value += self.coeffs[index] * Polynomial::pow(i_scalar, index);
        }
        value
    }
    pub fn at_scalar(&self, i: Scalar) -> Scalar {
        let mut value = Scalar::ZERO;
        for index in 0..self.coeffs.len() {
            value += self.coeffs[index] * Polynomial::pow(i, index);
        }
        value
    }
}

pub struct BivariatePolynomial {
    pub(crate) polynomials: HashMap<Scalar, Polynomial>,
}

impl BivariatePolynomial {
    pub fn interpolate_0_j(&self, j: Scalar) -> Scalar {
        if !self.polynomials.contains_key(&j) {
            return Scalar::ZERO;
        }

        let b_i_j: HashMap<Scalar, Scalar> = self
            .polynomials
            .iter()
            .map(|(i, poly)| (i.clone(), poly.clone().at_scalar(j)))
            .collect();

        let mut acc = Scalar::ZERO;

        for (i, i_value) in b_i_j.iter() {
            let mut numerator = Scalar::ONE;
            let mut denominator = Scalar::ONE;

            for (j, _) in b_i_j.iter() {
                if i != j {
                    numerator *= j;
                    denominator *= j - i;
                }
            }
            acc = acc + i_value * numerator * denominator.invert();
        }
        acc
    }
}

pub fn get_lagrange_coefficient(current_index: Scalar, all_indices: HashSet<Scalar>) -> Scalar {
    get_lagrange_coefficient_w_target(Scalar::ZERO, current_index, all_indices)
}

pub fn get_lagrange_coefficient_w_target(
    target: Scalar,
    current_index: Scalar,
    all_indices: HashSet<Scalar>,
) -> Scalar {
    let mut numerator = Scalar::ONE;
    let mut denominator = Scalar::ONE;

    for index in all_indices.iter() {
        if index.clone() != current_index {
            numerator *= target - index;
            denominator *= current_index - index;
        }
    }

    numerator * denominator.invert()
}

#[cfg(test)]
#[path = "polynomial_tests.rs"]
mod polynomial_test;
