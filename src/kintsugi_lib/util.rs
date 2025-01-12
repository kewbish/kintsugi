use curve25519_dalek::Scalar;

pub fn i32_to_scalar(i: i32) -> Scalar {
    let mut acc = Scalar::ZERO;
    for _ in 0..i.abs() {
        if i > 0 {
            acc += Scalar::ONE;
        } else {
            acc -= Scalar::ONE;
        }
    }
    acc
}
