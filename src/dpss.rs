use curve25519_dalek::Scalar;

use crate::polynomial::Polynomial;

struct DPSS {}

impl DPSS {
    fn reshare_old(
        s_i_d: Scalar,
        s_hat_i_d: Scalar,
        new_degree: usize,
    ) -> (Polynomial, Polynomial) {
        (
            Polynomial::new_w_secret(new_degree, s_i_d),
            Polynomial::new_w_secret(new_degree, s_hat_i_d),
        )
    }
}
