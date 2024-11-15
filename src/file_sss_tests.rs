#[cfg(test)]
mod file_sss_test {
    use std::collections::HashSet;

    use rand::{rngs::OsRng, Rng};

    use crate::{file_sss::FileSSS, util::i32_to_scalar};

    #[test]
    fn test_reconstruct_vec() {
        let mut rng = OsRng;
        let size = rng.gen_range(100..200);
        let mut random_vec: Vec<u8> = Vec::<u8>::with_capacity(size);
        for _ in 0..size {
            random_vec.push(rand::random::<u8>());
        }

        let indices = HashSet::from([
            i32_to_scalar(1),
            i32_to_scalar(2),
            i32_to_scalar(3),
            i32_to_scalar(4),
        ]);
        let mut shares = FileSSS::split(random_vec.clone(), indices, 2);

        shares.remove(&i32_to_scalar(2)); // only need 3 to reconstruct

        let try_vec = FileSSS::reconstruct(shares);
        assert_eq!(random_vec, try_vec);
    }
}
