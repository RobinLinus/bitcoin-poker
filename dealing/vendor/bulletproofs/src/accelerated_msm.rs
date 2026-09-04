//! Fixed-work acceleration helpers for prover multiscalar multiplication.
//!
//! The prover passes witness-derived scalars only to Dalek's constant-time
//! [`MultiscalarMul`] implementation.  Parallelism is over fixed-size chunks
//! selected solely from the public vector length, so no secret scalar controls
//! task creation, memory access, or the choice of group algorithm. A separate
//! allocation-free variable-time helper is restricted to public transcript
//! challenges and public generator factors.

#[cfg(feature = "std")]
use alloc::vec::Vec;

use curve25519_dalek::{
    ristretto::RistrettoPoint,
    scalar::Scalar,
    traits::{Identity, MultiscalarMul},
};

#[cfg(feature = "std")]
use rayon::prelude::*;

/// Keeps each Dalek fixed-window lookup-table working set bounded while
/// leaving enough work in a task to amortize Rayon scheduling.
#[cfg(feature = "std")]
const CT_MSM_CHUNK_SIZE: usize = 4_096;

/// Below two chunks, the serial path avoids Rayon setup and reduction costs.
#[cfg(feature = "std")]
const CT_MSM_PARALLEL_THRESHOLD: usize = CT_MSM_CHUNK_SIZE * 2;

/// Avoids Rayon overhead in the final, small inner-product rounds.
#[cfg(feature = "std")]
const PARALLEL_FOLD_THRESHOLD: usize = 1_024;

/// Signed radix-16 digits of a canonical public scalar.
fn public_radix_16(scalar: &Scalar) -> [i8; 64] {
    let bytes = scalar.to_bytes();
    let mut digits = [0_i8; 64];
    for (index, digit) in digits.iter_mut().enumerate() {
        *digit = ((bytes[index >> 1] >> ((index & 1) << 2)) & 0x0f) as i8;
    }
    for index in 0..63 {
        let carry = (digits[index] + 8) >> 4;
        digits[index] -= carry << 4;
        digits[index + 1] += carry;
    }
    digits
}

/// Allocation-free variable-time double-scalar multiplication for public
/// scalars and public points.
///
/// The signed digits control branches and table indices, so this helper must
/// never receive witness-derived values.  Inner-product generator folding
/// calls it only with transcript challenges and public R1CS factors.
fn public_double_scalar_mul(
    left_scalar: &Scalar,
    left_point: &RistrettoPoint,
    right_scalar: &Scalar,
    right_point: &RistrettoPoint,
) -> RistrettoPoint {
    let left_digits = public_radix_16(left_scalar);
    let right_digits = public_radix_16(right_scalar);

    let mut left_table = [RistrettoPoint::identity(); 8];
    let mut right_table = [RistrettoPoint::identity(); 8];
    left_table[0] = *left_point;
    right_table[0] = *right_point;
    for index in 1..8 {
        left_table[index] = left_table[index - 1] + left_point;
        right_table[index] = right_table[index - 1] + right_point;
    }

    let mut result = RistrettoPoint::identity();
    let mut started = false;
    for index in (0..64).rev() {
        let left_digit = left_digits[index];
        let right_digit = right_digits[index];
        if started {
            for _ in 0..4 {
                result = result + result;
            }
        }
        if left_digit > 0 {
            result += left_table[left_digit as usize - 1];
            started = true;
        } else if left_digit < 0 {
            result -= left_table[usize::from(left_digit.unsigned_abs()) - 1];
            started = true;
        }
        if right_digit > 0 {
            result += right_table[right_digit as usize - 1];
            started = true;
        } else if right_digit < 0 {
            result -= right_table[usize::from(right_digit.unsigned_abs()) - 1];
            started = true;
        }
    }
    result
}

/// Computes a constant-time MSM, using fixed public chunks when `std` is
/// available.
///
/// This function is suitable for witness values and proof masks.  It must not
/// be replaced by Dalek's variable-time Pippenger implementation.
pub(crate) fn constant_time_multiscalar_mul(
    scalars: &[Scalar],
    points: &[RistrettoPoint],
) -> RistrettoPoint {
    assert_eq!(scalars.len(), points.len());

    #[cfg(feature = "std")]
    if scalars.len() >= CT_MSM_PARALLEL_THRESHOLD {
        let partials: Vec<RistrettoPoint> = scalars
            .par_chunks(CT_MSM_CHUNK_SIZE)
            .zip(points.par_chunks(CT_MSM_CHUNK_SIZE))
            .map(|(scalar_chunk, point_chunk)| {
                RistrettoPoint::multiscalar_mul(scalar_chunk, point_chunk)
            })
            .collect();

        // Keep the final reduction order fixed.  Point addition is public, but
        // deterministic ordering makes differential testing straightforward.
        return partials
            .into_iter()
            .fold(RistrettoPoint::identity(), |sum, partial| sum + partial);
    }

    RistrettoPoint::multiscalar_mul(scalars, points)
}

/// Computes a constant-time MSM after multiplying every secret scalar by a
/// corresponding public factor.
///
/// Products are streamed directly into Dalek's constant-time scalar recoding;
/// no additional heap vector containing witness-derived scalars is retained.
pub(crate) fn constant_time_multiscalar_mul_with_factors(
    scalars: &[Scalar],
    public_factors: &[Scalar],
    points: &[RistrettoPoint],
) -> RistrettoPoint {
    assert_eq!(scalars.len(), public_factors.len());
    assert_eq!(scalars.len(), points.len());

    #[cfg(feature = "std")]
    if scalars.len() >= CT_MSM_PARALLEL_THRESHOLD {
        let partials: Vec<RistrettoPoint> = scalars
            .par_chunks(CT_MSM_CHUNK_SIZE)
            .zip(public_factors.par_chunks(CT_MSM_CHUNK_SIZE))
            .zip(points.par_chunks(CT_MSM_CHUNK_SIZE))
            .map(|((scalar_chunk, factor_chunk), point_chunk)| {
                RistrettoPoint::multiscalar_mul(
                    scalar_chunk
                        .iter()
                        .zip(factor_chunk)
                        .map(|(scalar, factor)| scalar * factor),
                    point_chunk,
                )
            })
            .collect();

        return partials
            .into_iter()
            .fold(RistrettoPoint::identity(), |sum, partial| sum + partial);
    }

    RistrettoPoint::multiscalar_mul(
        scalars
            .iter()
            .zip(public_factors)
            .map(|(scalar, factor)| scalar * factor),
        points,
    )
}

/// Runs two independent fixed-work computations concurrently when `std` is
/// available, and sequentially for the no-std backend.
pub(crate) fn join<A, B, FA, FB>(left: FA, right: FB) -> (A, B)
where
    A: Send,
    B: Send,
    FA: FnOnce() -> A + Send,
    FB: FnOnce() -> B + Send,
{
    #[cfg(feature = "std")]
    {
        rayon::join(left, right)
    }

    #[cfg(not(feature = "std"))]
    {
        (left(), right())
    }
}

/// Folds the two secret inner-product vectors with fixed public challenges.
///
/// Scalar arithmetic is constant-time.  Parallel iteration is selected only
/// from the public vector length.
pub(crate) fn fold_secret_vectors(
    a_left: &mut [Scalar],
    a_right: &[Scalar],
    b_left: &mut [Scalar],
    b_right: &[Scalar],
    challenge: &Scalar,
    challenge_inverse: &Scalar,
) {
    assert_eq!(a_left.len(), a_right.len());
    assert_eq!(a_left.len(), b_left.len());
    assert_eq!(a_left.len(), b_right.len());

    #[cfg(feature = "std")]
    if a_left.len() >= PARALLEL_FOLD_THRESHOLD {
        a_left
            .par_iter_mut()
            .zip(a_right.par_iter())
            .zip(b_left.par_iter_mut())
            .zip(b_right.par_iter())
            .for_each(|(((a_l, a_r), b_l), b_r)| {
                *a_l = *a_l * challenge + challenge_inverse * a_r;
                *b_l = *b_l * challenge_inverse + challenge * b_r;
            });
        return;
    }

    for (((a_l, a_r), b_l), b_r) in a_left.iter_mut().zip(a_right).zip(b_left).zip(b_right) {
        *a_l = *a_l * challenge + challenge_inverse * a_r;
        *b_l = *b_l * challenge_inverse + challenge * b_r;
    }
}

/// Folds public generator pairs using allocation-free variable-time point
/// multiplication and fixed public parallel scheduling.
///
/// The scalars in this operation are transcript challenges and therefore
/// public.  Their signed digits control branches and table indices.  This
/// entry point must therefore never be called with witness-derived scalars.
/// The specialized two-point multiplication avoids the millions of tiny heap
/// allocations made by Dalek's generic two-point vartime MSM.
pub(crate) fn fold_public_points(
    left: &mut [RistrettoPoint],
    right: &[RistrettoPoint],
    left_scalar: &Scalar,
    right_scalar: &Scalar,
) {
    assert_eq!(left.len(), right.len());

    #[cfg(feature = "std")]
    if left.len() >= PARALLEL_FOLD_THRESHOLD {
        left.par_iter_mut()
            .zip(right.par_iter())
            .for_each(|(left_point, right_point)| {
                *left_point =
                    public_double_scalar_mul(left_scalar, left_point, right_scalar, right_point);
            });
        return;
    }

    for (left_point, right_point) in left.iter_mut().zip(right) {
        *left_point = public_double_scalar_mul(left_scalar, left_point, right_scalar, right_point);
    }
}

/// First-round public-generator fold, including each generator's public R1CS
/// factor. Both factor slices and both fold scalars must be public: their
/// products are passed to the variable-time public-only helper.
pub(crate) fn fold_public_points_with_factors(
    left: &mut [RistrettoPoint],
    right: &[RistrettoPoint],
    left_factors: &[Scalar],
    right_factors: &[Scalar],
    left_scalar: &Scalar,
    right_scalar: &Scalar,
) {
    assert_eq!(left.len(), right.len());
    assert_eq!(left.len(), left_factors.len());
    assert_eq!(left.len(), right_factors.len());

    #[cfg(feature = "std")]
    if left.len() >= PARALLEL_FOLD_THRESHOLD {
        left.par_iter_mut()
            .zip(right.par_iter())
            .zip(left_factors.par_iter())
            .zip(right_factors.par_iter())
            .for_each(|(((left_point, right_point), left_factor), right_factor)| {
                let left_weight = left_scalar * left_factor;
                let right_weight = right_scalar * right_factor;
                *left_point =
                    public_double_scalar_mul(&left_weight, left_point, &right_weight, right_point);
            });
        return;
    }

    for (((left_point, right_point), left_factor), right_factor) in left
        .iter_mut()
        .zip(right)
        .zip(left_factors)
        .zip(right_factors)
    {
        let left_weight = left_scalar * left_factor;
        let right_weight = right_scalar * right_factor;
        *left_point =
            public_double_scalar_mul(&left_weight, left_point, &right_weight, right_point);
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use curve25519_dalek::{
        constants::RISTRETTO_BASEPOINT_POINT,
        ristretto::RistrettoPoint,
        scalar::Scalar,
        traits::{Identity, MultiscalarMul, VartimeMultiscalarMul},
    };

    use super::{
        constant_time_multiscalar_mul, constant_time_multiscalar_mul_with_factors,
        fold_public_points, fold_public_points_with_factors, fold_secret_vectors,
        public_double_scalar_mul, CT_MSM_CHUNK_SIZE,
    };

    #[test]
    fn public_double_scalar_mul_matches_dalek_for_edge_and_deterministic_vectors() {
        use rand_chacha::ChaCha20Rng;
        use rand_core::SeedableRng;

        let identity = RistrettoPoint::identity();
        let base_twice = RISTRETTO_BASEPOINT_POINT + RISTRETTO_BASEPOINT_POINT;
        let high_canonical = -Scalar::ONE;
        let wide_bytes = [0xff_u8; 64];
        let wide = Scalar::from_bytes_mod_order_wide(&wide_bytes);

        let edge_cases = [
            (
                Scalar::ZERO,
                identity,
                Scalar::ZERO,
                RISTRETTO_BASEPOINT_POINT,
            ),
            (
                Scalar::ONE,
                RISTRETTO_BASEPOINT_POINT,
                Scalar::ZERO,
                base_twice,
            ),
            (
                high_canonical,
                RISTRETTO_BASEPOINT_POINT,
                -Scalar::from(17_u64),
                base_twice,
            ),
            (wide, base_twice, high_canonical, RISTRETTO_BASEPOINT_POINT),
        ];
        for (left_scalar, left_point, right_scalar, right_point) in edge_cases {
            let expected = RistrettoPoint::vartime_multiscalar_mul(
                [left_scalar, right_scalar],
                [left_point, right_point],
            );
            let actual =
                public_double_scalar_mul(&left_scalar, &left_point, &right_scalar, &right_point);
            assert_eq!(actual.compress(), expected.compress());
        }

        // Seeded vectors exercise every radix position reproducibly, including
        // negative signed digits after carry propagation.
        let mut rng = ChaCha20Rng::from_seed([0x52; 32]);
        for _ in 0..128 {
            let left_scalar = Scalar::random(&mut rng);
            let right_scalar = Scalar::random(&mut rng);
            let left_point = RISTRETTO_BASEPOINT_POINT * Scalar::random(&mut rng);
            let right_point = RISTRETTO_BASEPOINT_POINT * Scalar::random(&mut rng);
            let expected = RistrettoPoint::vartime_multiscalar_mul(
                [left_scalar, right_scalar],
                [left_point, right_point],
            );
            let actual =
                public_double_scalar_mul(&left_scalar, &left_point, &right_scalar, &right_point);
            assert_eq!(actual.compress(), expected.compress());
        }
    }

    #[test]
    fn chunked_constant_time_msm_matches_dalek() {
        let length = 2 * CT_MSM_CHUNK_SIZE + 17;
        let scalars = (0..length)
            .map(|index| Scalar::from((index as u64).wrapping_mul(37).wrapping_add(11)))
            .collect::<Vec<_>>();
        let points = vec![RISTRETTO_BASEPOINT_POINT; length];

        let expected = RistrettoPoint::multiscalar_mul(&scalars, &points);
        let actual = constant_time_multiscalar_mul(&scalars, &points);
        assert_eq!(actual.compress(), expected.compress());
    }

    #[test]
    fn factored_chunked_constant_time_msm_matches_dalek() {
        let length = 2 * CT_MSM_CHUNK_SIZE + 17;
        let scalars = (0..length)
            .map(|index| Scalar::from((index as u64).wrapping_mul(41).wrapping_add(3)))
            .collect::<Vec<_>>();
        let factors = (0..length)
            .map(|index| Scalar::from((index as u64).wrapping_mul(17).wrapping_add(5)))
            .collect::<Vec<_>>();
        let points = vec![RISTRETTO_BASEPOINT_POINT; length];

        let expected = RistrettoPoint::multiscalar_mul(
            scalars
                .iter()
                .zip(&factors)
                .map(|(scalar, factor)| scalar * factor),
            &points,
        );
        let actual = constant_time_multiscalar_mul_with_factors(&scalars, &factors, &points);
        assert_eq!(actual.compress(), expected.compress());
    }

    #[test]
    fn allocation_free_public_folds_match_two_point_msm() {
        let length = 1_037;
        let mut left = (0..length)
            .map(|index| RISTRETTO_BASEPOINT_POINT * Scalar::from(index as u64 + 1))
            .collect::<Vec<_>>();
        let right = (0..length)
            .map(|index| RISTRETTO_BASEPOINT_POINT * Scalar::from(index as u64 + 2_001))
            .collect::<Vec<_>>();
        let original_left = left.clone();
        let left_scalar = Scalar::from(19_u64);
        let right_scalar = Scalar::from(23_u64);

        fold_public_points(&mut left, &right, &left_scalar, &right_scalar);
        for index in 0..length {
            let expected = RistrettoPoint::vartime_multiscalar_mul(
                &[left_scalar, right_scalar],
                &[original_left[index], right[index]],
            );
            assert_eq!(left[index].compress(), expected.compress());
        }
    }

    #[test]
    fn factored_public_and_secret_folds_match_equations() {
        let length = 1_037;
        let mut points_left = vec![RISTRETTO_BASEPOINT_POINT; length];
        let points_right = vec![RISTRETTO_BASEPOINT_POINT * Scalar::from(7_u64); length];
        let original_points_left = points_left.clone();
        let left_factors = (0..length)
            .map(|index| Scalar::from(index as u64 + 3))
            .collect::<Vec<_>>();
        let right_factors = (0..length)
            .map(|index| Scalar::from(index as u64 + 9))
            .collect::<Vec<_>>();
        let challenge = Scalar::from(29_u64);
        let challenge_inverse = challenge.invert();

        fold_public_points_with_factors(
            &mut points_left,
            &points_right,
            &left_factors,
            &right_factors,
            &challenge_inverse,
            &challenge,
        );
        for index in 0..length {
            let expected = RistrettoPoint::vartime_multiscalar_mul(
                &[
                    challenge_inverse * left_factors[index],
                    challenge * right_factors[index],
                ],
                &[original_points_left[index], points_right[index]],
            );
            assert_eq!(points_left[index].compress(), expected.compress());
        }

        let mut a_left = vec![Scalar::from(2_u64); length];
        let a_right = vec![Scalar::from(3_u64); length];
        let mut b_left = vec![Scalar::from(5_u64); length];
        let b_right = vec![Scalar::from(11_u64); length];
        fold_secret_vectors(
            &mut a_left,
            &a_right,
            &mut b_left,
            &b_right,
            &challenge,
            &challenge_inverse,
        );
        assert!(a_left.iter().all(|value| *value
            == Scalar::from(2_u64) * challenge + challenge_inverse * Scalar::from(3_u64)));
        assert!(b_left.iter().all(|value| *value
            == Scalar::from(5_u64) * challenge_inverse + challenge * Scalar::from(11_u64)));
    }

    #[cfg(feature = "std")]
    #[test]
    #[ignore = "release-only diagnostic for tuning the fixed public chunk size"]
    fn release_stage_timings() {
        use std::time::Instant;

        let msm_length = 1 << 16;
        let scalars = (0..msm_length)
            .map(|index| Scalar::from(index as u64 + 1))
            .collect::<Vec<_>>();
        let points = vec![RISTRETTO_BASEPOINT_POINT; msm_length];

        let serial_started = Instant::now();
        let serial = RistrettoPoint::multiscalar_mul(&scalars, &points);
        let serial_elapsed = serial_started.elapsed();
        let parallel_started = Instant::now();
        let parallel = constant_time_multiscalar_mul(&scalars, &points);
        let parallel_elapsed = parallel_started.elapsed();
        assert_eq!(serial.compress(), parallel.compress());

        let fold_length = 1 << 14;
        let mut old_fold = vec![RISTRETTO_BASEPOINT_POINT; fold_length];
        let mut new_fold = old_fold.clone();
        let fold_right = vec![RISTRETTO_BASEPOINT_POINT * Scalar::from(7_u64); fold_length];
        let left_scalar = Scalar::from(31_u64);
        let right_scalar = Scalar::from(37_u64);

        let old_fold_started = Instant::now();
        for (left, right) in old_fold.iter_mut().zip(&fold_right) {
            *left = RistrettoPoint::vartime_multiscalar_mul(
                &[left_scalar, right_scalar],
                &[*left, *right],
            );
        }
        let old_fold_elapsed = old_fold_started.elapsed();
        let new_fold_started = Instant::now();
        fold_public_points(&mut new_fold, &fold_right, &left_scalar, &right_scalar);
        let new_fold_elapsed = new_fold_started.elapsed();
        assert!(old_fold
            .iter()
            .zip(&new_fold)
            .all(|(old, new)| old.compress() == new.compress()));

        eprintln!(
            "ct-msm {msm_length}: serial {serial_elapsed:?}, fixed-chunk parallel {parallel_elapsed:?}"
        );
        eprintln!(
            "public fold {fold_length}: generic two-point vartime {old_fold_elapsed:?}, allocation-free parallel {new_fold_elapsed:?}"
        );
    }
}
