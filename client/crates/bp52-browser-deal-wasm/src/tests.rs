use crate::rng::WorkerRng;
use rand_core::RngCore;

#[test]
fn worker_rng_is_deterministic_and_domain_separated() {
    let mut first = WorkerRng::new([1; 32]);
    let mut repeated = WorkerRng::new([1; 32]);
    let mut other = WorkerRng::new([2; 32]);
    let mut first_bytes = [0_u8; 97];
    let mut repeated_bytes = [0_u8; 97];
    let mut other_bytes = [0_u8; 97];
    first.fill_bytes(&mut first_bytes);
    repeated.fill_bytes(&mut repeated_bytes);
    other.fill_bytes(&mut other_bytes);
    assert_eq!(first_bytes, repeated_bytes);
    assert_ne!(first_bytes, other_bytes);
}
