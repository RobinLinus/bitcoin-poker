//! Boolean constraint helpers for the fixed-shape SHA-256 relation.
//!
//! [`crate::boolean::Bit`] maintains the invariant that its linear combination is Boolean.
//! Constructors either use a constant, constrain a fresh witness, or derive a
//! new bit through a Boolean identity.  Keeping that invariant here makes it
//! difficult for the SHA-256 gadget to accidentally use an unconstrained bit.

use core::fmt;

use bp52_proof_backend::{ConstraintSystem, LinearCombination, R1CSError, Scalar, Variable};
use zeroize::Zeroize;

/// A Boolean-valued R1CS linear combination and its optional prover witness.
///
/// The assignment is `Some` while synthesizing for a prover and `None` while
/// synthesizing for a verifier.  It is metadata only: soundness comes from the
/// R1CS constraints, not from this field.
#[derive(Clone)]
#[must_use]
pub struct Bit {
    linear_combination: LinearCombination,
    assignment: Option<bool>,
}

impl fmt::Debug for Bit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Bit([REDACTED])")
    }
}

impl Drop for Bit {
    fn drop(&mut self) {
        self.assignment.zeroize();
    }
}

impl Bit {
    /// Returns a constant Boolean value without allocating a multiplier.
    pub fn constant(value: bool) -> Self {
        Self {
            linear_combination: Scalar::from(u64::from(value)).into(),
            assignment: Some(value),
        }
    }

    /// Allocates a fresh bit and enforces `b * (b - 1) = 0`.
    ///
    /// `allocate_multiplier` is used directly so the Booleanity check consumes
    /// exactly one multiplication gate.  The right input is constrained to
    /// `b - 1` and the multiplication output is constrained to zero.
    ///
    /// # Errors
    ///
    /// Returns [`R1CSError::MissingAssignment`] if a prover-side constraint
    /// system is used without an assignment.
    pub fn allocate<CS: ConstraintSystem>(
        cs: &mut CS,
        assignment: Option<bool>,
    ) -> Result<Self, R1CSError> {
        let multiplier_assignment = assignment.map(|value| {
            let scalar = Scalar::from(u64::from(value));
            (scalar, scalar - Scalar::ONE)
        });
        let (left, right, output) = cs.allocate_multiplier(multiplier_assignment)?;
        cs.constrain(right - left + Scalar::ONE);
        cs.constrain(output.into());

        Ok(Self {
            linear_combination: left.into(),
            assignment,
        })
    }

    /// Constrains an existing variable to be Boolean.
    pub fn from_variable<CS: ConstraintSystem>(
        cs: &mut CS,
        variable: Variable,
        assignment: Option<bool>,
    ) -> Self {
        Self::from_linear_combination(cs, variable.into(), assignment)
    }

    /// Constrains an existing linear combination to be Boolean.
    pub fn from_linear_combination<CS: ConstraintSystem>(
        cs: &mut CS,
        linear_combination: LinearCombination,
        assignment: Option<bool>,
    ) -> Self {
        let (_, _, product) = cs.multiply(
            linear_combination.clone(),
            linear_combination.clone() - Scalar::ONE,
        );
        cs.constrain(product.into());
        Self {
            linear_combination,
            assignment,
        }
    }

    /// Returns the optional prover assignment.
    #[must_use]
    pub const fn assignment(&self) -> Option<bool> {
        self.assignment
    }

    /// Returns this bit as an R1CS linear combination.
    #[must_use]
    pub fn linear_combination(&self) -> LinearCombination {
        self.linear_combination.clone()
    }

    /// Enforces equality with another Boolean value.
    pub fn constrain_equal<CS: ConstraintSystem>(&self, cs: &mut CS, other: &Self) {
        cs.constrain(self.linear_combination() - other.linear_combination());
    }

    /// Computes `!self` without allocating a multiplier.
    pub fn not(&self) -> Self {
        Self {
            linear_combination: LinearCombination::from(Scalar::ONE) - self.linear_combination(),
            assignment: self.assignment.map(|value| !value),
        }
    }

    /// Computes `self & other` with one multiplication gate.
    pub fn and<CS: ConstraintSystem>(&self, cs: &mut CS, other: &Self) -> Self {
        let (_, _, product) = cs.multiply(self.linear_combination(), other.linear_combination());
        Self::derived(
            product.into(),
            zip_assignments(self.assignment, other.assignment).map(|(left, right)| left & right),
        )
    }

    /// Computes `self | other` with one multiplication gate.
    pub fn or<CS: ConstraintSystem>(&self, cs: &mut CS, other: &Self) -> Self {
        let (_, _, product) = cs.multiply(self.linear_combination(), other.linear_combination());
        Self::derived(
            self.linear_combination() + other.linear_combination() - product,
            zip_assignments(self.assignment, other.assignment).map(|(left, right)| left | right),
        )
    }

    /// Computes `self ^ other` with one multiplication gate.
    pub fn xor<CS: ConstraintSystem>(&self, cs: &mut CS, other: &Self) -> Self {
        let (_, _, product) = cs.multiply(self.linear_combination(), other.linear_combination());
        Self::derived(
            self.linear_combination() + other.linear_combination() - product * Scalar::from(2_u64),
            zip_assignments(self.assignment, other.assignment).map(|(left, right)| left ^ right),
        )
    }

    /// Computes the parity of three bits with two multiplication gates.
    pub fn xor3<CS: ConstraintSystem>(&self, cs: &mut CS, b: &Self, c: &Self) -> Self {
        self.xor(cs, b).xor(cs, c)
    }

    /// Selects `when_true` when `self` is one and `when_false` otherwise.
    ///
    /// This enforces `when_false + self * (when_true - when_false)` with one
    /// multiplication gate.
    pub fn select<CS: ConstraintSystem>(
        &self,
        cs: &mut CS,
        when_true: &Self,
        when_false: &Self,
    ) -> Self {
        let delta = when_true.linear_combination() - when_false.linear_combination();
        let (_, _, selected_delta) = cs.multiply(self.linear_combination(), delta);
        let assignment = match (self.assignment, when_true.assignment, when_false.assignment) {
            (Some(selector), Some(true_value), Some(false_value)) => {
                Some(if selector { true_value } else { false_value })
            }
            _ => None,
        };
        Self::derived(when_false.linear_combination() + selected_delta, assignment)
    }

    /// Computes the SHA-256 choice function `self ? when_true : when_false`.
    pub fn choice<CS: ConstraintSystem>(
        &self,
        cs: &mut CS,
        when_true: &Self,
        when_false: &Self,
    ) -> Self {
        self.select(cs, when_true, when_false)
    }

    /// Computes the majority value of three bits with two multipliers.
    pub fn majority<CS: ConstraintSystem>(&self, cs: &mut CS, b: &Self, c: &Self) -> Self {
        // If self == b, the majority is self.  Otherwise it is c.
        let different = self.xor(cs, b);
        different.select(cs, c, self)
    }

    /// Creates a bit derived from already-constrained Boolean inputs.
    fn derived(linear_combination: LinearCombination, assignment: Option<bool>) -> Self {
        Self {
            linear_combination,
            assignment,
        }
    }
}

fn zip_assignments(left: Option<bool>, right: Option<bool>) -> Option<(bool, bool)> {
    match (left, right) {
        (Some(left), Some(right)) => Some((left, right)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use bp52_group::ProtocolGenerators;
    use bp52_proof_backend::{BackendParameters, ConstraintSystem, Prover, Transcript};

    use super::Bit;

    #[test]
    fn boolean_primitives_have_expected_assignments_and_shape()
    -> Result<(), Box<dyn std::error::Error>> {
        let generators = ProtocolGenerators::derive()?;
        let parameters = BackendParameters::new(16, &generators)?;
        let mut prover = Prover::new(
            parameters.pedersen(),
            Transcript::new(b"BP52/boolean-shape-test/v1"),
        );

        let zero = Bit::allocate(&mut prover, Some(false))?;
        let one = Bit::allocate(&mut prover, Some(true))?;
        assert_eq!(format!("{one:?}"), "Bit([REDACTED])");
        assert_eq!(zero.not().assignment(), Some(true));
        assert_eq!(one.and(&mut prover, &zero).assignment(), Some(false));
        assert_eq!(one.or(&mut prover, &zero).assignment(), Some(true));
        assert_eq!(one.xor(&mut prover, &zero).assignment(), Some(true));
        assert_eq!(one.xor3(&mut prover, &one, &one).assignment(), Some(true));
        assert_eq!(
            one.choice(&mut prover, &zero, &one).assignment(),
            Some(false)
        );
        assert_eq!(
            one.majority(&mut prover, &zero, &one).assignment(),
            Some(true)
        );

        let metrics = prover.metrics();
        assert_eq!(metrics.multipliers, 10);
        assert_eq!(metrics.constraints, 20);
        Ok(())
    }
}
