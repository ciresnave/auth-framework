//! The comparison helpers decide whether a presented secret equals the stored one, so they must
//! look at every byte they are given, however long the inputs are. A helper that only examines a
//! prefix reports two different long values as equal.
use auth_framework::security::secure_utils::SecureComparison;

/// Every public entry point that compares two secrets, as `(name, str comparison)`.
type StrComparison = fn(&str, &str) -> bool;

fn string_comparisons() -> Vec<(&'static str, StrComparison)> {
    vec![
        (
            "secure_string_compare",
            SecureComparison::secure_string_compare,
        ),
        ("constant_time_eq", SecureComparison::constant_time_eq),
        ("verify_token", SecureComparison::verify_token),
        ("constant_time_eq_bytes", |a, b| {
            SecureComparison::constant_time_eq_bytes(a.as_bytes(), b.as_bytes())
        }),
    ]
}

/// Lengths around the old fixed-size cap, and far past it.
const LENGTHS: [usize; 6] = [1, 1_023, 1_024, 1_025, 4_096, 70_000];

#[test]
fn equal_inputs_of_any_length_compare_equal() {
    for (name, compare) in string_comparisons() {
        for length in LENGTHS {
            let a = "a".repeat(length);
            assert!(
                compare(&a, &a.clone()),
                "{name}: equal {length}-byte inputs differ"
            );
        }
        assert!(compare("", ""), "{name}: empty inputs must compare equal");
    }
}

#[test]
fn a_difference_at_any_position_is_detected() {
    for (name, compare) in string_comparisons() {
        for length in LENGTHS {
            let base = "a".repeat(length);
            let mut positions = vec![0, length / 2, length - 1];
            // The first byte past the old cap, and the byte just before it.
            positions.extend([1_023usize, 1_024].into_iter().filter(|p| *p < length));
            for position in positions {
                let mut other = base.clone().into_bytes();
                other[position] = b'b';
                let other = String::from_utf8(other).unwrap();
                assert!(
                    !compare(&base, &other),
                    "{name}: {length}-byte inputs differing only at byte {position} compared equal"
                );
            }
        }
    }
}

#[test]
fn inputs_of_different_lengths_never_compare_equal() {
    for (name, compare) in string_comparisons() {
        assert!(!compare("short", "longer"), "{name}");
        assert!(!compare("", "x"), "{name}");
        let long = "a".repeat(5_000);
        assert!(
            !compare(&long, &long[..4_999]),
            "{name}: a strict prefix compared equal"
        );
        assert!(
            !compare(&long[..4_999], &long),
            "{name}: a strict prefix compared equal"
        );
    }
}
