//! Executable source-compatibility contract for NetDiag's vendored `argmin` patch.

#[cfg(test)]
mod tests {
    use argmin::bulk;
    use argmin::core::{Error, SendAlias, SyncAlias};
    #[cfg(feature = "rayon")]
    use rayon::prelude::*;

    trait LegacyCost {
        type Param;
        type Output;

        fn cost(&self, param: &Self::Param) -> Result<Self::Output, Error>;

        bulk!(cost, Self::Param, Self::Output);
    }

    struct Doubler;

    impl LegacyCost for Doubler {
        type Param = u64;
        type Output = u64;

        fn cost(&self, param: &Self::Param) -> Result<Self::Output, Error> {
            Ok(param * 2)
        }
    }

    #[test]
    fn three_argument_bulk_macro_keeps_its_public_contract() {
        assert_eq!(Doubler.bulk_cost(&[1_u64, 2, 3]).unwrap(), [2, 4, 6]);
    }
}
