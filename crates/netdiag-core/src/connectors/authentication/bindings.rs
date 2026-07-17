use super::authentication_error;
use super::identity::{BearerEnvironmentBinding, BearerSourceDeclaration, BearerSourceIdentity};
use super::token::{ValidatedBearerToken, validate_bearer_token};
use crate::error::Result;
use std::collections::{BTreeMap, BTreeSet};
use std::env::VarError;
use std::fmt;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BearerEnvironmentBindings {
    identities: BTreeSet<BearerSourceIdentity>,
}

impl BearerEnvironmentBindings {
    pub fn new(bindings: impl IntoIterator<Item = BearerEnvironmentBinding>) -> Result<Self> {
        let mut identities = BTreeSet::new();
        for binding in bindings {
            if !identities.insert(binding.0) {
                return Err(authentication_error(
                    "bearer environment bindings contain a duplicate identity",
                ));
            }
        }
        Ok(Self { identities })
    }

    pub fn validate_exact_declarations(
        &self,
        declarations: &[BearerSourceDeclaration],
    ) -> Result<()> {
        let declared = declaration_identities(declarations)?;
        if let Some(missing) = declared.difference(&self.identities).next() {
            return Err(authentication_error(format!(
                "bearer declaration is not externally authorized for {}",
                missing.description()
            )));
        }
        if let Some(extra) = self.identities.difference(&declared).next() {
            return Err(authentication_error(format!(
                "bearer environment binding does not match a declaration for {}",
                extra.description()
            )));
        }
        Ok(())
    }

    pub fn resolve_all(
        &self,
        declarations: &[BearerSourceDeclaration],
    ) -> Result<ResolvedBearerTokens> {
        self.resolve_all_with_lookup(declarations, |name| std::env::var(name))
    }

    pub fn resolve_all_with_lookup<F>(
        &self,
        declarations: &[BearerSourceDeclaration],
        mut lookup: F,
    ) -> Result<ResolvedBearerTokens>
    where
        F: FnMut(&str) -> std::result::Result<String, VarError>,
    {
        self.validate_exact_declarations(declarations)?;
        let mut tokens = BTreeMap::new();
        for declaration in declarations {
            let identity = &declaration.0;
            let value = lookup(&identity.environment_variable).map_err(|error| {
                let reason = match error {
                    VarError::NotPresent => "is not set",
                    VarError::NotUnicode(_) => "is not valid Unicode",
                };
                authentication_error(format!(
                    "bearer environment variable {:?} for source {:?} {reason}",
                    identity.environment_variable, identity.source_name
                ))
            })?;
            let token = validate_bearer_token(value)?;
            if tokens.insert(identity.clone(), token).is_some() {
                return Err(authentication_error(
                    "bearer declarations contain a duplicate identity",
                ));
            }
        }
        Ok(ResolvedBearerTokens { tokens })
    }
}

#[derive(Default)]
pub struct ResolvedBearerTokens {
    tokens: BTreeMap<BearerSourceIdentity, ValidatedBearerToken>,
}

impl ResolvedBearerTokens {
    pub fn token_for(
        &self,
        declaration: &BearerSourceDeclaration,
    ) -> Result<&ValidatedBearerToken> {
        self.tokens.get(&declaration.0).ok_or_else(|| {
            authentication_error(format!(
                "bearer token was not resolved for {}",
                declaration.0.description()
            ))
        })
    }

    pub fn into_token_for(
        mut self,
        declaration: &BearerSourceDeclaration,
    ) -> Result<ValidatedBearerToken> {
        self.tokens.remove(&declaration.0).ok_or_else(|| {
            authentication_error(format!(
                "bearer token was not resolved for {}",
                declaration.0.description()
            ))
        })
    }
}

impl fmt::Debug for ResolvedBearerTokens {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedBearerTokens")
            .field("token_count", &self.tokens.len())
            .finish()
    }
}

fn declaration_identities(
    declarations: &[BearerSourceDeclaration],
) -> Result<BTreeSet<BearerSourceIdentity>> {
    let mut identities = BTreeSet::new();
    for declaration in declarations {
        if !identities.insert(declaration.0.clone()) {
            return Err(authentication_error(
                "bearer declarations contain a duplicate identity",
            ));
        }
    }
    Ok(identities)
}
