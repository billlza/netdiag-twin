use std::collections::BTreeSet;

mod argument;
use argument::{attached_short_option_value, is_flag, is_separated_option_name};

pub(super) fn passthrough_redaction_values(arguments: &[String]) -> Vec<String> {
    let mut values = BTreeSet::new();
    for argument in arguments {
        let trimmed = argument.trim();
        if let Some((flag, value)) = trimmed.split_once('=')
            && (is_separated_option_name(flag) || flag == "--")
        {
            insert_value(&mut values, value);
        } else if let Some(value) = attached_short_option_value(trimmed) {
            insert_value(&mut values, value);
        } else if !is_flag(trimmed) {
            insert_value(&mut values, trimmed);
        }
    }
    values.into_iter().collect()
}

fn insert_value(values: &mut BTreeSet<String>, value: &str) {
    if !value.is_empty() {
        values.insert(value.to_string());
    }
}

#[cfg(test)]
mod tests;
