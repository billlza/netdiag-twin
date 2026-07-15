use super::super::repo_root;
use crate::error::{NetdiagError, Result};
use crate::python_runtime::{TrustedPythonRuntime, resolve_trusted_python_runtime};
use crate::storage::{PathStatus, path_status};
use std::path::Path;

pub(super) fn schema_python_runtime() -> Result<TrustedPythonRuntime> {
    resolve_schema_python_runtime(&repo_root().join(".venv-jsonschema/bin/python"))
}

fn resolve_schema_python_runtime(interpreter: &Path) -> Result<TrustedPythonRuntime> {
    if path_status(interpreter)? != PathStatus::RegularFile {
        return Err(NetdiagError::Connector(format!(
            "schema validation requires a trusted regular-file Python virtual environment at {}; recreate it with `python3 -m venv --clear --copies .venv-jsonschema` and install requirements-jsonschema.lock with --require-hashes and --only-binary=:all:",
            interpreter.display()
        )));
    }
    resolve_trusted_python_runtime(interpreter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_python_requires_an_explicit_regular_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let missing = temp.path().join("missing-python");

        let error = resolve_schema_python_runtime(&missing)
            .expect_err("a missing schema interpreter must fail closed");

        assert!(error.to_string().contains("trusted regular-file Python"));
        assert!(error.to_string().contains("venv --clear --copies"));
    }

    #[cfg(unix)]
    #[test]
    fn schema_python_rejects_a_virtual_environment_symlink() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("python-copy");
        let linked = temp.path().join("python");
        std::fs::write(&target, b"not executed").expect("write target");
        symlink(&target, &linked).expect("create interpreter symlink");

        let error = resolve_schema_python_runtime(&linked)
            .expect_err("a symlinked schema interpreter must fail closed");

        assert!(error.to_string().contains("trusted regular-file Python"));
    }
}
