mod atomic_replace;
mod coordination;
mod identity;
mod known_folder;
mod open;
mod security;

pub use atomic_replace::{move_file_noreplace_write_through, replace_file_write_through};
pub use coordination::{open_private_coordination_file, validate_private_coordination_file};
pub(crate) use identity::{identity_bytes, same_file};
pub use known_folder::{
    CurrentUserLocalAppDataError, WindowsHresultError, current_user_local_app_data_path,
};
pub(crate) use open::{
    open_directory_read_only_no_follow as open_windows_directory_read_only_no_follow,
    open_file_read_only_no_follow as open_windows_file_read_only_no_follow,
};
pub use security::{create_new_private_file, current_user_sid_bytes};
pub(crate) use security::{
    create_private_directory, validate_mutable_parent_security, validate_private_object_security,
};
