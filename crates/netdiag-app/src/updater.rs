use reqwest::Url;
use reqwest::redirect::Policy;
use std::time::Duration;

#[cfg(target_os = "macos")]
const MAX_UPDATE_FEED_URL_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateCheckOutcome {
    NativeDialogOpened,
    FeedReachable,
}

pub fn sparkle_status() -> String {
    match sparkle_readiness() {
        Ok(status) => status,
        Err(err) => err,
    }
}

#[cfg(target_os = "macos")]
pub fn sparkle_readiness() -> Result<String, String> {
    let app_dir = app_bundle_dir().ok_or_else(|| "Sparkle requires a bundled .app".to_string())?;
    validate_sparkle_framework(&app_dir)?;
    sparkle_feed_url()?;
    Ok("Sparkle native updater ready".to_string())
}

#[cfg(not(target_os = "macos"))]
pub fn sparkle_readiness() -> Result<String, String> {
    Err("Sparkle updater is only available on macOS".to_string())
}

pub fn sparkle_check_for_updates() -> Result<UpdateCheckOutcome, String> {
    #[cfg(target_os = "macos")]
    {
        match sparkle_check_for_updates_native() {
            Ok(()) => Ok(UpdateCheckOutcome::NativeDialogOpened),
            Err(native_err) => {
                let feed_url = sparkle_feed_url()?;
                match update_feed_reachable(&feed_url) {
                    Ok(()) => Err(format!(
                        "{native_err}; update feed is reachable, but the native Sparkle dialog could not be opened"
                    )),
                    Err(feed_err) => Err(format!("{native_err}; {feed_err}")),
                }
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let feed_url = default_feed_url()?;
        update_feed_reachable(&feed_url)?;
        Ok(UpdateCheckOutcome::FeedReachable)
    }
}

fn update_feed_reachable(feed_url: &Url) -> Result<(), String> {
    let response = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .connect_timeout(Duration::from_secs(3))
        .redirect(Policy::none())
        .no_proxy()
        .build()
        .map_err(|_| "failed to create update client".to_string())?
        .get(feed_url.clone())
        .send()
        .map_err(|error| {
            let reason = if error.is_timeout() {
                "timed out"
            } else if error.is_connect() {
                "connection failed"
            } else if error.is_request() {
                "request construction failed"
            } else {
                "transport failed"
            };
            format!("failed to reach update feed: {reason}")
        })?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!(
            "update feed returned HTTP status {}",
            response.status().as_u16()
        ))
    }
}

#[cfg(not(target_os = "macos"))]
fn default_feed_url() -> Result<Url, String> {
    validate_feed_url("https://billlza.github.io/netdiag-twin/appcast.xml")
}

fn validate_feed_url(value: &str) -> Result<Url, String> {
    if value.trim() != value {
        return Err("update feed URL contains surrounding whitespace".to_string());
    }
    netdiag_core::connectors::validate_http_connector_endpoint(value)
        .map_err(|error| format!("update feed URL {error}"))?;
    let url = Url::parse(value).map_err(|_| "update feed URL is invalid".to_string())?;
    if url.scheme() != "https" {
        return Err("update feed URL must use HTTPS".to_string());
    }
    Ok(url)
}

#[cfg(target_os = "macos")]
mod macos {
    use super::{MAX_UPDATE_FEED_URL_BYTES, Url, validate_feed_url};
    use objc2::msg_send;
    use objc2::runtime::{AnyClass, AnyObject};
    use objc2_foundation::{NSBundle, NSString};
    use std::ffi::{CStr, CString};
    use std::os::raw::{c_char, c_int, c_void};
    use std::path::{Path, PathBuf};
    use std::sync::OnceLock;

    const RTLD_NOW: c_int = 0x2;
    const RTLD_GLOBAL: c_int = 0x8;

    static SPARKLE_CONTROLLER: OnceLock<usize> = OnceLock::new();
    static SPARKLE_DLOPEN: OnceLock<usize> = OnceLock::new();

    unsafe extern "C" {
        fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
        fn dlerror() -> *const c_char;
    }

    pub fn app_bundle_dir() -> Option<PathBuf> {
        std::env::current_exe().ok().and_then(|path| {
            path.ancestors()
                .find(|ancestor| {
                    ancestor
                        .extension()
                        .and_then(|extension| extension.to_str())
                        .is_some_and(|extension| extension.eq_ignore_ascii_case("app"))
                })
                .map(Path::to_path_buf)
        })
    }

    pub fn sparkle_framework_dir(app_dir: &Path) -> PathBuf {
        app_dir.join("Contents/Frameworks/Sparkle.framework")
    }

    pub fn validate_sparkle_framework(app_dir: &Path) -> Result<PathBuf, String> {
        let canonical_app = std::fs::canonicalize(app_dir)
            .map_err(|_| "failed to resolve the application bundle".to_string())?;
        let canonical_contents = std::fs::canonicalize(app_dir.join("Contents"))
            .map_err(|_| "failed to resolve the application Contents directory".to_string())?;
        require_contained(
            &canonical_contents,
            &canonical_app,
            "application Contents directory escapes the application bundle",
        )?;
        let canonical_frameworks = std::fs::canonicalize(app_dir.join("Contents/Frameworks"))
            .map_err(|_| "failed to resolve the embedded Frameworks directory".to_string())?;
        require_contained(
            &canonical_frameworks,
            &canonical_contents,
            "Frameworks directory escapes the application bundle",
        )?;
        let framework = sparkle_framework_dir(app_dir);
        let canonical_framework = std::fs::canonicalize(&framework)
            .map_err(|_| "Sparkle.framework is not embedded".to_string())?;
        require_contained(
            &canonical_framework,
            &canonical_frameworks,
            "Sparkle.framework escapes the embedded Frameworks directory",
        )?;
        if !std::fs::metadata(&canonical_framework)
            .map_err(|_| "failed to inspect embedded Sparkle.framework".to_string())?
            .is_dir()
        {
            return Err("Sparkle.framework is not an embedded directory".to_string());
        }
        require_real_directory(
            &canonical_framework.join("Versions"),
            "Sparkle framework Versions path is not a real directory",
        )?;
        let version_directory = canonical_framework.join("Versions/B");
        require_real_directory(
            &version_directory,
            "Sparkle framework version B is not a real directory",
        )?;
        let versioned_binary = version_directory.join("Sparkle");
        require_real_file(
            &versioned_binary,
            "Sparkle framework version B binary is not a real regular file",
        )?;
        let canonical_binary = std::fs::canonicalize(&versioned_binary)
            .map_err(|_| "failed to resolve Sparkle framework version B binary".to_string())?;

        let convenience_binary = canonical_framework.join("Sparkle");
        let convenience_metadata = std::fs::symlink_metadata(&convenience_binary)
            .map_err(|_| "Sparkle framework convenience binary is missing".to_string())?;
        if !convenience_metadata.file_type().is_symlink() {
            return Err("Sparkle framework convenience binary is not a symlink".to_string());
        }
        let canonical_convenience = std::fs::canonicalize(&convenience_binary)
            .map_err(|_| "failed to resolve Sparkle framework convenience binary".to_string())?;
        if canonical_convenience != canonical_binary {
            return Err(
                "Sparkle framework convenience binary does not target version B".to_string(),
            );
        }
        Ok(canonical_binary)
    }

    fn require_real_directory(path: &Path, message: &str) -> Result<(), String> {
        let metadata = std::fs::symlink_metadata(path).map_err(|_| message.to_string())?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            Err(message.to_string())
        } else {
            Ok(())
        }
    }

    fn require_real_file(path: &Path, message: &str) -> Result<(), String> {
        let metadata = std::fs::symlink_metadata(path).map_err(|_| message.to_string())?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            Err(message.to_string())
        } else {
            Ok(())
        }
    }

    fn require_contained(path: &Path, root: &Path, message: &str) -> Result<(), String> {
        if path != root && path.starts_with(root) {
            Ok(())
        } else {
            Err(message.to_string())
        }
    }

    pub fn sparkle_check_for_updates_native() -> Result<(), String> {
        let controller = sparkle_controller()?;
        let sender = None::<&AnyObject>;
        // SAFETY: `controller` is an initialized SPUStandardUpdaterController retained for
        // the life of the process, and `checkForUpdates:` is Sparkle's documented main-thread
        // action for presenting the native update UI.
        unsafe {
            let _: () = msg_send![controller, checkForUpdates: sender];
        }
        Ok(())
    }

    fn sparkle_controller() -> Result<&'static AnyObject, String> {
        if let Some(controller) = SPARKLE_CONTROLLER.get() {
            let ptr = *controller as *mut AnyObject;
            // SAFETY: The pointer was created from a retained Objective-C object and leaked
            // intentionally into process lifetime storage.
            return unsafe {
                ptr.as_ref()
                    .ok_or_else(|| "Sparkle updater controller is null".to_string())
            };
        }
        ensure_main_thread()?;
        load_sparkle_framework()?;
        let class = AnyClass::get(c"SPUStandardUpdaterController").ok_or_else(|| {
            "SPUStandardUpdaterController is unavailable after loading Sparkle.framework"
                .to_string()
        })?;
        let none = None::<&AnyObject>;
        // SAFETY: The Sparkle framework has been loaded, `class` is SPUStandardUpdaterController,
        // and nil delegates are accepted by Sparkle for the standard user driver.
        let allocated: *mut AnyObject = unsafe { msg_send![class, alloc] };
        if allocated.is_null() {
            return Err("failed to allocate SPUStandardUpdaterController".to_string());
        }
        // SAFETY: `allocated` is the result of Objective-C `alloc`; this initializer is Sparkle's
        // standard controller initializer for apps that do not need custom delegates.
        let initialized: *mut AnyObject = unsafe {
            msg_send![
                allocated,
                initWithUpdaterDelegate: none,
                userDriverDelegate: none
            ]
        };
        if initialized.is_null() {
            return Err("failed to initialize SPUStandardUpdaterController".to_string());
        }
        let _ = SPARKLE_CONTROLLER.set(initialized as usize);
        // SAFETY: Stored pointer has just been checked non-null.
        unsafe {
            initialized
                .as_ref()
                .ok_or_else(|| "Sparkle updater controller is null".to_string())
        }
    }

    fn ensure_main_thread() -> Result<(), String> {
        let class = AnyClass::get(c"NSThread")
            .ok_or_else(|| "NSThread class is unavailable".to_string())?;
        // SAFETY: `NSThread isMainThread` is a class method returning Objective-C BOOL, which
        // objc2 maps to Rust bool for message sends.
        let is_main_thread: bool = unsafe { msg_send![class, isMainThread] };
        if is_main_thread {
            Ok(())
        } else {
            Err("Sparkle update checks must be started on the macOS main thread".to_string())
        }
    }

    fn load_sparkle_framework() -> Result<(), String> {
        if SPARKLE_DLOPEN.get().is_some() {
            return Ok(());
        }
        let app_dir =
            app_bundle_dir().ok_or_else(|| "Sparkle requires a bundled .app".to_string())?;
        let framework_binary = validate_sparkle_framework(&app_dir)?;
        use std::os::unix::ffi::OsStrExt;
        let framework_path = CString::new(framework_binary.as_os_str().as_bytes())
            .map_err(|_| "Sparkle framework path contains an interior NUL byte".to_string())?;
        // SAFETY: `framework_path` is a valid C string and we keep the loaded image alive for
        // process lifetime by storing the returned handle.
        let handle = unsafe { dlopen(framework_path.as_ptr(), RTLD_NOW | RTLD_GLOBAL) };
        if handle.is_null() {
            return Err(format!(
                "failed to load Sparkle.framework: {}",
                dlerror_string()
            ));
        }
        let _ = SPARKLE_DLOPEN.set(handle as usize);
        Ok(())
    }

    fn dlerror_string() -> String {
        // SAFETY: `dlerror` returns either null or a borrowed NUL-terminated error string.
        let message = unsafe { dlerror() };
        if message.is_null() {
            "unknown dlopen error".to_string()
        } else {
            // SAFETY: Non-null `dlerror` result is documented as a C string.
            unsafe { CStr::from_ptr(message) }
                .to_string_lossy()
                .into_owned()
        }
    }

    pub fn sparkle_feed_url() -> Result<Url, String> {
        let key = NSString::from_str("SUFeedURL");
        let value = NSBundle::mainBundle()
            .objectForInfoDictionaryKey(&key)
            .ok_or_else(|| "the application bundle does not contain SUFeedURL".to_string())?
            .downcast::<NSString>()
            .map_err(|_| "the application bundle SUFeedURL is not text".to_string())?
            .to_string();
        if value.len() > MAX_UPDATE_FEED_URL_BYTES {
            return Err("update feed URL is too long".to_string());
        }
        validate_feed_url(&value)
    }
}

#[cfg(target_os = "macos")]
use macos::{
    app_bundle_dir, sparkle_check_for_updates_native, sparkle_feed_url, validate_sparkle_framework,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    #[cfg(target_os = "macos")]
    use std::sync::atomic::{AtomicU64, Ordering};
    #[cfg(target_os = "macos")]
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(target_os = "macos")]
    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn update_feed_url_requires_clean_https_without_embedded_credentials() {
        assert!(validate_feed_url("https://updates.example.test/appcast.xml").is_ok());
        for value in [
            "http://updates.example.test/appcast.xml",
            " https://updates.example.test/appcast.xml",
            "https://user:secret@updates.example.test/appcast.xml",
            "https://updates.example.test/appcast.xml?token=secret",
        ] {
            let error = validate_feed_url(value).expect_err("unsafe feed URL must fail");
            assert!(!error.contains("secret"));
        }
    }

    #[test]
    fn feed_probe_does_not_follow_redirects_or_echo_the_url() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).expect("request");
            stream
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: https://secret.example.test/next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .expect("response");
        });
        let url = Url::parse(&format!("http://{address}/appcast.xml")).expect("URL");
        let error = update_feed_reachable(&url).expect_err("redirect must fail");
        server.join().expect("server");
        assert!(error.contains("HTTP status 302"));
        assert!(!error.contains(address.to_string().as_str()));
        assert!(!error.contains("secret"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn framework_validation_requires_the_fixed_version_b_binary() {
        use std::os::unix::fs::symlink;

        let root = test_path("sparkle-framework");
        let app = root.join("NetDiag Twin.app");
        let framework = app.join("Contents/Frameworks/Sparkle.framework");
        let version = framework.join("Versions/B");
        std::fs::create_dir_all(&version).expect("framework directories");
        std::fs::write(version.join("Sparkle"), b"framework").expect("framework binary");
        symlink("B", framework.join("Versions/Current")).expect("version symlink");
        symlink("Versions/Current/Sparkle", framework.join("Sparkle")).expect("binary symlink");

        let binary = validate_sparkle_framework(&app).expect("internal symlinks");
        assert!(binary.ends_with("Versions/B/Sparkle"));

        std::fs::remove_file(framework.join("Sparkle")).expect("remove internal symlink");
        let other_version = framework.join("Versions/A");
        std::fs::create_dir_all(&other_version).expect("other version directory");
        std::fs::write(other_version.join("Sparkle"), b"other").expect("other version binary");
        symlink("Versions/A/Sparkle", framework.join("Sparkle")).expect("wrong internal symlink");
        let error = validate_sparkle_framework(&app).expect_err("wrong version must fail");
        assert!(error.contains("does not target version B"));

        std::fs::remove_file(framework.join("Sparkle")).expect("remove wrong symlink");
        let outside = root.join("outside");
        std::fs::write(&outside, b"outside").expect("outside binary");
        symlink(&outside, framework.join("Sparkle")).expect("escaping symlink");
        let error = validate_sparkle_framework(&app).expect_err("escape must fail");
        assert!(error.contains("does not target version B"));

        std::fs::remove_file(framework.join("Sparkle")).expect("remove escaping symlink");
        symlink("Versions/Current/Sparkle", framework.join("Sparkle"))
            .expect("restore convenience symlink");
        std::fs::remove_file(version.join("Sparkle")).expect("remove real binary");
        std::fs::write(version.join("Sparkle.real"), b"framework").expect("alternate binary");
        symlink("Sparkle.real", version.join("Sparkle")).expect("versioned binary symlink");
        let error = validate_sparkle_framework(&app).expect_err("versioned symlink must fail");
        assert!(error.contains("version B binary is not a real regular file"));
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[cfg(target_os = "macos")]
    fn test_path(label: &str) -> std::path::PathBuf {
        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "netdiag-{label}-{}-{nanos}-{id}",
            std::process::id()
        ))
    }
}
