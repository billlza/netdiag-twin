use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateCheckOutcome {
    NativeDialogOpened,
    FeedReachable { feed_url: String },
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
    let framework_dir = sparkle_framework_dir(&app_dir);
    if !framework_dir.exists() {
        return Err("Sparkle.framework is not embedded".to_string());
    }
    let feed_url = sparkle_feed_url().unwrap_or_else(default_feed_url);
    Ok(format!("Sparkle native updater ready · {feed_url}"))
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
                let feed_url = sparkle_feed_url().unwrap_or_else(default_feed_url);
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
        let feed_url = default_feed_url();
        update_feed_reachable(&feed_url)?;
        Ok(UpdateCheckOutcome::FeedReachable { feed_url })
    }
}

fn update_feed_reachable(feed_url: &str) -> Result<(), String> {
    let response = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|err| format!("failed to create update client: {err}"))?
        .get(feed_url)
        .send()
        .map_err(|err| format!("failed to reach update feed: {err}"))?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!(
            "update feed is not reachable: {} ({feed_url})",
            response.status()
        ))
    }
}

fn default_feed_url() -> String {
    "https://billlza.github.io/netdiag-twin/appcast.xml".to_string()
}

#[cfg(target_os = "macos")]
mod macos {
    use objc2::msg_send;
    use objc2::runtime::{AnyClass, AnyObject};
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
        let framework_binary = sparkle_framework_dir(&app_dir).join("Sparkle");
        if !framework_binary.exists() {
            return Err(format!(
                "Sparkle framework binary is missing: {}",
                framework_binary.display()
            ));
        }
        let framework_path = CString::new(framework_binary.to_string_lossy().as_bytes())
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

    pub fn sparkle_feed_url() -> Option<String> {
        let info_plist = app_bundle_dir()?.join("Contents/Info.plist");
        let output = std::process::Command::new("/usr/libexec/PlistBuddy")
            .args(["-c", "Print :SUFeedURL"])
            .arg(info_plist)
            .output()
            .ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
    }
}

#[cfg(target_os = "macos")]
use macos::{
    app_bundle_dir, sparkle_check_for_updates_native, sparkle_feed_url, sparkle_framework_dir,
};

#[cfg(not(target_os = "macos"))]
fn sparkle_feed_url() -> Option<String> {
    None
}
