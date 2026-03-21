#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PamHookType {
    /// Called by PAM during authentication (for example when sshd checks credentials).
    Authenticate,
    /// Called after authentication to establish, refresh, or delete credentials.
    Setcred,
    /// Called for account policy checks (expiration, access restrictions, time limits).
    AcctMgmt,
    /// Called when a new session is opened (for sshd, after login succeeds).
    OpenSession,
    /// Called when a session is closed (for sshd, on logout).
    CloseSession,
    /// Called to change the user's authentication token (for example, when changing passwords).
    Chauthtok,
}

impl std::str::FromStr for PamHookType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pam_sm_authenticate" => Ok(Self::Authenticate),
            "pam_sm_setcred" => Ok(Self::Setcred),
            "pam_sm_acct_mgmt" => Ok(Self::AcctMgmt),
            "pam_sm_open_session" => Ok(Self::OpenSession),
            "pam_sm_close_session" => Ok(Self::CloseSession),
            "pam_sm_chauthtok" => Ok(Self::Chauthtok),
            _ => Err(()),
        }
    }
}

impl PamHookType {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Authenticate => "pam_sm_authenticate",
            Self::Setcred => "pam_sm_setcred",
            Self::AcctMgmt => "pam_sm_acct_mgmt",
            Self::OpenSession => "pam_sm_open_session",
            Self::CloseSession => "pam_sm_close_session",
            Self::Chauthtok => "pam_sm_chauthtok",
        }
    }
}

impl std::fmt::Display for PamHookType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_str().fmt(f)
    }
}

/// Macro to create PAM hooks with a consistent pattern
#[macro_export] // macro export path is at the root of the crate (`crate::create_hook!`)`)
macro_rules! create_hook {
    ($target:ident) => {
        /// Called by PAM during authentication (for example when sshd checks credentials).
        ///
        /// # Safety
        /// This function is called by PAM with pointers to C data. Inherently unsafe
        #[unsafe(no_mangle)]
        #[allow(clippy::similar_names)]
        pub unsafe extern "C" fn $target(
            pamh: *mut PamHandle,
            flags: c_int,
            argc: c_int,
            argv: *const *const c_char,
        ) -> c_int {
            let handler = unsafe { MultiHandler::from_c_args(argc, argv) };
            if pamh.is_null() {
                PamReturnCode::Service_Err as c_int
            } else {
                // Safety: We checked pamh for null above
                // and PAM guarantees that the pointer will be valid for the duration of the call
                // Also, we won't actually do any mutations, we'll only use it to *read* PAM items
                let pam_h = unsafe { &mut *pamh };
                if let Ok(hook_type) = stringify!($target).parse() {
                    handler.handle_hook(hook_type, pam_h, flags) as c_int
                } else {
                    PamReturnCode::Service_Err as c_int
                }
            }
        }
    };
}
