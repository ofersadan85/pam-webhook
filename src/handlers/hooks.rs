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
