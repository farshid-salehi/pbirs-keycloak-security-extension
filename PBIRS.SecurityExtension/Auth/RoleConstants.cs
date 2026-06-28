namespace PBIRS.SecurityExtension.Auth
{
    /// <summary>
    /// Canonical PBIRS roles used by the authorization extension.
    /// Use these constants when checking permissions in the host application.
    /// </summary>
    public static class RoleConstants
    {
        public const string SystemAdministrator = "System Administrator";
        public const string ContentManager = "Content Manager";
        public const string Browser = "Browser";
        public const string Publisher = "Publisher";
        public const string MyReports = "My Reports";
    }
}
