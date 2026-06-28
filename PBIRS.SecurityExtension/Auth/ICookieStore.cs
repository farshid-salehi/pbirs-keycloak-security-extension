using System;

namespace PBIRS.SecurityExtension.Auth
{
    /// <summary>
    /// Abstract cookie store that adapts to the host environment (ASP.NET, ASP.NET Core, tests, etc.).
    /// Implementations should persist cookie name/value and set appropriate metadata (expires, secure, httpOnly).
    /// </summary>
    public interface ICookieStore
    {
        /// <summary>
        /// Get the cookie value for the given name. Return null if missing.
        /// </summary>
        string? Get(string name);

        /// <summary>
        /// Set the cookie value. Expiration is optional.
        /// </summary>
        void Set(string name, string value, DateTimeOffset? expires = null);

        /// <summary>
        /// Delete the cookie from the store.
        /// </summary>
        void Delete(string name);
    }
}
