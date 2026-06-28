using System;

namespace PBIRS.SecurityExtension.Auth
{
    /// <summary>
    /// CookieManager composes a SlidingSessionManager and an ICookieStore to persist encrypted session cookies.
    /// The CookieManager itself is web-agnostic: the host app must implement ICookieStore to map to HttpContext cookies.
    /// </summary>
    public class CookieManager
    {
        private readonly SlidingSessionManager _sessionManager;
        private readonly string _cookieName;

        public CookieManager(SlidingSessionManager sessionManager, string cookieName = ".PBIRS.Auth")
        {
            _sessionManager = sessionManager ?? throw new ArgumentNullException(nameof(sessionManager));
            _cookieName = cookieName;
        }

        public void IssueSessionCookie(ICookieStore store, object payload)
        {
            var protectedValue = _sessionManager.CreateSessionCookie(payload);
            // set cookie with expiration equal to idle timeout inside the session manager
            store.Set(_cookieName, protectedValue);
        }

        public (T? Payload, bool Renewed) GetSessionPayload<T>(ICookieStore store)
        {
            var val = store.Get(_cookieName);
            if (string.IsNullOrEmpty(val))
                return (default, false);

            var (payload, renewed) = _sessionManager.ValidateSessionCookie<T>(val);
            if (renewed != null)
            {
                store.Set(_cookieName, renewed);
                return (payload, true);
            }

            return (payload, false);
        }

        public void ClearSession(ICookieStore store)
        {
            store.Delete(_cookieName);
        }
    }
}
