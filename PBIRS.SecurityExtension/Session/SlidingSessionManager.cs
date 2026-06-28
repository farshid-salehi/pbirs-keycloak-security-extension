using System;
using Newtonsoft.Json;

namespace PBIRS.SecurityExtension.Session
{
    public class SlidingSessionManager
    {
        private readonly TimeSpan _idleTimeout;
        private readonly TimeSpan _renewWindow;
        private readonly string _purpose;

        public SlidingSessionManager(TimeSpan idleTimeout, TimeSpan renewWindow, string purpose)
        {
            _idleTimeout = idleTimeout;
            _renewWindow = renewWindow;
            _purpose = purpose;
        }

        public string CreateSessionCookie(object sessionPayload)
        {
            var expires = DateTimeOffset.UtcNow.Add(_idleTimeout);
            return PBIRS.SecurityExtension.Cookie.CookieProtection.Protect(sessionPayload, _purpose, expires);
        }

        public (T? Payload, string? RenewedCookie) ValidateSessionCookie<T>(string cookieValue)
        {
            var (payload, expires) = PBIRS.SecurityExtension.Cookie.CookieProtection.Unprotect<T>(cookieValue, _purpose);
            if (payload == null || expires == null)
                return (default, null);

            if (expires <= DateTimeOffset.UtcNow)
                return (default, null);

            var timeLeft = expires.Value - DateTimeOffset.UtcNow;
            if (timeLeft <= _renewWindow)
            {
                // issue a renewed cookie
                var renewed = CreateSessionCookie(payload);
                return (payload, renewed);
            }

            return (payload, null);
        }
    }
}
