using System;
using System.Text;
using Newtonsoft.Json;
using System.Security.Cryptography;

namespace PBIRS.SecurityExtension.Cookie
{
    /// <summary>
    /// Simple cookie protection using DPAPI (ProtectedData). Not suitable for distributed multi-machine deployments.
    /// For production, replace with a shared data-protection key ring or an encryption service.
    /// </summary>
    public static class CookieProtection
    {
        public static string Protect<T>(T payload, string purpose, DateTimeOffset expires)
        {
            var wrapper = new CookieEnvelope<T>
            {
                Payload = payload,
                Expires = expires
            };

            var json = JsonConvert.SerializeObject(wrapper);
            var bytes = Encoding.UTF8.GetBytes(json);
            var entropy = Encoding.UTF8.GetBytes(purpose ?? string.Empty);
            var protectedBytes = ProtectedData.Protect(bytes, entropy, DataProtectionScope.CurrentUser);
            return Convert.ToBase64String(protectedBytes);
        }

        public static (T? payload, DateTimeOffset? expires) Unprotect<T>(string protectedValue, string purpose)
        {
            try
            {
                var protectedBytes = Convert.FromBase64String(protectedValue);
                var entropy = Encoding.UTF8.GetBytes(purpose ?? string.Empty);
                var bytes = ProtectedData.Unprotect(protectedBytes, entropy, DataProtectionScope.CurrentUser);
                var json = Encoding.UTF8.GetString(bytes);
                var wrapper = JsonConvert.DeserializeObject<CookieEnvelope<T>>(json);
                return (wrapper?.Payload, wrapper?.Expires);
            }
            catch
            {
                return (default, null);
            }
        }

        private class CookieEnvelope<TT>
        {
            public TT? Payload { get; set; }
            public DateTimeOffset Expires { get; set; }
        }
    }
}
