using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace PBIRS.SecurityExtension.Auth
{
    public class AuthorizationRequest
    {
        public string Url { get; set; } = string.Empty;
        public string CodeVerifier { get; set; } = string.Empty;
        public string State { get; set; } = string.Empty;
        public string Nonce { get; set; } = string.Empty;
    }

    public class AuthenticationResult
    {
        public bool IsAuthenticated { get; set; }
        public ClaimsPrincipal? Principal { get; set; }
        public AuthenticatedSession? Session { get; set; }
        public IEnumerable<string>? Errors { get; set; }
    }

    public class AuthenticatedSession
    {
        public string AccessToken { get; set; } = string.Empty;
        public string? IdToken { get; set; }
        public string? RefreshToken { get; set; }
        public DateTimeOffset ExpiresAt { get; set; }
        public IEnumerable<Claim> Claims { get; set; } = Array.Empty<Claim>();
    }
}
