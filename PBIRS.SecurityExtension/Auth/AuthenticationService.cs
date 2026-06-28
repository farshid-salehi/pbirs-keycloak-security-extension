using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using PBIRS.SecurityExtension.Oidc;
using System.IdentityModel.Tokens.Jwt;

namespace PBIRS.SecurityExtension.Auth
{
    /// <summary>
    /// AuthenticationService orchestrates the OIDC client, cookie manager, claim/role mapping and principal creation.
    /// It is intentionally host-agnostic: the host must provide an ICookieStore implementation that maps to the host's cookie system.
    /// </summary>
    public class AuthenticationService : IAuthenticationExtension2
    {
        private readonly OidcClient _oidcClient;
        private readonly CookieManager _cookieManager;
        private readonly ClaimsMapper _claimsMapper;
        private readonly RoleMapper _roleMapper;
        private readonly PrincipalFactory _principalFactory;

        public AuthenticationService(OidcClient oidcClient, CookieManager cookieManager, ClaimsMapper claimsMapper, RoleMapper roleMapper, PrincipalFactory principalFactory)
        {
            _oidcClient = oidcClient ?? throw new ArgumentNullException(nameof(oidcClient));
            _cookieManager = cookieManager ?? throw new ArgumentNullException(nameof(cookieManager));
            _claimsMapper = claimsMapper ?? new ClaimsMapper();
            _roleMapper = roleMapper ?? new RoleMapper();
            _principalFactory = principalFactory ?? new PrincipalFactory();
        }

        public async Task<AuthorizationRequest> CreateSignInRequestAsync(string redirectUri)
        {
            var combo = await _oidcClient.CreateAuthorizationRequestUrlAsync(redirectUri).ConfigureAwait(false);
            // returned form is url|code_verifier|state|nonce
            var parts = combo.Split('|');
            if (parts.Length < 4) throw new InvalidOperationException("Unexpected authorization request format from OidcClient");
            return new AuthorizationRequest { Url = parts[0], CodeVerifier = parts[1], State = parts[2], Nonce = parts[3] };
        }

        public async Task<AuthenticationResult> HandleSignInCallbackAsync(string code, string codeVerifier, string state, string nonce, string redirectUri, ICookieStore cookieStore, string cookieName)
        {
            // redeem code
            var token = await _oidcClient.RedeemAuthorizationCodeAsync(code, codeVerifier, redirectUri).ConfigureAwait(false);

            if (token == null || string.IsNullOrEmpty(token.IdToken))
            {
                return new AuthenticationResult { IsAuthenticated = false, Errors = new[] { "Missing id_token in token response" } };
            }

            // validate id token
            var jwt = await _oidcClient.ValidateIdTokenAsync(token.IdToken!, nonce).ConfigureAwait(false);

            // map claims and roles
            var mapped = _claimsMapper.Map(jwt).ToList();
            var roles = _roleMapper.MapRoles(mapped).ToList();

            // build principal
            var principal = _principalFactory.CreatePrincipal(mapped, roles);

            // session payload
            var session = new AuthenticatedSession
            {
                AccessToken = token.AccessToken ?? string.Empty,
                IdToken = token.IdToken,
                RefreshToken = token.RefreshToken,
                ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(token.ExpiresIn),
                Claims = mapped
            };

            // issue cookie
            _cookieManager.IssueSessionCookie(cookieStore, session);

            return new AuthenticationResult { IsAuthenticated = true, Principal = principal, Session = session };
        }

        public Task<AuthenticationResult> ValidateSessionAsync(ICookieStore cookieStore, string cookieName)
        {
            var (payload, renewed) = _cookieManager.GetSessionPayload<AuthenticatedSession>(cookieStore);
            if (payload == null)
            {
                return Task.FromResult(new AuthenticationResult { IsAuthenticated = false });
            }

            // check expiry
            if (payload.ExpiresAt <= DateTimeOffset.UtcNow)
            {
                _cookieManager.ClearSession(cookieStore);
                return Task.FromResult(new AuthenticationResult { IsAuthenticated = false });
            }

            // rebuild principal from stored claims
            var principal = _principalFactory.CreatePrincipal(payload.Claims, _roleMapper.MapRoles(payload.Claims));

            return Task.FromResult(new AuthenticationResult { IsAuthenticated = true, Principal = principal, Session = payload });
        }

        public Task SignOutAsync(ICookieStore cookieStore, string cookieName)
        {
            _cookieManager.ClearSession(cookieStore);
            return Task.CompletedTask;
        }
    }
}
