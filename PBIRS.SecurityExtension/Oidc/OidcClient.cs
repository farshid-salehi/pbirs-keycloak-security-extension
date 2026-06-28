using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Newtonsoft.Json;

namespace PBIRS.SecurityExtension.Oidc
{
    public class OidcOptions
    {
        public string Authority { get; set; } = null!; // e.g. https://auth.example.com
        public string ClientId { get; set; } = null!;
        public string? ClientSecret { get; set; }
        public string RedirectUri { get; set; } = null!;
        public string Scope { get; set; } = "openid profile email";
        public string ResponseType { get; set; } = "code";
        public bool RequirePkce { get; set; } = true;
        public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(5);
    }

    public class OidcClient : IDisposable
    {
        private readonly OidcOptions _options;
        private readonly HttpClient _http;
        private readonly IConfigurationManager<OpenIdConnectConfiguration> _configManager;
        private OpenIdConnectConfiguration? _config;

        public OidcClient(OidcOptions options, HttpClient? httpClient = null)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _http = httpClient ?? new HttpClient();

            var wellKnown = new ConfigurationManager<OpenIdConnectConfiguration>(
                _options.Authority.TrimEnd('/') + "/.well-known/openid-configuration",
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever(_http) { RequireHttps = _options.Authority.StartsWith("https://", StringComparison.OrdinalIgnoreCase) }
            );

            _configManager = wellKnown;
        }

        private async Task<OpenIdConnectConfiguration> GetConfigurationAsync()
        {
            if (_config is null)
            {
                _config = await _configManager.GetConfigurationAsync(default).ConfigureAwait(false);
            }
            return _config;
        }

        public async Task<string> CreateAuthorizationRequestUrlAsync(string redirectUri, string? state = null, string? nonce = null)
        {
            var cfg = await GetConfigurationAsync().ConfigureAwait(false);
            state ??= StateUtil.CreateState();
            nonce ??= StateUtil.CreateNonce();

            string codeVerifier = PkceUtil.GenerateCodeVerifier();
            string codeChallenge = PkceUtil.GenerateCodeChallenge(codeVerifier);

            // We return a tuple-like string that includes the url|code_verifier so callers can later redeem.
            var sb = new StringBuilder();
            var uri = new UriBuilder(cfg.AuthorizationEndpoint);
            var q = new List<string>
            {
                "response_type=" + Uri.EscapeDataString(_options.ResponseType),
                "client_id=" + Uri.EscapeDataString(_options.ClientId),
                "scope=" + Uri.EscapeDataString(_options.Scope),
                "redirect_uri=" + Uri.EscapeDataString(redirectUri ?? _options.RedirectUri),
                "state=" + Uri.EscapeDataString(state),
                "nonce=" + Uri.EscapeDataString(nonce)
            };

            if (_options.RequirePkce)
            {
                q.Add("code_challenge=" + Uri.EscapeDataString(codeChallenge));
                q.Add("code_challenge_method=S256");
            }

            uri.Query = string.Join("&", q);
            // return url and code verifier separated by a pipe so callers can persist the verifier server-side or in a cookie.
            return uri.ToString() + "|" + codeVerifier + "|" + state + "|" + nonce;
        }

        public async Task<TokenResponse> RedeemAuthorizationCodeAsync(string code, string codeVerifier, string redirectUri)
        {
            var cfg = await GetConfigurationAsync().ConfigureAwait(false);

            var values = new List<KeyValuePair<string, string>>
            {
                new("grant_type", "authorization_code"),
                new("code", code),
                new("redirect_uri", redirectUri ?? _options.RedirectUri),
                new("client_id", _options.ClientId)
            };

            if (!string.IsNullOrEmpty(_options.ClientSecret))
            {
                values.Add(new KeyValuePair<string, string>("client_secret", _options.ClientSecret));
            }

            if (!string.IsNullOrEmpty(codeVerifier))
            {
                values.Add(new KeyValuePair<string, string>("code_verifier", codeVerifier));
            }

            var req = new HttpRequestMessage(HttpMethod.Post, cfg.TokenEndpoint)
            {
                Content = new FormUrlEncodedContent(values)
            };

            var res = await _http.SendAsync(req).ConfigureAwait(false);
            var body = await res.Content.ReadAsStringAsync().ConfigureAwait(false);
            if (!res.IsSuccessStatusCode)
            {
                throw new InvalidOperationException($"Token endpoint returned {res.StatusCode}: {body}");
            }

            var token = JsonConvert.DeserializeObject<TokenResponse>(body) ?? throw new InvalidOperationException("Unable to deserialize token response");
            token.Raw = body;
            return token;
        }

        public async Task<TokenResponse> RefreshTokenAsync(string refreshToken)
        {
            var cfg = await GetConfigurationAsync().ConfigureAwait(false);
            var values = new List<KeyValuePair<string, string>>
            {
                new("grant_type", "refresh_token"),
                new("refresh_token", refreshToken),
                new("client_id", _options.ClientId)
            };
            if (!string.IsNullOrEmpty(_options.ClientSecret))
                values.Add(new KeyValuePair<string, string>("client_secret", _options.ClientSecret));

            var req = new HttpRequestMessage(HttpMethod.Post, cfg.TokenEndpoint)
            {
                Content = new FormUrlEncodedContent(values)
            };

            var res = await _http.SendAsync(req).ConfigureAwait(false);
            var body = await res.Content.ReadAsStringAsync().ConfigureAwait(false);
            if (!res.IsSuccessStatusCode)
            {
                throw new InvalidOperationException($"Refresh token endpoint returned {res.StatusCode}: {body}");
            }

            var token = JsonConvert.DeserializeObject<TokenResponse>(body) ?? throw new InvalidOperationException("Unable to deserialize refresh token response");
            token.Raw = body;
            return token;
        }

        public async Task<JwtSecurityToken> ValidateIdTokenAsync(string idToken, string expectedNonce)
        {
            var cfg = await GetConfigurationAsync().ConfigureAwait(false);

            var validationParameters = new TokenValidationParameters
            {
                ValidIssuer = cfg.Issuer,
                ValidAudiences = new[] { _options.ClientId },
                IssuerSigningKeys = cfg.SigningKeys,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                RequireSignedTokens = true,
                ClockSkew = _options.ClockSkew
            };

            var handler = new JwtSecurityTokenHandler();
            SecurityToken validated;
            var principal = handler.ValidateToken(idToken, validationParameters, out validated);

            var jwt = validated as JwtSecurityToken ?? throw new SecurityTokenValidationException("ID token is not a JWT");

            // validate nonce
            var claimNonce = principal.FindFirst("nonce")?.Value;
            if (string.IsNullOrEmpty(expectedNonce) || claimNonce != expectedNonce)
            {
                throw new SecurityTokenValidationException("Invalid nonce");
            }

            return jwt;
        }

        public void Dispose()
        {
            _http?.Dispose();
        }
    }

    public static class PkceUtil
    {
        public static string GenerateCodeVerifier(int length = 64)
        {
            var bytes = new byte[length];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            return Base64UrlEncode(bytes);
        }

        public static string GenerateCodeChallenge(string codeVerifier)
        {
            using var sha = SHA256.Create();
            var bytes = Encoding.ASCII.GetBytes(codeVerifier);
            var hash = sha.ComputeHash(bytes);
            return Base64UrlEncode(hash);
        }

        private static string Base64UrlEncode(byte[] input)
        {
            return Convert.ToBase64String(input)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }
    }

    public static class StateUtil
    {
        public static string CreateState(int length = 32)
        {
            var bytes = new byte[length];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        public static string CreateNonce(int length = 32) => CreateState(length);
    }

    public class TokenResponse
    {
        [JsonProperty("access_token")] public string? AccessToken { get; set; }
        [JsonProperty("id_token")] public string? IdToken { get; set; }
        [JsonProperty("refresh_token")] public string? RefreshToken { get; set; }
        [JsonProperty("expires_in")] public int ExpiresIn { get; set; }
        [JsonProperty("token_type")] public string? TokenType { get; set; }

        [JsonIgnore] public string? Raw { get; set; }
    }
}
