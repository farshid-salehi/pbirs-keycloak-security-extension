using System.Security.Claims;
using System.Threading.Tasks;

namespace PBIRS.SecurityExtension.Auth
{
    public interface IAuthenticationExtension2
    {
        Task<AuthenticationResult> ValidateSessionAsync(ICookieStore cookieStore, string cookieName);

        Task<AuthenticationResult> HandleSignInCallbackAsync(string code, string codeVerifier, string state, string nonce, string redirectUri, ICookieStore cookieStore, string cookieName);

        Task<AuthorizationRequest> CreateSignInRequestAsync(string redirectUri);

        Task SignOutAsync(ICookieStore cookieStore, string cookieName);
    }
}
