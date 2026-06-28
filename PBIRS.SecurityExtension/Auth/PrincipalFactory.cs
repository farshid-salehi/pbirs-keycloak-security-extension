using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace PBIRS.SecurityExtension.Auth
{
    /// <summary>
    /// Builds a ClaimsPrincipal from mapped claims and roles.
    /// </summary>
    public class PrincipalFactory
    {
        public virtual ClaimsPrincipal CreatePrincipal(IEnumerable<Claim> claims, IEnumerable<Claim> roles)
        {
            var identity = new ClaimsIdentity(claims.Concat(roles), "PBIRS.OIDC");
            return new ClaimsPrincipal(identity);
        }
    }
}
