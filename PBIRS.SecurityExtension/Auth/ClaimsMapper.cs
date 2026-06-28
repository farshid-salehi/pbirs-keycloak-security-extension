using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;

namespace PBIRS.SecurityExtension.Auth
{
    /// <summary>
    /// Maps claims from an ID token (JWT) to application claims. Keep this simple and override/extend in your app.
    /// </summary>
    public class ClaimsMapper
    {
        /// <summary>
        /// Map claims from the Id token JWT into a set of Claims for the application principal.
        /// Common mappings: sub -> NameIdentifier, preferred_username or email -> Name, given_name/family_name.
        /// </summary>
        public virtual IEnumerable<Claim> Map(JwtSecurityToken idToken)
        {
            var claims = new List<Claim>();

            var sub = idToken.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
            if (!string.IsNullOrEmpty(sub)) claims.Add(new Claim(ClaimTypes.NameIdentifier, sub));

            var preferred = idToken.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value
                            ?? idToken.Claims.FirstOrDefault(c => c.Type == "upn")?.Value
                            ?? idToken.Claims.FirstOrDefault(c => c.Type == "email")?.Value;
            if (!string.IsNullOrEmpty(preferred)) claims.Add(new Claim(ClaimTypes.Name, preferred));

            var given = idToken.Claims.FirstOrDefault(c => c.Type == "given_name")?.Value;
            var family = idToken.Claims.FirstOrDefault(c => c.Type == "family_name")?.Value;
            if (!string.IsNullOrEmpty(given)) claims.Add(new Claim(ClaimTypes.GivenName, given));
            if (!string.IsNullOrEmpty(family)) claims.Add(new Claim(ClaimTypes.Surname, family));

            // copy other standard claims
            var email = idToken.Claims.FirstOrDefault(c => c.Type == "email")?.Value;
            if (!string.IsNullOrEmpty(email)) claims.Add(new Claim(ClaimTypes.Email, email));

            // include raw claims that may be useful
            claims.AddRange(idToken.Claims.Where(c => c.Type != "exp" && c.Type != "nbf" && c.Type != "iat"));

            return claims.Distinct(new ClaimEqualityComparer()).ToList();
        }

        private class ClaimEqualityComparer : IEqualityComparer<Claim>
        {
            public bool Equals(Claim? x, Claim? y)
            {
                if (x == null || y == null) return false;
                return x.Type == y.Type && x.Value == y.Value;
            }

            public int GetHashCode(Claim obj) => (obj.Type + "|" + obj.Value).GetHashCode();
        }
    }
}
