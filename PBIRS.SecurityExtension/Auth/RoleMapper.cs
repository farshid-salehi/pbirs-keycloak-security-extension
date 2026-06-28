using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Newtonsoft.Json.Linq;

namespace PBIRS.SecurityExtension.Auth
{
    /// <summary>
    /// RoleMapper extracts roles from common claim shapes used by OIDC providers (roles, role, realm_access.roles, resource_access.<client>.roles)
    /// and converts them into ClaimTypes.Role claims.
    /// </summary>
    public class RoleMapper
    {
        public virtual IEnumerable<Claim> MapRoles(IEnumerable<Claim> claims)
        {
            var roles = new List<string>();

            // look for generic "roles" or "role"
            var rolesClaims = claims.Where(c => c.Type == "roles" || c.Type == "role").ToList();
            foreach (var rc in rolesClaims)
            {
                // could be space/comma separated or JSON array; try parse as JSON first
                var v = rc.Value;
                if (v.StartsWith("[") || v.StartsWith("{"))
                {
                    try
                    {
                        var token = JToken.Parse(v);
                        if (token.Type == JTokenType.Array)
                        {
                            foreach (var item in token)
                            {
                                var s = item.ToString();
                                if (!string.IsNullOrEmpty(s)) roles.Add(s);
                            }
                        }
                    }
                    catch { /* ignore parse errors */ }
                }
                else
                {
                    // split on common delimiters
                    var parts = v.Split(new[] { ' ', ',' }, System.StringSplitOptions.RemoveEmptyEntries);
                    foreach (var p in parts) roles.Add(p);
                }
            }

            // realm_access: { "roles": ["a","b"] }
            var realm = claims.FirstOrDefault(c => c.Type == "realm_access")?.Value;
            if (!string.IsNullOrEmpty(realm))
            {
                try
                {
                    var token = JToken.Parse(realm);
                    var arr = token["roles"] as JArray;
                    if (arr != null)
                    {
                        foreach (var r in arr) roles.Add(r.ToString());
                    }
                }
                catch { }
            }

            // resource_access: { "client-id": { "roles": [..] }, ... }
            var resource = claims.FirstOrDefault(c => c.Type == "resource_access")?.Value;
            if (!string.IsNullOrEmpty(resource))
            {
                try
                {
                    var token = JToken.Parse(resource);
                    foreach (var child in token.Children())
                    {
                        var rolesArr = child.SelectToken("roles") as JArray;
                        if (rolesArr != null)
                        {
                            foreach (var r in rolesArr) roles.Add(r.ToString());
                        }
                    }
                }
                catch { }
            }

            return roles.Distinct().Select(r => new Claim(ClaimTypes.Role, r));
        }
    }
}
