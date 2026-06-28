using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace PBIRS.SecurityExtension.Auth
{
    /// <summary>
    /// Default authorization service that implements IAuthorizationExtension.
    /// It maps incoming role claims into canonical PBIRS roles using a configurable mapping dictionary
    /// and simple substring/contains fallback rules.
    /// </summary>
    public class AuthorizationService : IAuthorizationExtension
    {
        private readonly IDictionary<string, string> _mapping;

        /// <summary>
        /// Create a new instance with optional custom mapping.
        /// The mapping dictionary keys are provider role names (case-insensitive) and values are canonical PBIRS role names.
        /// </summary>
        public AuthorizationService(IDictionary<string, string>? mapping = null)
        {
            // default mapping: common role names -> canonical PBIRS roles
            _mapping = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "admin", RoleConstants.SystemAdministrator },
                { "administrator", RoleConstants.SystemAdministrator },
                { "system_admin", RoleConstants.SystemAdministrator },

                { "content_manager", RoleConstants.ContentManager },
                { "content-manager", RoleConstants.ContentManager },
                { "contentmanager", RoleConstants.ContentManager },
                { "editor", RoleConstants.ContentManager },

                { "browser", RoleConstants.Browser },
                { "view", RoleConstants.Browser },
                { "viewer", RoleConstants.Browser },

                { "publisher", RoleConstants.Publisher },
                { "publish", RoleConstants.Publisher },

                { "my-reports", RoleConstants.MyReports },
                { "my_reports", RoleConstants.MyReports },
                { "myreports", RoleConstants.MyReports }
            };

            if (mapping != null)
            {
                foreach (var kv in mapping)
                    _mapping[kv.Key] = kv.Value;
            }
        }

        /// <summary>
        /// Map the principal's roles/claims into canonical PBIRS roles.
        /// </summary>
        public IEnumerable<string> MapRoles(ClaimsPrincipal principal)
        {
            if (principal == null) return Array.Empty<string>();

            // Gather role-like claims emitted earlier by RoleMapper and others.
            var roleClaims = principal.Claims.Where(c => c.Type == ClaimTypes.Role || c.Type.Equals("role", StringComparison.OrdinalIgnoreCase) || c.Type.Equals("roles", StringComparison.OrdinalIgnoreCase))
                                            .Select(c => c.Value)
                                            .Where(v => !string.IsNullOrEmpty(v))
                                            .ToList();

            var mapped = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var r in roleClaims)
            {
                // first exact mapping
                if (_mapping.TryGetValue(r, out var canonical))
                {
                    mapped.Add(canonical);
                    continue;
                }

                // try split on common delimiters (space, comma)
                var parts = r.Split(new[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var p in parts)
                {
                    if (_mapping.TryGetValue(p, out var c2)) mapped.Add(c2);
                }

                // fuzzy contains checks
                var lowered = r.ToLowerInvariant();
                if (lowered.Contains("admin")) mapped.Add(RoleConstants.SystemAdministrator);
                if (lowered.Contains("editor") || lowered.Contains("content")) mapped.Add(RoleConstants.ContentManager);
                if (lowered.Contains("view") || lowered.Contains("browse") || lowered.Contains("reader")) mapped.Add(RoleConstants.Browser);
                if (lowered.Contains("publish")) mapped.Add(RoleConstants.Publisher);
                if (lowered.Contains("report")) mapped.Add(RoleConstants.MyReports);
            }

            return mapped.ToArray();
        }

        /// <summary>
        /// True if the principal has the specified canonical role.
        /// </summary>
        public bool IsInRole(ClaimsPrincipal principal, string role)
        {
            if (principal == null) return false;
            if (string.IsNullOrEmpty(role)) return false;

            var mapped = MapRoles(principal);
            return mapped.Any(r => string.Equals(r, role, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Authorize principal if any of the required roles are present.
        /// </summary>
        public bool Authorize(ClaimsPrincipal principal, params string[] requiredRoles)
        {
            if (principal == null) return false;
            if (requiredRoles == null || requiredRoles.Length == 0) return true; // nothing required => allow

            var mapped = MapRoles(principal).ToList();
            foreach (var req in requiredRoles)
            {
                if (mapped.Any(r => string.Equals(r, req, StringComparison.OrdinalIgnoreCase))) return true;
            }

            return false;
        }
    }
}
