using System.Security.Claims;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace PBIRS.SecurityExtension.Auth
{
    /// <summary>
    /// Authorization extension API for PBIRS hosts.
    /// Responsible for mapping incoming principal claims/roles into the application's canonical role names
    /// and performing simple authorization checks.
    /// </summary>
    public interface IAuthorizationExtension
    {
        /// <summary>
        /// Map the principal's claims/roles into the set of canonical PBIRS role names.
        /// </summary>
        IEnumerable<string> MapRoles(ClaimsPrincipal principal);

        /// <summary>
        /// Returns true if the principal has the specified canonical role.
        /// </summary>
        bool IsInRole(ClaimsPrincipal principal, string role);

        /// <summary>
        /// Authorize the principal for the required roles (any match grants access).
        /// </summary>
        bool Authorize(ClaimsPrincipal principal, params string[] requiredRoles);
    }
}
