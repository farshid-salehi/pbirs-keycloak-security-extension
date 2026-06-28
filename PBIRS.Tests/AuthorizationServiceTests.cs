using System.Linq;
using System.Security.Claims;
using PBIRS.SecurityExtension.Auth;
using Xunit;

namespace PBIRS.Tests
{
    public class AuthorizationServiceTests
    {
        [Fact]
        public void Maps_Admin_To_SystemAdministrator()
        {
            var claims = new[] { new Claim(ClaimTypes.Role, "admin") };
            var principal = new ClaimsPrincipal(new ClaimsIdentity(claims));
            var svc = new AuthorizationService();

            var roles = svc.MapRoles(principal).ToList();
            Assert.Contains(RoleConstants.SystemAdministrator, roles);
            Assert.True(svc.IsInRole(principal, RoleConstants.SystemAdministrator));
        }

        [Fact]
        public void Maps_Editor_To_ContentManager()
        {
            var claims = new[] { new Claim(ClaimTypes.Role, "editor") };
            var principal = new ClaimsPrincipal(new ClaimsIdentity(claims));
            var svc = new AuthorizationService();

            var roles = svc.MapRoles(principal).ToList();
            Assert.Contains(RoleConstants.ContentManager, roles);
            Assert.True(svc.IsInRole(principal, RoleConstants.ContentManager));
        }

        [Fact]
        public void Maps_Publisher_And_Reports()
        {
            var claims = new[] { new Claim(ClaimTypes.Role, "publisher"), new Claim(ClaimTypes.Role, "my-reports") };
            var principal = new ClaimsPrincipal(new ClaimsIdentity(claims));
            var svc = new AuthorizationService();

            var roles = svc.MapRoles(principal).ToList();
            Assert.Contains(RoleConstants.Publisher, roles);
            Assert.Contains(RoleConstants.MyReports, roles);
            Assert.True(svc.Authorize(principal, RoleConstants.Publisher));
            Assert.True(svc.Authorize(principal, RoleConstants.MyReports));
        }

        [Fact]
        public void Authorize_Returns_False_When_No_Roles()
        {
            var principal = new ClaimsPrincipal(new ClaimsIdentity());
            var svc = new AuthorizationService();
            Assert.False(svc.Authorize(principal, RoleConstants.SystemAdministrator));
        }
    }
}
