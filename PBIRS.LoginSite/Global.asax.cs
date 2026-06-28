using System;
using System.Web;
using PBIRS.SecurityExtension.Auth;
using PBIRS.SecurityExtension.Oidc;

namespace PBIRS.LoginSite
{
    public class Global : HttpApplication
    {
        protected void Application_Start(object sender, EventArgs e)
        {
            // Configure OIDC options - adjust these values for your environment
            var oidcOptions = new OidcOptions
            {
                Authority = "https://your-issuer.example.com",
                ClientId = "your-client-id",
                ClientSecret = null,
                RedirectUri = "https://localhost:5001/Callback.aspx",
                Scope = "openid profile email",
                RequirePkce = true
            };

            var oidcClient = new OidcClient(oidcOptions);
            var sliding = new SlidingSessionManager(TimeSpan.FromMinutes(30), TimeSpan.FromMinutes(5), "PBIRS.Session.Purpose");
            var cookieManager = new CookieManager(sliding, ".PBIRS.Auth");
            var authService = new AuthenticationService(oidcClient, cookieManager, new ClaimsMapper(), new RoleMapper(), new PrincipalFactory());

            // store in application for simple access in pages (or register via DI in a more advanced setup)
            Application["AuthService"] = authService;
            Application["CookieName"] = ".PBIRS.Auth";
        }

        protected void Application_BeginRequest(object sender, EventArgs e)
        {
            var ctx = HttpContext.Current;
            if (ctx == null) return;

            // Automatic redirect: protect all pages except the auth endpoints and static files
            var path = ctx.Request.Path ?? string.Empty;
            var lower = path.ToLowerInvariant();
            if (lower.StartsWith("/login.aspx") || lower.StartsWith("/callback.aspx") || lower.StartsWith("/logout.aspx") || lower.StartsWith("/error.aspx") || lower.Contains(".css") || lower.Contains(".js") || lower.Contains(".png") || lower.Contains(".jpg") || lower.Contains(".ico"))
                return;

            try
            {
                var svc = Application["AuthService"] as IAuthenticationExtension2;
                if (svc == null) return;

                var cookieStore = new AspNetCookieStore(ctx);
                var result = svc.ValidateSessionAsync(cookieStore, Application["CookieName"] as string ?? ".PBIRS.Auth").GetAwaiter().GetResult();
                if (!result.IsAuthenticated)
                {
                    // redirect to login
                    ctx.Response.Redirect("/Login.aspx", true);
                }
            }
            catch
            {
                // on error, redirect to error page
                ctx.Response.Redirect("/Error.aspx?m=" + HttpUtility.UrlEncode("Authentication failure"), true);
            }
        }
    }
}
