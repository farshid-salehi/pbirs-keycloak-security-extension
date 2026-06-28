using System;
using System.Web;
using PBIRS.SecurityExtension.Auth;
using PBIRS.SecurityExtension.Oidc;

namespace PBIRS.LoginSite
{
    public partial class Logout : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            var auth = HttpContext.Current.Application["AuthService"] as IAuthenticationExtension2;
            var oidc = HttpContext.Current.Application["AuthService"] as AuthenticationService; // AuthenticationService holds OidcClient internally but not exposed; we'll retrieve via reflection if needed
            var cookieStore = new AspNetCookieStore(HttpContext.Current);

            if (auth == null)
            {
                Response.Redirect("/Error.aspx?m=" + HttpUtility.UrlEncode("Authentication service not configured"));
                return;
            }

            try
            {
                // Clear local session cookie
                auth.SignOutAsync(cookieStore, HttpContext.Current.Application["CookieName"] as string ?? ".PBIRS.Auth").GetAwaiter().GetResult();

                // Try to perform single logout at the provider if endpoint exists
                var appAuthService = HttpContext.Current.Application["AuthService"] as AuthenticationService;
                if (appAuthService != null)
                {
                    // try to get id_token_hint from current session cookie before clearing; read cookie payload
                    var cm = appAuthService.GetType().GetField("_cookieManager", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)?.GetValue(appAuthService) as PBIRS.SecurityExtension.Auth.CookieManager;
                    if (cm != null)
                    {
                        var (payload, renewed) = cm.GetSessionPayload<PBIRS.SecurityExtension.Auth.AuthenticatedSession>(cookieStore);
                        var idToken = payload?.IdToken;
                        // get OIDC end session endpoint via reflection to access OidcClient
                        var oidcClient = appAuthService.GetType().GetField("_oidcClient", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)?.GetValue(appAuthService) as OidcClient;
                        if (oidcClient != null)
                        {
                            var postLogoutUri = new Uri(Request.Url, "/").ToString();
                            var endSession = oidcClient.GetEndSessionUrlAsync(idToken, postLogoutUri, StateUtil.CreateState()).GetAwaiter().GetResult();
                            if (!string.IsNullOrEmpty(endSession))
                            {
                                Response.Redirect(endSession, true);
                                return;
                            }
                        }
                    }
                }

                // fallback: redirect to root
                Response.Redirect("/", true);
            }
            catch (Exception ex)
            {
                Response.Redirect("/Error.aspx?m=" + HttpUtility.UrlEncode(ex.Message));
            }
        }
    }
}
