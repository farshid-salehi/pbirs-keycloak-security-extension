using System;
using System.Web;
using PBIRS.SecurityExtension.Auth;

namespace PBIRS.LoginSite
{
    public partial class Callback : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            var error = Request.QueryString["error"];
            if (!string.IsNullOrEmpty(error))
            {
                var desc = Request.QueryString["error_description"] ?? error;
                Response.Redirect("/Error.aspx?m=" + HttpUtility.UrlEncode(desc));
                return;
            }

            var code = Request.QueryString["code"];
            var state = Request.QueryString["state"];
            if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state))
            {
                Response.Redirect("/Error.aspx?m=" + HttpUtility.UrlEncode("Missing code or state"));
                return;
            }

            var codeVerifier = Session["oidc." + state + ".code_verifier"] as string;
            var nonce = Session["oidc." + state + ".nonce"] as string;

            if (string.IsNullOrEmpty(codeVerifier) || string.IsNullOrEmpty(nonce))
            {
                Response.Redirect("/Error.aspx?m=" + HttpUtility.UrlEncode("State not found or expired"));
                return;
            }

            var auth = HttpContext.Current.Application["AuthService"] as IAuthenticationExtension2;
            if (auth == null)
            {
                Response.Redirect("/Error.aspx?m=" + HttpUtility.UrlEncode("Authentication service not configured"));
                return;
            }

            try
            {
                var cookieStore = new AspNetCookieStore(HttpContext.Current);
                var redirectUri = new Uri(Request.Url, "Callback.aspx").ToString();
                var result = auth.HandleSignInCallbackAsync(code, codeVerifier, state, nonce, redirectUri, cookieStore, HttpContext.Current.Application["CookieName"] as string ?? ".PBIRS.Auth").GetAwaiter().GetResult();

                if (!result.IsAuthenticated)
                {
                    Response.Redirect("/Error.aspx?m=" + HttpUtility.UrlEncode("Authentication failed"));
                    return;
                }

                // redirect to original page or root
                Response.Redirect("/", true);
            }
            catch (Exception ex)
            {
                Response.Redirect("/Error.aspx?m=" + HttpUtility.UrlEncode(ex.Message));
            }
        }
    }
}
