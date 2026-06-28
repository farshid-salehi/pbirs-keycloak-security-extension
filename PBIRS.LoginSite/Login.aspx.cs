using System;
using System.Web;
using PBIRS.SecurityExtension.Auth;

namespace PBIRS.LoginSite
{
    public partial class Login : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            var auth = HttpContext.Current.Application["AuthService"] as IAuthenticationExtension2;
            if (auth == null)
            {
                Response.Redirect("/Error.aspx?m=" + HttpUtility.UrlEncode("Authentication service not configured"));
                return;
            }

            try
            {
                var redirectUri = new Uri(Request.Url, "Callback.aspx").ToString();
                var req = auth.CreateSignInRequestAsync(redirectUri).GetAwaiter().GetResult();

                // persist code_verifier, state and nonce in session keyed by state
                Session["oidc." + req.State + ".code_verifier"] = req.CodeVerifier;
                Session["oidc." + req.State + ".nonce"] = req.Nonce;

                Response.Redirect(req.Url);
            }
            catch (Exception ex)
            {
                Response.Redirect("/Error.aspx?m=" + HttpUtility.UrlEncode(ex.Message));
            }
        }
    }
}
