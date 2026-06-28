using System;
using System.Web;

namespace PBIRS.LoginSite
{
    public partial class ErrorPage : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            var m = Request.QueryString["m"] ?? "An error occurred.";
            LitMessage.Text = HttpUtility.HtmlEncode(m);
        }
    }
}
