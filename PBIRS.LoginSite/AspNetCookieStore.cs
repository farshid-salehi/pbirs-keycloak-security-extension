using System;
using System.Web;

namespace PBIRS.LoginSite
{
    public class AspNetCookieStore : PBIRS.SecurityExtension.Auth.ICookieStore
    {
        private readonly HttpContext _ctx;
        public AspNetCookieStore(HttpContext ctx) => _ctx = ctx ?? throw new ArgumentNullException(nameof(ctx));
        public string? Get(string name) => _ctx.Request.Cookies[name]?.Value;
        public void Set(string name, string value, DateTimeOffset? expires = null)
        {
            var cookie = new HttpCookie(name, value) { HttpOnly = true, Secure = _ctx.Request.IsSecureConnection, Path = "/" };
            if (expires.HasValue) cookie.Expires = expires.Value.UtcDateTime;
            _ctx.Response.Cookies.Remove(name);
            _ctx.Response.Cookies.Add(cookie);
        }
        public void Delete(string name)
        {
            var cookie = new HttpCookie(name, string.Empty) { Expires = DateTime.UtcNow.AddDays(-1), Path = "/" };
            _ctx.Response.Cookies.Remove(name);
            _ctx.Response.Cookies.Add(cookie);
        }
    }
}
