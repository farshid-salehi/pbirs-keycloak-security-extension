using System;
using PBIRS.SecurityExtension.Oidc;
using Xunit;

namespace PBIRS.Tests
{
    public class OidcUtilitiesTests
    {
        [Fact]
        public void Pkce_Generator_Produces_Challenge()
        {
            var verifier = PkceUtil.GenerateCodeVerifier();
            Assert.False(string.IsNullOrEmpty(verifier));

            var challenge = PkceUtil.GenerateCodeChallenge(verifier);
            Assert.False(string.IsNullOrEmpty(challenge));
            Assert.NotEqual(verifier, challenge);
        }

        [Fact]
        public void State_And_Nonce_Are_Unique()
        {
            var s1 = StateUtil.CreateState();
            var s2 = StateUtil.CreateState();
            Assert.NotEqual(s1, s2);

            var n1 = StateUtil.CreateNonce();
            var n2 = StateUtil.CreateNonce();
            Assert.NotEqual(n1, n2);
        }
    }
}
