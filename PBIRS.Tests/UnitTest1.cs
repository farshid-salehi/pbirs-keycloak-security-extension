using Xunit;
using PBIRS.Common;

namespace PBIRS.Tests
{
    public class UnitTest1
    {
        [Fact]
        public void Hello_ReturnsMessage()
        {
            var s = Class1.Hello();
            Assert.Equal("PBIRS.Common ready", s);
        }
    }
}
