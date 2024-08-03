using RyuSocks.Auth;
using RyuSocks.Auth.Packets;
using System;
using Xunit;

namespace RyuSocks.Test.Auth
{
    public class UsernameAndPasswordResponseTest
    {
        [Theory]
        [InlineData(0x03, false)]
        [InlineData(AuthConsts.UsernameAndPasswordVersion, true)]
        public void Validate_ThrowsOnWrongVersion(byte version, bool hasRightVersion)
        {
            UsernameAndPasswordResponse expectedUsernameAndPasswordResponse = new([version, 0]);

            if (hasRightVersion)
            {
                expectedUsernameAndPasswordResponse.Validate();
            }
            else
            {
                Assert.ThrowsAny<Exception>(() => expectedUsernameAndPasswordResponse.Validate());
            }
        }
    }
}
