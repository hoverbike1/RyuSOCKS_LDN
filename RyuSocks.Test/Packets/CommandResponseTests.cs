/*
 * Copyright (C) RyuSOCKS
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

using RyuSocks.Packets;
using RyuSocks.Test.Utils;
using RyuSocks.Types;
using RyuSocks.Utils;
using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Xunit;

namespace RyuSocks.Test.Packets
{
    public class CommandResponseTests
    {
        private const string VeryLongInvalidTestDomainName = "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc.local";

#pragma warning disable IDE0055 // Disable formatting
        public static readonly TheoryData<byte, ReplyField, byte, string, ushort> DnsEndPointData = new()
        {
            // version,             replyField,              reserved,  domainName,   port
            {  0x22,                ReplyField.Succeeded,      0x05,    "abc.local",  1337 },
            {  ProxyConsts.Version, ReplyField.TTLExpired,     0x21,    "123.local",  4242 },
            {  ProxyConsts.Version, (ReplyField)byte.MaxValue, 0xAA,    "test.local", 1042 },
        };
        
        public static readonly TheoryData<byte, ReplyField, byte, string, ushort, bool> IpEndPointData = new()
        {
            // version,            replyField               reserved,  ipAddress,                  port, isIpv4
            { 0x22,                ReplyField.Succeeded,      0xBB,    "10.0.0.122",               1337, true  },
            { 0x22,                ReplyField.Succeeded,      0xCC,    "2001:db8::aaaa:c0c0:4444", 1337, false },
            { ProxyConsts.Version, ReplyField.TTLExpired,     0xDD,    "192.168.12.23",            4242, true  },
            { ProxyConsts.Version, ReplyField.TTLExpired,     0xEE,    "2001:db8::2222:cbba:1234", 4212, false },
            { ProxyConsts.Version, (ReplyField)byte.MaxValue, 0xFF,    "0.0.0.0",                  1042, true  },
            { ProxyConsts.Version, (ReplyField)byte.MaxValue, 0x07,    "2001:db8::ffff:0001",         2, false },
        };
#pragma warning restore IDE0055

        [Theory]
        [StringData(byte.MinValue + 1, byte.MaxValue, 4)]
        [StringData(byte.MinValue, byte.MaxValue + 1)]
        public void Bytes_Size_DnsEndPoint(string domainName)
        {
            // Version: 1 byte
            // Reply field: 1 byte
            // Reserved: 1 byte
            // Address type: 1 byte
            // Address: 2 - 256 bytes
            // Port: 2 bytes
            // Total: 8 - 262 bytes

            if (domainName.Length == 0)
            {
                Assert.Throws<ArgumentException>(() => new DnsEndPoint(domainName, 0));
                return;
            }

            DnsEndPoint endpoint = new(domainName, 0);

            if (domainName.Length > byte.MaxValue)
            {
                Assert.Throws<ArgumentOutOfRangeException>(() => new CommandResponse(endpoint));
                return;
            }

            CommandResponse response = new(endpoint);

            Assert.Equal(7 + domainName.Length, response.Bytes.Length);
        }

        [Theory]
        [InlineData("10.0.0.5", 2211, true)]
        [InlineData("2001:db8::abba:c000:1221", 572, false)]
        public void Bytes_Size_IPEndPoint(string ipAddress, ushort port, bool isIpv4)
        {
            // Version: 1 byte
            // Reply field: 1 byte
            // Reserved: 1 byte
            // Address type: 1 byte
            // Address: 4 or 16 bytes
            // Port: 2 bytes
            // Total: 10 or 22 bytes

            IPEndPoint endpoint = new(IPAddress.Parse(ipAddress), port);
            CommandResponse response = new(endpoint);

            AddressFamily expectedAddressFamily = isIpv4 ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6;
            int expectedLength = isIpv4 ? 10 : 22;

            Assert.Equal(expectedAddressFamily, endpoint.AddressFamily);
            Assert.Equal(expectedLength, response.Bytes.Length);
        }

        [Theory]
        [MemberData(nameof(DnsEndPointData))]
        public void Bytes_MatchStructure_DnsEndPoint(byte version, ReplyField replyField, byte reserved, string domainName, ushort port)
        {
            byte[] expectedBytes = [
                // Version
                version,
                // Reply field
                (byte)replyField,
                // Reserved
                reserved,
                // Address type
                0x03,
                // Address
                // Port
            ];
            Array.Resize(ref expectedBytes, expectedBytes.Length + 1 + domainName.Length + 2);
            // Address
            expectedBytes[4] = (byte)Encoding.ASCII.GetByteCount(domainName);
            Encoding.ASCII.GetBytes(domainName).CopyTo(expectedBytes.AsSpan(5));
            // Port
            BitConverter.GetBytes(port).Reverse().ToArray().CopyTo(expectedBytes.AsSpan(expectedBytes.Length - 2));

            CommandResponse response = new(new DnsEndPoint(domainName, port))
            {
                Version = version,
                ReplyField = replyField,
                Reserved = reserved,
            };

            Assert.Equal(expectedBytes, response.Bytes);
            // FIXME: Throwing exceptions from properties results in failure
            // NOTE: Consider returning a default value instead of throwing an exception for properties
            // Assert.Equivalent(new CommandRequest(expectedBytes), response);
        }

        [Theory]
        [MemberData(nameof(IpEndPointData))]
        public void Bytes_MatchStructure_IPEndPoint(byte version, ReplyField replyField, byte reserved, string ipAddress, ushort port, bool isIpv4)
        {
            IPAddress address = IPAddress.Parse(ipAddress);
            byte[] expectedBytes = [
                // Version
                version,
                // Reply field
                (byte)replyField,
                // Reserved
                reserved,
                // Address type
                isIpv4 ? (byte)0x01 : (byte)0x04,
                // Address
                // Port
            ];
            Array.Resize(ref expectedBytes, expectedBytes.Length + (isIpv4 ? 4 : 16) + 2);
            // Address
            bool addressWritten = address.TryWriteBytes(expectedBytes.AsSpan(4), out _);
            Assert.True(addressWritten);
            // Port
            BitConverter.GetBytes(port).Reverse().ToArray().CopyTo(expectedBytes.AsSpan(expectedBytes.Length - 2));

            CommandResponse response = new(new IPEndPoint(address, port))
            {
                Version = version,
                ReplyField = replyField,
                Reserved = reserved,
            };

            Assert.Equal(expectedBytes, response.Bytes);
            // FIXME: Throwing exceptions from properties results in failure
            // NOTE: Consider returning a default value instead of throwing an exception for properties
            // Assert.Equivalent(new CommandRequest(expectedBytes), response);
        }

        [Theory]
        [MemberData(nameof(DnsEndPointData))]
        public void Properties_ValuesMatch_DnsEndPoint(byte version, ReplyField replyField, byte reserved, string domainName, ushort port)
        {
            CommandResponse response = new(new DnsEndPoint(domainName, port))
            {
                Version = version,
                ReplyField = replyField,
                Reserved = reserved,
            };

            Assert.Equal(version, response.Version);
            Assert.Equal(replyField, response.ReplyField);
            Assert.Equal((AddressType)0x03, response.AddressType);
            Assert.Equal(reserved, response.Reserved);
            Assert.Equal(domainName, response.BoundDomainName);
            Assert.Equal(port, response.BoundPort);
        }

        [Theory]
        [MemberData(nameof(IpEndPointData))]
        public void Properties_ValuesMatch_IPEndPoint(byte version, ReplyField replyField, byte reserved, string ipAddress, ushort port, bool isIpv4)
        {
            IPAddress address = IPAddress.Parse(ipAddress);
            CommandResponse response = new(new IPEndPoint(address, port))
            {
                Version = version,
                ReplyField = replyField,
                Reserved = reserved,
            };

            Assert.Equal(version, response.Version);
            Assert.Equal(replyField, response.ReplyField);
            Assert.Equal(isIpv4 ? (AddressType)0x01 : (AddressType)0x04, response.AddressType);
            Assert.Equal(reserved, response.Reserved);
            Assert.Equal(address, response.BoundAddress);
            Assert.Equal(port, response.BoundPort);
        }

        [Theory]
        [InlineData(0x0, ReplyField.Succeeded, 0x00, AddressType.DomainName, "test.local", 1042, false)]
        [InlineData(0x1, ReplyField.Succeeded, 0x00, AddressType.DomainName, "test.local", 1242, false)]
        [InlineData(ProxyConsts.Version, ReplyField.TTLExpired, 0x2F, AddressType.DomainName, "test.local", 42, false)]
        [InlineData(ProxyConsts.Version, ReplyField.TTLExpired, 0x00, AddressType.Ipv6Address, "test.local", 66, false)]
        [InlineData(ProxyConsts.Version, ReplyField.NetworkUnreachable, 0x00, (AddressType)0xFF, "test.local", 21, false)]
        [InlineData(ProxyConsts.Version, ReplyField.NetworkUnreachable, 0x00, AddressType.DomainName, "", 1222, false)]
        [InlineData(ProxyConsts.Version, ReplyField.ServerFailure, 0x00, AddressType.DomainName, VeryLongInvalidTestDomainName, 1111, false)]
        [InlineData(ProxyConsts.Version, (ReplyField)0xFF, 0x00, AddressType.DomainName, "test.local", 0, true)]
        [InlineData(ProxyConsts.Version, ReplyField.Succeeded, 0x00, AddressType.DomainName, "test.local", 1042, true)]
        public void Validate_ThrowsOnInvalidValue_DomainName(byte version, ReplyField replyField, byte reserved, AddressType addressType, string domainName, ushort port, bool isValidInput)
        {
            // Construct the packet manually to skip the checks in the constructor
            byte[] packetBytes = [
                // Version
                version,
                // Reply field
                (byte)replyField,
                // Reserved
                reserved,
                // Address type
                (byte)addressType,
                // Address
                // Port
            ];
            Array.Resize(ref packetBytes, packetBytes.Length + 1 + (domainName.Length > 0 ? domainName.Length : 1) + 2);
            // Address
            packetBytes[4] = (byte)Encoding.ASCII.GetByteCount(domainName);
            Encoding.ASCII.GetBytes(domainName).CopyTo(packetBytes.AsSpan(5));
            // Port
            BitConverter.GetBytes(port).Reverse().ToArray().CopyTo(packetBytes.AsSpan(packetBytes.Length - 2));

            CommandResponse response = new(packetBytes);

            if (!isValidInput)
            {
                Assert.ThrowsAny<Exception>(() => response.Validate());
                return;
            }

            response.Validate();
        }

        [Theory]
        [InlineData(0, ReplyField.Succeeded, 0x00, AddressType.Ipv6Address, "2001:db8::aaaa:c0c0:4444", 1042, false, false)]
        [InlineData(0, ReplyField.Succeeded, 0x00, AddressType.Ipv4Address, "10.0.0.122", 1242, true, false)]
        [InlineData(1, ReplyField.Succeeded, 0x00, AddressType.Ipv6Address, "2001:db8::aaaa:c0c0:4444", 1042, false, false)]
        [InlineData(0xAF, ReplyField.Succeeded, 0x00, AddressType.Ipv4Address, "10.0.0.122", 1242, true, false)]
        [InlineData(ProxyConsts.Version, ReplyField.TTLExpired, 0x7F, AddressType.Ipv6Address, "2001:db8::aaaa:c0c0:4444", 1042, false, false)]
        [InlineData(ProxyConsts.Version, ReplyField.TTLExpired, 0xAA, AddressType.Ipv4Address, "10.0.0.122", 1242, true, false)]
        [InlineData(ProxyConsts.Version, ReplyField.TTLExpired, 0x00, AddressType.DomainName, "2001:db8::aaaa:c0c0:4444", 1042, false, false)]
        [InlineData(ProxyConsts.Version, ReplyField.TTLExpired, 0x00, AddressType.DomainName, "10.0.0.122", 1242, true, false)]
        [InlineData(ProxyConsts.Version, ReplyField.HostUnreachable, 0x00, (AddressType)0xFF, "2001:db8::aaaa:c0c0:4444", 1042, false, false)]
        [InlineData(ProxyConsts.Version, ReplyField.HostUnreachable, 0x00, (AddressType)0xFF, "10.0.0.122", 1242, true, false)]
        [InlineData(ProxyConsts.Version, ReplyField.CommandNotSupported, 0x00, AddressType.Ipv6Address, "2001:db8::aaaa:c0c0:4444", 0, false, true)]
        [InlineData(ProxyConsts.Version, ReplyField.CommandNotSupported, 0x00, AddressType.Ipv4Address, "10.0.0.122", 0, true, true)]
        [InlineData(ProxyConsts.Version, ReplyField.Succeeded, 0x00, AddressType.Ipv6Address, "2001:db8::ffff:0001", 2, false, true)]
        [InlineData(ProxyConsts.Version, ReplyField.Succeeded, 0x00, AddressType.Ipv4Address, "0.0.0.0", 1042, true, true)]
        [InlineData(ProxyConsts.Version, (ReplyField)0xFF, 0x00, AddressType.Ipv6Address, "2001:db8::aaaa:c0c0:4444", 2222, false, true)]
        [InlineData(ProxyConsts.Version, (ReplyField)0xFF, 0x00, AddressType.Ipv4Address, "10.0.0.122", 1111, true, true)]
        public void Validate_ThrowsOnInvalidValue_IPAddress(byte version, ReplyField replyField, byte reserved, AddressType addressType, string ipAddress, ushort port, bool isIpv4, bool isValidInput)
        {
            // Construct the packet manually to skip the checks in the constructor
            IPAddress address = IPAddress.Parse(ipAddress);
            byte[] packetBytes = [
                // Version
                version,
                // Reply field
                (byte)replyField,
                // Reserved
                reserved,
                // Address type
                (byte)addressType,
                // Address
                // Port
            ];
            Array.Resize(ref packetBytes, packetBytes.Length + (isIpv4 ? 4 : 16) + 2);
            // Address
            bool addressWritten = address.TryWriteBytes(packetBytes.AsSpan(4), out _);
            Assert.True(addressWritten);
            // Port
            BitConverter.GetBytes(port).Reverse().ToArray().CopyTo(packetBytes.AsSpan(packetBytes.Length - 2));

            CommandResponse response = new(packetBytes);

            if (!isValidInput)
            {
                Assert.ThrowsAny<Exception>(() => response.Validate());
                return;
            }

            response.Validate();
        }
    }
}
