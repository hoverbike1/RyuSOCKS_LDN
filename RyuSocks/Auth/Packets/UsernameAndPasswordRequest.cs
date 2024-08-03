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
using System;
using System.Text;

namespace RyuSocks.Auth.Packets
{
    public class UsernameAndPasswordRequest : Packet
    {
        private const int MinimumPacketLength = 4;
        private const int MaximumPacketLength = 513;

        public byte Version
        {
            get
            {
                return Bytes[0];
            }
            set
            {
                Bytes[0] = value;
            }
        }

        public byte UsernameLength
        {
            get
            {
                return Bytes[1];
            }
            set
            {
                Bytes[1] = value;
            }
        }

        public string Username
        {
            get
            {
                return Encoding.ASCII.GetString(Bytes.AsSpan(2, UsernameLength));
            }
            set
            {
                ArgumentOutOfRangeException.ThrowIfGreaterThan(value.Length, 0xFF);
                UsernameLength = (byte)value.Length;
                Encoding.ASCII.GetBytes(value).CopyTo(Bytes.AsSpan(2, UsernameLength));
            }
        }

        public byte PasswordLength
        {
            get
            {
                return Bytes[2 + UsernameLength];
            }
            set
            {
                Bytes[2 + UsernameLength] = value;
            }
        }

        public string Password
        {
            get
            {
                return Encoding.ASCII.GetString(Bytes.AsSpan(3 + UsernameLength, PasswordLength));
            }
            set
            {
                ArgumentOutOfRangeException.ThrowIfGreaterThan(value.Length, 0xFF);
                PasswordLength = (byte)value.Length;
                Encoding.ASCII.GetBytes(value).CopyTo(Bytes.AsSpan(3 + UsernameLength, PasswordLength));
            }
        }

        public UsernameAndPasswordRequest(byte[] packetBytes) : base(packetBytes)
        {
            if (Bytes.Length is < MinimumPacketLength or > MaximumPacketLength)
            {
                throw new ArgumentOutOfRangeException(
                    $"Packet length is invalid: {Bytes.Length} (Expected: {MinimumPacketLength} <= length <= {MaximumPacketLength})");
            }
        }

        public UsernameAndPasswordRequest(string username, string password)
        {
            int packetLength = username.Length + password.Length + 4;

            if (packetLength < MaximumPacketLength)
            {
                Bytes = new byte[packetLength];
            }
            else
            {
                throw new ArgumentOutOfRangeException($"Packet length is invalid: {packetLength} (Expected: {MinimumPacketLength} <= length <= {MaximumPacketLength})");
            }

            Version = AuthConsts.UsernameAndPasswordVersion;
            Username = username;
            Password = password;
        }

        public override void Validate()
        {
            if (Bytes.Length is < MinimumPacketLength or > MaximumPacketLength)
            {
                throw new ArgumentOutOfRangeException($"Packet length is invalid: {Bytes.Length} (Expected: {MinimumPacketLength} <= length <= {MaximumPacketLength})");
            }

            if (Version != AuthConsts.UsernameAndPasswordVersion)
            {
                throw new InvalidOperationException($"{nameof(Version)} is invalid: {Version:X} (Expected: {AuthConsts.UsernameAndPasswordVersion:X})");
            }

            if (string.IsNullOrEmpty(Username))
            {
                throw new InvalidOperationException($"{nameof(Username)} can't be null or empty.");
            }

            if (string.IsNullOrEmpty(Password))
            {
                throw new InvalidOperationException($"{nameof(Password)} can't be null or empty.");
            }
        }
    }
}
