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

using RyuSocks.Types;
using System;

namespace RyuSocks.Auth
{
    /// <summary>
    /// Novell Directory Service (NDS) authentication
    /// </summary>
    [AuthMethodImpl(0x07)]
    public class NDS : IProxyAuth
    {
        public int WrapperLength => throw new NotImplementedException();

        public bool Authenticate(ReadOnlySpan<byte> incomingPacket, out ReadOnlySpan<byte> outgoingPacket)
        {
            throw new NotImplementedException();
        }

        public int Wrap(Span<byte> packet, int packetLength, ProxyEndpoint remoteEndpoint)
        {
            throw new NotImplementedException();
        }

        public int Unwrap(Span<byte> packet, int packetLength, out ProxyEndpoint remoteEndpoint)
        {
            throw new NotImplementedException();
        }
    }
}
