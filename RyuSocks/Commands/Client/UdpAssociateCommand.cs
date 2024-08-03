// Copyright (C) RyuSOCKS
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2,
// as published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

using RyuSocks.Packets;
using RyuSocks.Types;
using RyuSocks.Utils;
using System;
using System.Net;
using System.Net.Sockets;

namespace RyuSocks.Commands.Client
{
    [ProxyCommandImpl(0x03)]
    public partial class UdpAssociateCommand : ClientCommand
    {
        private readonly Socket _socket;
        public override bool HandlesCommunication => true;
        public override bool UsesDatagrams => true;
        // TODO: Improve WrapperLength value.
        //       This is currently set to the maximum length of an EndpointPacket,
        //       but we usually don't need that much space.
        public override int WrapperLength => 262;

        public UdpAssociateCommand(SocksClient client, ProxyEndpoint source) : base(client, source)
        {
            var sourceEndpoint = source.ToEndPoint();
            _socket = new Socket(sourceEndpoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            _socket.Bind(sourceEndpoint);

            CommandRequest request = _socket.LocalEndPoint switch
            {
                IPEndPoint ipEndPoint => new CommandRequest(ipEndPoint)
                {
                    Version = ProxyConsts.Version,
                    Command = ProxyCommand.UdpAssociate,
                },
                DnsEndPoint dnsEndPoint => new CommandRequest(dnsEndPoint)
                {
                    Version = ProxyConsts.Version,
                    Command = ProxyCommand.UdpAssociate,
                },
                _ => throw new InvalidOperationException(
                    $"The type of LocalEndPoint is not supported: {_socket.LocalEndPoint}"),
            };

            request.Validate();
            Client.Send(request.AsSpan());
        }

        public override int Wrap(Span<byte> buffer, int packetLength, ProxyEndpoint remoteEndpoint)
        {
            UdpPacket packet = new(remoteEndpoint, packetLength);
            buffer[..packetLength].CopyTo(packet.UserData);
            packet.Validate();

            buffer.Clear();
            packet.AsSpan().CopyTo(buffer);

            return packet.Bytes.Length;
        }

        public override int Unwrap(Span<byte> buffer, int packetLength, out ProxyEndpoint remoteEndpoint)
        {
            UdpPacket packet = new(buffer[..packetLength].ToArray());
            remoteEndpoint = packet.ProxyEndpoint;
            packet.Validate();

            buffer.Clear();
            packet.UserData.CopyTo(buffer);

            return packet.Bytes.Length;
        }

        public override void ProcessResponse(CommandResponse response)
        {
            EnsureSuccessReply(response.ReplyField);

            if (ServerEndpoint == null)
            {
                ServerEndpoint = response.ProxyEndpoint;
                Accepted = true;
                Ready = true;
                return;
            }

            throw new InvalidOperationException($"Unexpected invocation of {nameof(ProcessResponse)}. {nameof(ServerEndpoint)} is already assigned.");
        }

        public override int ReceiveFrom(Span<byte> buffer, ref EndPoint endpoint)
        {
            int receivedBytes = 0;

            // Discard packets from unexpected endpoints
            while (ServerEndpoint.ToEndPoint() != endpoint)
            {
                receivedBytes = _socket.ReceiveFrom(buffer, ref endpoint);
            }

            return receivedBytes;
        }

        public override int SendTo(ReadOnlySpan<byte> buffer, EndPoint endpoint)
        {
            return _socket.SendTo(buffer, ServerEndpoint.ToEndPoint());
        }
    }
}
