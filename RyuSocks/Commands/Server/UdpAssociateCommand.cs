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
using System.Collections.Generic;
using System.Net;

namespace RyuSocks.Commands.Server
{
    [ProxyCommandImpl(0x03)]
    public partial class UdpAssociateCommand : ServerCommand, IDisposable
    {
        public override bool HandlesCommunication => true;
        public override bool UsesDatagrams => true;
        // TODO: Improve WrapperLength value.
        //       This is currently set to the maximum length of an EndpointPacket,
        //       but we usually don't need that much space.
        public override int WrapperLength => 262;
        private UdpServer _server;

        public UdpAssociateCommand(SocksSession session, IPEndPoint boundEndpoint, ProxyEndpoint source) : base(session, boundEndpoint, source)
        {
            if (source == ProxyEndpoint.Null)
            {
                Session.SendAsync(new CommandResponse
                {
                    Version = ProxyConsts.Version,
                    // TODO: Figure out which error should be used here
                    ReplyField = ReplyField.ServerFailure,
                }.AsSpan());

                session.Disconnect();
                return;
            }

            _server = new UdpServer(this, boundEndpoint);

            _server.Start();

            // CommandResponse sent by UdpServer.OnStarted() below.
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

        public override int SendTo(ReadOnlySpan<byte> buffer, EndPoint endpoint)
        {
            return (int)_server.Send(endpoint, buffer);
        }

        public override void OnReceived(ReadOnlySpan<byte> buffer)
        {
            throw new InvalidOperationException("This connection can't be used to send data.");
        }

        private void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_server != null)
                {
                    _server.Stop();
                    _server.Dispose();
                    _server = null;
                }
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        class UdpServer : NetCoreServer.UdpServer
        {
            private readonly UdpAssociateCommand _command;
            private readonly HashSet<ProxyEndpoint> _destinationEndpoints = [];

            public UdpServer(UdpAssociateCommand command, IPEndPoint endpoint) : base(endpoint)
            {
                _command = command;
            }

            protected override void OnStarted()
            {
                CommandResponse response = Endpoint switch
                {
                    IPEndPoint ipEndPoint => new CommandResponse(ipEndPoint)
                    {
                        Version = ProxyConsts.Version,
                        ReplyField = ReplyField.Succeeded,
                    },
                    DnsEndPoint dnsEndPoint => new CommandResponse(dnsEndPoint)
                    {
                        Version = ProxyConsts.Version,
                        ReplyField = ReplyField.Succeeded,
                    },
                    _ => throw new InvalidOperationException(
                        $"The type of EndPoint is not supported: {Endpoint}"),
                };

                _command.Session.SendAsync(response.AsSpan());
            }

            private bool IsClientEndpoint(EndPoint endpoint)
            {
                return endpoint == _command.ProxyEndpoint.ToEndPoint() ||
                       (endpoint is IPEndPoint ipEndpoint && _command.ProxyEndpoint.Contains(ipEndpoint));
            }

            protected override void OnReceived(EndPoint endpoint, byte[] buffer, long offset, long size)
            {
                Span<byte> bufferSpan = buffer.AsSpan((int)offset, (int)size);

                if (IsClientEndpoint(endpoint))
                {
                    int bufferLength = bufferSpan.Length;
                    int requiredWrapperSpace = _command.Session.GetRequiredWrapperSpace();

                    if (requiredWrapperSpace != 0)
                    {
                        byte[] wrapperBuffer = new byte[bufferSpan.Length + requiredWrapperSpace];
                        bufferSpan.CopyTo(wrapperBuffer);
                        bufferSpan = wrapperBuffer;
                    }

                    bufferLength = _command.Session.Unwrap(bufferSpan, bufferLength, out ProxyEndpoint remoteEndpoint);

                    if (!_destinationEndpoints.Contains(remoteEndpoint) && !_command.Session.IsDestinationValid(remoteEndpoint))
                    {
                        return;
                    }

                    _destinationEndpoints.Add(remoteEndpoint);

                    this.SendAsync(remoteEndpoint.ToEndPoint(), bufferSpan[..bufferLength]);

                    return;
                }

                ProxyEndpoint proxyEndpoint = endpoint switch
                {
                    IPEndPoint ipEndpoint => new ProxyEndpoint(ipEndpoint),
                    DnsEndPoint dnsEndpoint => new ProxyEndpoint(dnsEndpoint),
                    _ => throw new ArgumentException($"The type {endpoint} is not supported.", nameof(endpoint)),
                };

                if (!_destinationEndpoints.Contains(proxyEndpoint))
                {
                    return;
                }

                _command.Session.SendTo(bufferSpan, proxyEndpoint);
            }
        }
    }
}
