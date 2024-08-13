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

using NetCoreServer;
using RyuSocks.Auth;
using RyuSocks.Auth.Extensions;
using RyuSocks.Commands;
using RyuSocks.Commands.Extensions;
using RyuSocks.Packets;
using RyuSocks.Types;
using RyuSocks.Utils;
using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;

namespace RyuSocks
{
    public partial class SocksSession : TcpSession
    {
        public bool Closing { get; protected set; }
        public bool Authenticated { get; protected set; }
        public IProxyAuth Auth { get; protected set; }
        public ServerCommand Command { get; protected set; }

        public new SocksServer Server => base.Server as SocksServer;

        public SocksSession(TcpServer server) : base(server) { }

        public bool IsDestinationValid(ProxyEndpoint destination)
        {
            if (!Server.UseAllowList && !Server.UseBlockList)
            {
                return true;
            }

            bool isDestinationValid = false;

            // Check whether the client is allowed to connect to the requested destination.
            foreach (IPAddress destinationAddress in destination.Addresses)
            {
                if (Server.UseAllowList
                    && Server.AllowedDestinations.TryGetValue(destinationAddress, out ushort[] allowedPorts)
                    && allowedPorts.Contains(destination.Port))
                {
                    isDestinationValid = true;
                    break;
                }

                if (Server.UseBlockList
                    && (!Server.BlockedDestinations.TryGetValue(destinationAddress, out allowedPorts)
                        || !allowedPorts.Contains(destination.Port)))
                {
                    isDestinationValid = true;
                    break;
                }
            }

            return isDestinationValid;
        }

        public int GetRequiredWrapperSpace()
        {
            int wrapperSpace = 0;

            if (Authenticated)
            {
                wrapperSpace = Auth.WrapperLength;
            }

            if (Command != null && wrapperSpace < Command.WrapperLength)
            {
                wrapperSpace = Command.WrapperLength;
            }

            return wrapperSpace;
        }

        // TODO: Remove this once async Send/Receive for commands has been implemented.
        public int Unwrap(Span<byte> packet, int packetLength, out ProxyEndpoint remoteEndpoint)
        {
            if (!IsConnected || Closing)
            {
                throw new InvalidOperationException("Session is not connected or closing soon.");
            }

            remoteEndpoint = null;
            int totalWrapperLength = packetLength;

            if (Authenticated)
            {
                totalWrapperLength = Auth.Unwrap(packet, packetLength, out remoteEndpoint);
            }

            if (Command != null)
            {
                totalWrapperLength = Command.Unwrap(packet, packetLength, out remoteEndpoint);
            }

            return totalWrapperLength;
        }

        protected virtual void ProcessAuthMethodSelection(ReadOnlySpan<byte> buffer)
        {
            var request = new MethodSelectionRequest(buffer.ToArray());
            request.Validate();

            foreach (var requestedAuthMethod in request.Methods)
            {
                if (Server.AcceptableAuthMethods.Contains(requestedAuthMethod))
                {
                    var reply = new MethodSelectionResponse(requestedAuthMethod)
                    {
                        Version = ProxyConsts.Version,
                    };

                    SendAsync(reply.AsSpan());
                    Auth = requestedAuthMethod.GetAuth();

                    return;
                }
            }

            var errorReply = new MethodSelectionResponse(AuthMethod.NoAcceptableMethods)
            {
                Version = ProxyConsts.Version,
            };

            SendAsync(errorReply.AsSpan());
            Closing = true;
        }

        protected virtual void ProcessCommandRequest(Span<byte> buffer, int bufferLength)
        {
            bufferLength = Unwrap(buffer, bufferLength, out _);
            var request = new CommandRequest(buffer[..bufferLength].ToArray());
            request.Validate();

            var errorReply = new CommandResponse(new IPEndPoint(0, 0))
            {
                Version = ProxyConsts.Version,
            };

            // Check whether the client requested a valid command.
            if (Server.OfferedCommands.Contains(request.Command))
            {
                // FIXME: Some commands use this field as the client endpoint, not the destination.
                if (IsDestinationValid(request.ProxyEndpoint))
                {
                    Command = request.Command.GetServerCommand()(this, (IPEndPoint)Server.Endpoint, request.ProxyEndpoint);
                    return;
                }

                errorReply.ReplyField = ReplyField.ConnectionNotAllowed;
                SendAsync(errorReply.AsSpan());
                Closing = true;

                return;
            }

            errorReply.ReplyField = ReplyField.CommandNotSupported;
            SendAsync(errorReply.AsSpan());
            Closing = true;
        }

        protected override void OnReceived(byte[] buffer, long offset, long size)
        {
            Span<byte> bufferSpan = buffer.AsSpan((int)offset, (int)size);

            // Choose the authentication method.
            if (Auth == null)
            {
                ProcessAuthMethodSelection(bufferSpan);
                // TODO: We should avoid having special cases. Is this fine?
                Authenticated = Auth.GetAuth() == AuthMethod.NoAuth;

                return;
            }

            // Authenticate the client.
            if (!Authenticated)
            {
                try
                {
                    Authenticated = Auth.Authenticate(bufferSpan, out ReadOnlySpan<byte> sendBuffer);
                    SendAsync(sendBuffer);
                }
                catch (AuthenticationException)
                {
                    // TODO: Log the exception here.
                    Closing = true;
                }

                return;
            }

            int bufferLength = bufferSpan.Length;
            int requiredWrapperSpace = GetRequiredWrapperSpace();

            if (requiredWrapperSpace != 0)
            {
                byte[] wrapperBuffer = new byte[bufferSpan.Length + requiredWrapperSpace];
                bufferSpan.CopyTo(wrapperBuffer);
                bufferSpan = wrapperBuffer;
            }

            // Attempt to process a command request.
            if (Command == null)
            {
                ProcessCommandRequest(bufferSpan, bufferLength);
                return;
            }

            // Don't process packets for clients we are disconnecting soon.
            if (Closing)
            {
                return;
            }

            bufferLength = Unwrap(bufferSpan, bufferLength, out _);

            Command.OnReceived(bufferSpan[..bufferLength]);
        }

        protected override void OnEmpty()
        {
            if (Closing)
            {
                Disconnect();
            }
        }

        public override bool SendAsync(ReadOnlySpan<byte> buffer)
        {
            int bufferLength = buffer.Length;
            int bufferSize = bufferLength + GetRequiredWrapperSpace();

            byte[] sendBufferArray = buffer.ToArray();
            Span<byte> sendBuffer = sendBufferArray;

            if (bufferLength != bufferSize)
            {
                Array.Resize(ref sendBufferArray, bufferSize);
                sendBuffer = sendBufferArray;
            }

            if (Command != null)
            {
                bufferLength = Command.Wrap(sendBuffer, bufferLength, null);
            }

            if (Authenticated)
            {
                bufferLength = Auth.Wrap(sendBuffer, bufferLength, null);
            }

            if (Command is { UsesDatagrams: true })
            {
                throw new InvalidOperationException($"{nameof(SendAsync)} can't be used when sending datagrams.");
            }

            if (Command is { HandlesCommunication: true })
            {
                throw new NotImplementedException("Async Send/Receive for commands has not been implemented yet.");
            }

            return base.SendAsync(sendBuffer[..bufferLength]);
        }

        public override long Send(ReadOnlySpan<byte> buffer)
        {
            int bufferLength = buffer.Length;
            int bufferSize = bufferLength + GetRequiredWrapperSpace();

            byte[] sendBufferArray = buffer.ToArray();
            Span<byte> sendBuffer = sendBufferArray;

            if (bufferLength != bufferSize)
            {
                Array.Resize(ref sendBufferArray, bufferSize);
                sendBuffer = sendBufferArray;
            }

            if (Command != null)
            {
                bufferLength = Command.Wrap(sendBuffer, bufferLength, null);
            }

            if (Authenticated)
            {
                bufferLength = Auth.Wrap(sendBuffer, bufferLength, null);
            }

            if (Command is { UsesDatagrams: true })
            {
                throw new InvalidOperationException($"{nameof(Send)} can't be used when sending datagrams.");
            }

            if (Command is { HandlesCommunication: true })
            {
                long sentSize = Command.Send(sendBuffer[..bufferLength], SocketFlags.None, out SocketError errorCode);

                if (errorCode != SocketError.Success)
                {
                    throw new SocketException((int)errorCode);
                }

                return sentSize;
            }

            return base.Send(sendBuffer[..bufferLength]);
        }

        public int SendTo(ReadOnlySpan<byte> buffer, ProxyEndpoint endpoint)
        {
            if (Command == null)
            {
                throw new InvalidOperationException("No command was requested yet.");
            }

            if (!Command.UsesDatagrams)
            {
                throw new InvalidOperationException("The requested command is not able to send datagrams.");
            }

            int bufferLength = buffer.Length;
            int bufferSize = bufferLength + GetRequiredWrapperSpace();

            byte[] sendBufferArray = buffer.ToArray();
            Span<byte> sendBuffer = sendBufferArray;

            if (bufferLength != bufferSize)
            {
                Array.Resize(ref sendBufferArray, bufferSize);
                sendBuffer = sendBufferArray;
            }

            bufferLength = Command.Wrap(sendBuffer, bufferLength, endpoint);

            if (Authenticated)
            {
                bufferLength = Auth.Wrap(sendBuffer, bufferLength, endpoint);
            }

            return Command.SendTo(sendBuffer[..bufferLength], SocketFlags.None, endpoint.ToEndPoint());
        }

        public int SendTo(ReadOnlySpan<byte> buffer, EndPoint endpoint)
        {
            ProxyEndpoint remoteEndpoint = endpoint switch
            {
                IPEndPoint ipEndpoint => new ProxyEndpoint(ipEndpoint),
                DnsEndPoint dnsEndpoint => new ProxyEndpoint(dnsEndpoint),
                _ => throw new ArgumentException($"The provided type {endpoint} is not supported.", nameof(endpoint)),
            };

            return SendTo(buffer, remoteEndpoint);
        }
    }
}
