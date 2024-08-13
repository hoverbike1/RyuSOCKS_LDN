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

namespace RyuSocks.Commands.Client
{
    [ProxyCommandImpl(0x02)]
    public partial class BindCommand : ClientCommand
    {
        public override bool HandlesCommunication => false;
        public override bool UsesDatagrams => false;

        public BindCommand(SocksClient client, ProxyEndpoint source) : base(client, source)
        {
            CommandRequest request = new(source)
            {
                Version = ProxyConsts.Version,
                Command = ProxyCommand.Bind,
            };

            request.Validate();
            Client.Send(request.AsSpan());
        }

        public override void ProcessResponse(CommandResponse response)
        {
            EnsureSuccessReply(response.ReplyField);

            // Server endpoint used to listen for an incoming connection.
            if (ServerEndpoint == null)
            {
                ServerEndpoint = response.ProxyEndpoint;
                Accepted = true;
                return;
            }

            // Anticipated incoming connection.
            if (RemoteClients.Count == 0)
            {
                RemoteClients.Add(response.ProxyEndpoint);
                Ready = true;
                return;
            }

            throw new InvalidOperationException($"Unexpected invocation of {nameof(ProcessResponse)}. {nameof(ServerEndpoint)} and {nameof(ClientEndpoints)} are already assigned.");
        }
    }
}
