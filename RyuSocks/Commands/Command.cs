using RyuSocks.Types;
using System;
using System.Net;

namespace RyuSocks.Commands
{
    public abstract class Command : IWrapper
    {
        public abstract bool HandlesCommunication { get; }
        public abstract bool UsesDatagrams { get; }
        public virtual int WrapperLength => 0;

        protected readonly ProxyEndpoint ProxyEndpoint;

        protected Command(ProxyEndpoint proxyEndpoint)
        {
            ProxyEndpoint = proxyEndpoint;
        }

        public virtual int Wrap(Span<byte> packet, int packetLength, ProxyEndpoint remoteEndpoint)
        {
            return 0;
        }

        public virtual int Unwrap(Span<byte> packet, int packetLength, out ProxyEndpoint remoteEndpoint)
        {
            remoteEndpoint = ProxyEndpoint;
            return 0;
        }

        public virtual int Send(ReadOnlySpan<byte> buffer)
        {
            throw new NotSupportedException("This command does not require a second connection, so this method must not be called.");
        }

        public virtual int SendTo(ReadOnlySpan<byte> buffer, EndPoint endpoint)
        {
            throw new NotSupportedException("This command does not use datagrams, so this method must not be called.");
        }

        public virtual int Receive(Span<byte> buffer)
        {
            throw new NotSupportedException("This command does not require a second connection, so this method must not be called.");
        }

        public virtual int ReceiveFrom(Span<byte> buffer, ref EndPoint endpoint)
        {
            throw new NotSupportedException("This command does not use datagrams, so this method must not be called.");
        }
    }
}
