using RyuSocks.Types;
using System;
using System.Net;
using System.Net.Sockets;

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

        public virtual void Disconnect()
        {
            throw new NotSupportedException("This command does not require a second connection, so this method must not be called.");
        }

        public virtual void GetSocketOption(
            SocketOptionLevel optionLevel,
            SocketOptionName optionName,
            byte[] optionValue)
        {
            throw new NotSupportedException("This command does not require a second connection, so this method must not be called.");
        }

        public virtual void SetSocketOption(
            SocketOptionLevel optionLevel,
            SocketOptionName optionName,
            byte[] optionValue)
        {
            throw new NotSupportedException("This command does not require a second connection, so this method must not be called.");
        }

        public virtual bool Poll(int microSeconds, SelectMode mode)
        {
            throw new NotSupportedException("This command does not require a second connection, so this method must not be called.");
        }

        public virtual int Send(ReadOnlySpan<byte> buffer, SocketFlags socketFlags, out SocketError errorCode)
        {
            throw new NotSupportedException("This command does not require a second connection, so this method must not be called.");
        }

        public virtual int SendTo(ReadOnlySpan<byte> buffer, SocketFlags socketFlags, EndPoint remoteEP)
        {
            throw new NotSupportedException("This command does not use datagrams, so this method must not be called.");
        }

        public virtual int Receive(Span<byte> buffer, SocketFlags socketFlags, out SocketError errorCode)
        {
            throw new NotSupportedException("This command does not require a second connection, so this method must not be called.");
        }

        public virtual int ReceiveFrom(Span<byte> buffer, SocketFlags socketFlags, ref EndPoint remoteEP)
        {
            throw new NotSupportedException("This command does not use datagrams, so this method must not be called.");
        }
    }
}
