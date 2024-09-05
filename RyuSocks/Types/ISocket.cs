using System;
using System.Net;
using System.Net.Sockets;

namespace RyuSocks.Types
{
    public interface ISocket
    {
        public int Available { get; }
        public bool Blocking { get; set; }

        public void Disconnect();
        public void Shutdown(SocketShutdown how);
        public void GetSocketOption(SocketOptionLevel optionLevel, SocketOptionName optionName, byte[] optionValue);
        public object GetSocketOption(SocketOptionLevel optionLevel, SocketOptionName optionName);
        public void SetSocketOption(SocketOptionLevel optionLevel, SocketOptionName optionName, byte[] optionValue);
        public void SetSocketOption(SocketOptionLevel optionLevel, SocketOptionName optionName, int optionValue);
        public bool Poll(int microSeconds, SelectMode mode);
        public int Send(ReadOnlySpan<byte> buffer, SocketFlags socketFlags, out SocketError errorCode);
        public int SendTo(ReadOnlySpan<byte> buffer, SocketFlags socketFlags, EndPoint remoteEP);
        public int Receive(Span<byte> buffer, SocketFlags socketFlags, out SocketError errorCode);
        public int ReceiveFrom(Span<byte> buffer, SocketFlags socketFlags, ref EndPoint remoteEP);
    }
}
