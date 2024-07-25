using System;

namespace RyuSocks.Types
{
    public interface IWrapper
    {
        /// <summary>
        /// The maximum amount of bytes that will be added or removed by this wrapper.
        /// </summary>
        public int WrapperLength { get; }

        /// <summary>
        /// Wrap the packet as required.
        /// </summary>
        /// <param name="packet">The packet to wrap.</param>
        /// <param name="packetLength">
        /// The current length of the packet.
        /// It may be smaller than the provided <see cref="Span{T}"/> of <paramref name="packet"/>.
        /// </param>
        /// <param name="remoteEndpoint">The destination endpoint of this packet.</param>
        /// <returns>The length of the wrapped packet.</returns>
        public int Wrap(Span<byte> packet, int packetLength, ProxyEndpoint remoteEndpoint);

        /// <summary>
        /// Unwrap the packet and perform the checks as required.
        /// </summary>
        /// <param name="packet">The packet to unwrap.</param>
        /// <param name="packetLength">
        /// The current length of the packet.
        /// It may be smaller than the provided <see cref="Span{T}"/> of <paramref name="packet"/>.
        /// </param>
        /// <param name="remoteEndpoint">The source endpoint of this packet.</param>
        /// <returns>The length of the wrapped packet.</returns>
        public int Unwrap(Span<byte> packet, int packetLength, out ProxyEndpoint remoteEndpoint);
    }
}
