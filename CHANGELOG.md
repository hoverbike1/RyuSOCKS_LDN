# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1-alpha] - 2024-08-14

### Added

- Minimal implementation of `Shutdown()`
  for `SocksClient` and `Command` (in case it handles communication).

## [0.3.0-alpha] - 2024-08-14

### Added

- `SocksClient.Connect()` implementation which takes an `IPEndPoint`.
- `Socket.Disconnect()` method is exposed by `SocksClient` and commands now.
- Username and password authentication method
  according to [RFC 1929](https://datatracker.ietf.org/doc/html/rfc1929) ([#16]).
- New list property (`ClientCommand.ClientEndpoints`) which contains
  all remote client endpoints received from a proxy server.
- New `EndPoint` properties for `SocksClient`:
  `LocalEndPoint`, `ProxiedLocalEndPoint` and `ProxiedRemoteEndPoint`.
- Minimal implementation of `GetSocketOption()` and `SetSocketOption()`
  for `SocksClient` and `Command` (in case it handles communication).
- Minimal implementation of `Poll()` and `Blocking` 
  for `SocksClient` and `Command` (in case it handles communication).

### Changed

- Remove `Is`-prefix from `SocksSession` properties.

### Removed

- The client command property `BindCommand.ClientEndpoint`
  in favor of `ClientCommand.ClientEndpoints`.

### Fixed

- `SocksClient.Dispose()` now also calls `Dispose()` for commands
  which implement `IDisposable`.
- `UdpAssociateCommand.WrapperLength` now correctly returns the maximum amount 
  of bytes required to wrap/unwrap a `UdpPacket`.
- The send and receive methods of commands hava parameters for
  `SocketFlags` and `SocketError` now.

## [0.2.0-alpha] - 2024-07-28

### Added

- Logo made by [Justin de Haas](https://onemuri.nl/).
- Basic SOCKS5 proxy client (not compliant yet).
- New generated `IProxyAuth.GetAuth()` extension method
  to get the `AuthMethod` value from an auth implementation.
- `Packet` constructor which takes a byte array.
- New method `Packet.AsSpan()` to get the underlying byte array of a packet
  as a `Span<byte>`.
- Constructors taking a `ProxyEndpoint` for `EndpointPackets`.
- `Equals()` and `GetHashCode()` implementation for `ProxyEndpoint`.
- New interface `IWrapper` which contains `Wrap()` and `Unwrap()`.
- New properties for `Command` implementations to control communication
  with the proxy server.
- New method `Packet.IsValid()` which returns a bool instead of throwing exceptions. 
- `Validate()` implementation for `EndPointPacket`.
- `Socket.Close()` and `Socket.Dispose()` methods are exposed by `SocksClient` now.
- Missing parameterless constructor for `CommandRequest`.

### Changed

- Improved introduction in `README.md`.
- Renamed `Destination` class to `ProxyEndpoint`.
- `SocksSession.Process*()` methods were marked as virtual.
- Improved exception messages.
- Throw `ArgumentOutOfRangeException` instead of `ArgumentException`
  if the length of the domain name is invalid for `EndpointPackets`.
- Replaced init-only setter for `Packet.Bytes` with a regular setter.
- Replaced protected fields of `SocksSession` with public properties
  containing a protected setter.
- Changed the signature for `Wrap()` and `Unwrap()`.

### Fixed

- Misbehaving UdpAssociate command.

## [0.1.0-alpha] - 2024-04-21

### Added

- Basic SOCKS5 proxy server (not compliant yet).
- Connect command.
- Bind command.
- UdpAssociate command without fragmentation.
- Configurable authentication methods.
- Configurable SOCKS commands.
- Configurable allow and block lists.

[Unreleased]: https://github.com/TSRBerry/RyuSOCKS/compare/v0.3.1-alpha...HEAD
[0.3.0-alpha]: https://github.com/TSRBerry/RyuSOCKS/compare/v0.3.0-alpha...v0.3.1-alpha
[0.3.0-alpha]: https://github.com/TSRBerry/RyuSOCKS/compare/v0.2.0-alpha...v0.3.0-alpha
[0.2.0-alpha]: https://github.com/TSRBerry/RyuSOCKS/compare/v0.1.0-alpha...v0.2.0-alpha
[0.1.0-alpha]: https://github.com/TSRBerry/RyuSOCKS/releases/tag/v0.1.0-alpha

[#16]: https://github.com/TSRBerry/RyuSOCKS/pull/16
