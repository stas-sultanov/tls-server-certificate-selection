
# Kestrel TLS Server Certificate Selection

This repository demonstrates how an ASP.NET web server (Kestrel) can dynamically select and present different server certificates during the TLS handshake, based on the client's supported authentication algorithms.

## Background

According to [RFC 8446][rfc_8446], during the TLS handshake the client provides information about which server authentication algorithms it supports.

The exact location of the information needed for certificate selection depends on the TLS version:

| Version | Primary Source | Secondary Source
|:-------:|----------------|----------
| 1.2     | `signature_algorithms` extension | `cipher_suites` field
| 1.3     | `signature_algorithms_cert` extension | `signature_algorithms` extension

## How It Works

- **Kestrel exposes two key APIs:**
  - [TlsClientHelloBytesCallback][ms_learn_tlsclienthellobytescallback]: Fires when a `ClientHello` is received, providing raw TLS record bytes.
  - [ServerCertificateSelector][ms_learn_servercertificateselector]: Invoked before TLS negotiation completes, returns the certificate to use.
- The [`TlsClientHelloParser`][code_TlsClientHelloParser] parses the TLS record and extracts information from `ClientHello`.

### Flow

1. A method subscribed to [TlsClientHelloBytesCallback][ms_learn_tlsclienthellobytescallback] calls [`TryParse`][code_TryParse] and stores the parsed signature algorithms (see [`TlsSignatureScheme`][code_TlsSignatureScheme]) in the [ConnectionContext][ms_learn_ConnectionContext].
2. A method subscribed to [ServerCertificateSelector][ms_learn_servercertificateselector] reads the signature algorithms from [ConnectionContext][ms_learn_ConnectionContext].
3. If the client supports ECDSA, the server returns the ECDSA certificate; otherwise, if RSA is supported, it returns the RSA certificate.


## Project Structure

```bash
# Project root
.
├── src/                           # Source code root
│   └── System.Utils/              # Main library project
│       └── code/
│           ├── Buffers/           # Buffer utilities
│           └── Net/
│               └── Security/      # TLS
├── tests/                         # Test code root
│   └── System.Utils.Tests/        # Test project
│       └── code/
│           ├── UnitTests/         # Unit tests for core logic
│           └── IntegrationTests/  # Integration tests
└── demo.slnx                      # Solution file
```

## Prerequisites

To build and run tests on Windows:

- WSL with a Linux distribution
- [.NET 10 SDK][dotnet_10_sdk]
- VS Code with:
  - **Remote – WSL** (`ms-vscode-remote.remote-wsl`)
  - **C# Dev Kit** (`ms-dotnettools.csdevkit`)

---

[rfc_8446]: https://www.rfc-editor.org/rfc/rfc8446
[rfc_8446_clienthello]: https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2
[rfc_8446_extensions]: https://www.rfc-editor.org/rfc/rfc8446#section-4.2
[rfc_8446_signature_scheme_list]: https://www.rfc-editor.org/rfc/rfc8446#section-4.2.3
[dotnet_10_sdk]: https://dotnet.microsoft.com/download/dotnet/10.0
[ms_learn_tlsclienthellobytescallback]: https://learn.microsoft.com/dotnet/api/microsoft.aspnetcore.server.kestrel.https.httpsconnectionadapteroptions.tlsclienthellobytescallback?view=aspnetcore-10.0
[ms_learn_servercertificateselector]: https://learn.microsoft.com/dotnet/api/microsoft.aspnetcore.server.kestrel.https.httpsconnectionadapteroptions.servercertificateselector
[ms_learn_ConnectionContext]: https://learn.microsoft.com/dotnet/api/microsoft.aspnetcore.connections.connectioncontext?view=aspnetcore-10.0

[code_TlsClientHelloParser]: ./src/System.Utils/code/Net/Security/TlsClientHelloParser.cs
[code_TlsSignatureScheme]: ./src/System.Utils/code/Net/Security/TlsSignatureScheme.cs
[code_TryParse]: ./src/System.Utils/code/Net/Security/TlsClientHelloParser.cs
