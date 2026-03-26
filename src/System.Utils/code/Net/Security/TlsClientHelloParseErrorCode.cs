// Authored by Stas Sultanov
// Copyright © Stas Sultanov

namespace System.Net.Security;

/// <summary>
/// Defines error code groups for the <see cref="TlsClientHelloParseErrorCode"/> enum.
/// </summary>
file static class ErrorCodeGroup
{
	public const Int32 Data               = 0x0100;
	public const Int32 Record             = 0x0200;
	public const Int32 Handshake          = 0x0300;
	public const Int32 ClientHello        = 0x0400;
	public const Int32 Extension          = 0x0500;
	public const Int32 SignatureAlgorithm = 0x0600;
}

/// <summary>
/// Defines error codes for the <see cref="TlsClientHelloParser.TryParse"/> method.
/// </summary>
public enum TlsClientHelloParseErrorCode
{
	/// <summary>
	/// No error occurred.
	/// </summary>
	None = 0x0000,

	/// <summary>
	/// An error occurred while reading the data.
	/// </summary>
	ReadError = 0x0001,

	/// <summary>
	/// The input data is empty, so there is no TLS record to parse.
	/// </summary>
	Data_IsEmpty = ErrorCodeGroup.Data | 0x01,

	/// <summary>
	/// The input data.length is invalid.
	/// </summary>
	Data_Length_IsInvalid = ErrorCodeGroup.Data | 0x02,

	/// <summary>
	/// The TLSPlaintext.length field value is invalid.
	/// </summary>
	TLSPlaintextField_Length_IsInvalid = ErrorCodeGroup.Record | 0x01,

	/// <summary>
	/// The TLSPlaintext.type field value is invalid.
	/// </summary>
	TLSPlaintextField_Type_IsInvalid = ErrorCodeGroup.Record | 0x02,

	/// <summary>
	/// The Handshake.msg_type field value is invalid.
	/// </summary>
	Handshake_MessageType_IsInvalid = ErrorCodeGroup.Handshake | 0x01,

	/// <summary>
	/// The Handshake.length field value is invalid.
	/// </summary>
	Handshake_Length_IsInvalid = ErrorCodeGroup.Handshake | 0x02,

	/// <summary>
	/// The ClientHello.legacy_session_id.length is invalid.
	/// </summary>
	ClientHello_LegacySessionId_LengthIsInvalid = ErrorCodeGroup.ClientHello | 0x01,

	/// <summary>
	/// The ClientHello.cipher_suites.length is invalid.
	/// </summary>
	ClientHello_CipherSuites_LengthIsInvalid = ErrorCodeGroup.ClientHello | 0x02,

	/// <summary>
	/// The ClientHello.legacy_compression_methods.length is invalid.
	/// </summary>
	ClientHello_LegacyCompressionMethods_LengthIsInvalid = ErrorCodeGroup.ClientHello | 0x03,

	/// <summary>
	/// The ClientHello.extensions.length is invalid.
	/// </summary>
	ClientHello_Extensions_LengthIsInvalid = ErrorCodeGroup.ClientHello | 0x04,

	/// <summary>
	/// The Extension.extension_data.length is invalid.
	/// </summary>
	Extension_ExtensionData_LengthIsInvalid = ErrorCodeGroup.Extension | 0x01,

	/// <summary>
	/// The SignatureSchemeList.supported_signature_algorithms.length is invalid.
	/// </summary>
	SignatureSchemeList_SupportedSignatureAlgorithms_LengthIsInvalid = ErrorCodeGroup.SignatureAlgorithm | 0x11,

	/// <summary>
	/// The SignatureSchemeList.supported_signature_algorithms.data is malformed.
	/// </summary>
	SignatureSchemeList_SupportedSignatureAlgorithms_DataIsMalformed = ErrorCodeGroup.SignatureAlgorithm | 0x12
}
