/// Validates the server's presented certificate by deriving its SPKI hash
/// and comparing it against a locally pinned expected value.
///
/// Security model:
/// - trust is granted only if the derived SPKI hash matches the pinned hash
/// - default TLS validation alone is not treated as sufficient for this check
/// - this component does not validate application-level authorization or client integrity
///
import Foundation
import Alamofire
import Security
import CryptoKit

final class SPKIHashTrustEvaluator: ServerTrustEvaluating {
    /// Base64-encoded SHA-256 hash of the expected Subject Public Key Info (SPKI).
    /// This is the local pin used to validate the server certificate.
    private let pinnedSPKIHash = "BASE64_ENCODED_SPKI_HASH"

    func evaluate(_ trust: SecTrust, forHost host: String) throws {

        guard
            let certificateChain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
            let certificate = certificateChain.first
        else {
            throw AFError.serverTrustEvaluationFailed(reason: .noCertificatesFound)
        }

        print("🧾 Host:", host)
        print("🧾 Leaf subject:", SecCertificateCopySubjectSummary(certificate) as String? ?? "nil")
        print("🧾 Leaf SHA256 fingerprint:", sha256Fingerprint(of: certificate))

        let pin = try spkiPin(from: certificate)

        print("🔐 Server SPKI:", pin)
        print("🔐 Expected SPKI:", pinnedSPKIHash)

        guard pin == pinnedSPKIHash else {
            print("❌ SPKI MISMATCH — BLOCKING CONNECTION")
            throw AFError.serverTrustEvaluationFailed(
                reason: .customEvaluationFailed(error: PinningError.pinMismatch)
            )
        }

        print("✅ SPKI MATCH — CONNECTION ALLOWED")
    }

    private func spkiPin(from certificate: SecCertificate) throws -> String {
        guard let publicKey = SecCertificateCopyKey(certificate) else {
            throw PinningError.publicKeyExtractionFailed
        }

        var error: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw PinningError.externalRepresentationFailed
        }

        guard let attributes = SecKeyCopyAttributes(publicKey) else {
            throw PinningError.unsupportedKeyType
        }

        let keyAttributes = attributes as NSDictionary
        guard let keyType = keyAttributes[kSecAttrKeyType] as? String else {
            throw PinningError.unsupportedKeyType
        }

        let spkiData: Data
        let rsaKeyType = kSecAttrKeyTypeRSA as String
        let ecKeyType = kSecAttrKeyTypeECSECPrimeRandom as String

        switch keyType {
        case rsaKeyType:
            spkiData = buildRSASPKI(from: publicKeyData)
        case ecKeyType:
            spkiData = buildECSPKI(from: publicKeyData)
        default:
            throw PinningError.unsupportedKeyType
        }

        let digest = SHA256.hash(data: spkiData)
        return Data(digest).base64EncodedString()
    }

    private func buildRSASPKI(from rawKey: Data) -> Data {
        let rsaAlgorithmIdentifier: [UInt8] = [
            0x30, 0x0D,
            0x06, 0x09,
            0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
            0x05, 0x00
        ]

        let bitString = derEncodeBitString(rawKey)
        let body = Data(rsaAlgorithmIdentifier) + bitString
        return derEncodeSequence(body)
    }

    private func buildECSPKI(from rawKey: Data) -> Data {
        let ecAlgorithmIdentifier: [UInt8] = [
            0x30, 0x13,
            0x06, 0x07,
            0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
            0x06, 0x08,
            0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
        ]

        let bitString = derEncodeBitString(rawKey)
        let body = Data(ecAlgorithmIdentifier) + bitString
        return derEncodeSequence(body)
    }

    private func derEncodeSequence(_ content: Data) -> Data {
        Data([0x30]) + derEncodeLength(content.count) + content
    }

    private func derEncodeBitString(_ content: Data) -> Data {
        let prefixed = Data([0x00]) + content
        return Data([0x03]) + derEncodeLength(prefixed.count) + prefixed
    }

    private func derEncodeLength(_ length: Int) -> Data {
        if length < 0x80 {
            return Data([UInt8(length)])
        }

        var value = length
        var bytes: [UInt8] = []

        while value > 0 {
            bytes.insert(UInt8(value & 0xFF), at: 0)
            value >>= 8
        }

        return Data([0x80 | UInt8(bytes.count)]) + Data(bytes)
    }

    enum PinningError: Error {
        case pinMismatch
        case publicKeyExtractionFailed
        case externalRepresentationFailed
        case unsupportedKeyType
    }
}

func sha256Fingerprint(of cert: SecCertificate) -> String {
    let data = SecCertificateCopyData(cert) as Data
    let hash = SHA256.hash(data: data)
    return hash.map { String(format: "%02X", $0) }.joined(separator: ":")
}
