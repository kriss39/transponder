// The Secure Enclave of an Apple-silicon Mac (or an iPhone) as a Transponder
// signer, through CryptoKit. Exposed to C with @_cdecl; see
// trp_secure_enclave.h for the C side.
//
// The private key never leaves the enclave. CryptoKit hands out an opaque
// blob (`dataRepresentation`) that only this device's enclave can turn back
// into a usable key, so it can be stored in a plain file. CryptoKit signs
// SHA-256 of the input, so the signer reports pre_hash = 1.

import CryptoKit
import Foundation

private let ok: Int32 = 0
private let errBuffer: Int32 = -1
private let errInvalid: Int32 = -2
private let errUnsupported: Int32 = -3
private let errCrypto: Int32 = -4

private func restore(_ blob: UnsafePointer<UInt8>, _ len: Int) throws -> SecureEnclave.P256.Signing.PrivateKey {
    try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: Data(bytes: blob, count: len))
}

/// Create a key in the enclave. Writes the blob and the 64-byte public key (x || y).
@_cdecl("trp__enclave_create")
public func trpEnclaveCreate(
    _ blob: UnsafeMutablePointer<UInt8>, _ blobCap: Int, _ blobLen: UnsafeMutablePointer<Int>,
    _ publicKey: UnsafeMutablePointer<UInt8>
) -> Int32 {
    guard SecureEnclave.isAvailable else { return errUnsupported }
    do {
        let key = try SecureEnclave.P256.Signing.PrivateKey()
        let data = key.dataRepresentation
        guard data.count <= blobCap else { return errBuffer }
        data.copyBytes(to: blob, count: data.count)
        blobLen.pointee = data.count
        key.publicKey.rawRepresentation.copyBytes(to: publicKey, count: 64)
        return ok
    } catch {
        return errCrypto
    }
}

/// The 64-byte public key (x || y) of a stored blob.
@_cdecl("trp__enclave_public_key")
public func trpEnclavePublicKey(
    _ blob: UnsafePointer<UInt8>, _ blobLen: Int, _ publicKey: UnsafeMutablePointer<UInt8>
) -> Int32 {
    guard SecureEnclave.isAvailable else { return errUnsupported }
    guard let key = try? restore(blob, blobLen) else { return errInvalid }
    key.publicKey.rawRepresentation.copyBytes(to: publicKey, count: 64)
    return ok
}

/// Sign SHA-256(digest) with the key in the enclave; writes r and s (32 bytes each).
@_cdecl("trp__enclave_sign")
public func trpEnclaveSign(
    _ blob: UnsafePointer<UInt8>, _ blobLen: Int, _ digest: UnsafePointer<UInt8>,
    _ r: UnsafeMutablePointer<UInt8>, _ s: UnsafeMutablePointer<UInt8>
) -> Int32 {
    guard SecureEnclave.isAvailable else { return errUnsupported }
    do {
        let key = try restore(blob, blobLen)
        let raw = try key.signature(for: Data(bytes: digest, count: 32)).rawRepresentation
        guard raw.count == 64 else { return errCrypto }
        raw.prefix(32).copyBytes(to: r, count: 32)
        raw.suffix(32).copyBytes(to: s, count: 32)
        return ok
    } catch {
        return errCrypto
    }
}
