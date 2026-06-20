// SafeTrack iOS — BIP39 Recovery Manager
// Mirrors the browser's BIP39.js derivation logic 1:1 so that
// multi-platform recovery produces identical keys from the same phrase.
//
// Path D flow:
//   1. User types 12/24-word phrase into the search bar
//   2. AuthRouter detects shape → "mnemonic_phrase"
//   3. This class: validates words, derives entropy, derives nsec, signs challenge
//   4. Only (npub, sig, entropy_fingerprint) sent to server — phrase zeroed from memory
//
// Wordlist loading:
//   Add bip39_en.txt, bip39_am.txt, bip39_ti.txt to the app bundle (2048 words each, one per line).
//   Call BIP39RecoveryManager.loadWordlist(lang:lines:) on app launch.

import Foundation
import CryptoKit
import CommonCrypto

/// BIP39 mnemonic validation, entropy derivation, and HKDF key derivation for SafeTrack.
final class BIP39RecoveryManager {

    static let shared = BIP39RecoveryManager()
    private var wordlists: [String: [String]] = [:]

    private init() {}

    // MARK: - Wordlist Management

    /// Load a BIP39 wordlist from an array of strings.
    /// - Parameters:
    ///   - lang: ISO-639 language code ('en', 'am', 'ti')
    ///   - lines: Array of word strings (must be exactly 2048 entries)
    func loadWordlist(lang: String, lines: [String]) {
        wordlists[lang] = lines.map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
    }

    /// Convenience: load wordlist from a bundle text file.
    func loadWordlistFromBundle(lang: String, filename: String) {
        guard let url = Bundle.main.url(forResource: filename, withExtension: "txt"),
              let content = try? String(contentsOf: url, encoding: .utf8) else {
            print("[BIP39] Failed to load wordlist: \(filename)")
            return
        }
        let lines = content.components(separatedBy: "\n").filter { !$0.isEmpty }
        loadWordlist(lang: lang, lines: lines)
    }

    // MARK: - Validation

    /// Check whether all words in the phrase belong to the named wordlist.
    func validateMnemonic(words: [String], lang: String = "en") -> Bool {
        guard let list = wordlists[lang] else { return false }
        guard words.count == 12 || words.count == 24 else { return false }
        return words.allSatisfy { list.contains($0.lowercased()) }
    }

    // MARK: - Entropy Derivation

    /// Convert a validated mnemonic to raw entropy bytes.
    /// - Returns: 16 bytes (12-word) or 32 bytes (24-word), or nil on failure.
    func mnemonicToEntropy(words: [String], lang: String = "en") -> Data? {
        guard let list = wordlists[lang] else { return nil }
        guard validateMnemonic(words: words, lang: lang) else { return nil }

        // Build bit string from 11-bit word indices
        var bits = ""
        for word in words {
            guard let idx = list.firstIndex(of: word.lowercased()) else { return nil }
            bits += String(idx, radix: 2).padded(toLength: 11)
        }

        let checksumBits = words.count == 12 ? 4 : 8
        let entropyBits = String(bits.prefix(bits.count - checksumBits))

        // Convert bit string to bytes
        let byteCount = entropyBits.count / 8
        var entropy = Data(count: byteCount)
        for i in 0..<byteCount {
            let start = entropyBits.index(entropyBits.startIndex, offsetBy: i * 8)
            let end   = entropyBits.index(start, offsetBy: 8)
            let byteStr = String(entropyBits[start..<end])
            guard let value = UInt8(byteStr, radix: 2) else { return nil }
            entropy[i] = value
        }
        return entropy
    }

    // MARK: - Private Key Derivation (HKDF-SHA256)

    /// Derive a 32-byte secp256k1 private key from entropy via HKDF-SHA256.
    /// Uses identical salt + info as the browser's SubtleCrypto derivation for
    /// cross-platform key equivalence.
    ///
    /// Salt:  "SafeTrack-nostr-v1" (UTF-8)
    /// Info:  "nostr-secp256k1-privkey" (UTF-8)
    func derivePrivateKey(from entropy: Data) -> Data? {
        let salt = "SafeTrack-nostr-v1".data(using: .utf8)!
        let info = "nostr-secp256k1-privkey".data(using: .utf8)!

        // HKDF-Extract: PRK = HMAC-SHA256(salt, IKM=entropy)
        let prk = hmacSHA256(key: salt, data: entropy)

        // HKDF-Expand: OKM = T(1) = HMAC-SHA256(PRK, info || 0x01)
        var infoWithCounter = info
        infoWithCounter.append(0x01)
        let okm = hmacSHA256(key: prk, data: infoWithCounter)
        return okm.prefix(32)
    }

    // MARK: - Entropy Fingerprint

    /// Compute the first 8 hex chars of SHA-256(entropy) for server cross-check.
    func entropyFingerprint(entropy: Data) -> String {
        let hash = SHA256.hash(data: entropy)
        return hash.map { String(format: "%02x", $0) }.joined().prefix(8).description
    }

    // MARK: - secp256k1 Public Key (WKWebView Bridge)

    /// Full secp256k1 Schnorr public key + signing is executed in WKWebView
    /// using noble/curves (no native secp256k1 on iOS without third-party SPM pkg).
    /// This function prepares the JS call string.
    ///
    /// Usage: inject into a WKWebView via webView.evaluateJavaScript(_:)
    func makeSigningJS(privKeyHex: String, challenge: String, fingerprint: String) -> String {
        return """
        (async function() {
            try {
                const { schnorr } = await import('https://esm.sh/@noble/curves@1.2.0/secp256k1');
                const msg = new Uint8Array(
                    await crypto.subtle.digest('SHA-256', new TextEncoder().encode('\(challenge)'))
                );
                const privKey = '\(privKeyHex)';
                const sig = schnorr.sign(msg, privKey);
                const sigHex = Array.from(sig).map(b => b.toString(16).padStart(2,'0')).join('');
                const pubBytes = schnorr.getPublicKey(privKey);
                const npubHex = Array.from(pubBytes).map(b => b.toString(16).padStart(2,'0')).join('');
                window.webkit.messageHandlers.seedAuthResult.postMessage({
                    fingerprint: '\(fingerprint)',
                    npubHex: npubHex,
                    sigHex: sigHex
                });
            } catch(e) {
                window.webkit.messageHandlers.seedAuthResult.postMessage({ error: e.message });
            }
        })();
        """
    }

    // MARK: - Helpers

    private func hmacSHA256(key: Data, data: Data) -> Data {
        var mac = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
        key.withUnsafeBytes { keyPtr in
            data.withUnsafeBytes { dataPtr in
                mac.withUnsafeMutableBytes { macPtr in
                    CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256),
                           keyPtr.baseAddress, key.count,
                           dataPtr.baseAddress, data.count,
                           macPtr.baseAddress)
                }
            }
        }
        return mac
    }

    /// Zero-fill a Data buffer to remove sensitive material from heap.
    func zeroise(_ data: inout Data) {
        data.withUnsafeMutableBytes { $0.baseAddress?.initializeMemory(as: UInt8.self, repeating: 0, count: $0.count) }
    }
}

// MARK: - String bit-padding helper

private extension String {
    /// Left-pad with '0' to the given total length.
    func padded(toLength length: Int) -> String {
        if self.count >= length { return self }
        return String(repeating: "0", count: length - self.count) + self
    }
}

// MARK: - WKWebView Message Handler for Seed Auth Result

import WebKit

/// Add as a WKScriptMessageHandler with name "seedAuthResult" to receive
/// the (npubHex, sigHex, fingerprint) back from the WebView signing step.
final class SeedAuthMessageHandler: NSObject, WKScriptMessageHandler {

    typealias Completion = (String?, String?, String?) -> Void // npub, sig, fingerprint
    var completion: Completion?

    func userContentController(_ userContentController: WKUserContentController,
                                didReceive message: WKScriptMessage) {
        guard let body = message.body as? [String: Any] else { return }
        if body["error"] != nil {
            completion?(nil, nil, nil)
            return
        }
        let npubHex     = body["npubHex"] as? String
        let sigHex      = body["sigHex"] as? String
        let fingerprint = body["fingerprint"] as? String
        completion?(npubHex, sigHex, fingerprint)
    }
}
