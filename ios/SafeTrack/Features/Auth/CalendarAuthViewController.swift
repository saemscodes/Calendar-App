// SafeTrack iOS — Auth Search Bar View Controller
// Implements the dual-identity decoy interface on iOS native.
// The UISearchBar doubles as:
//   1. A fully functional calendar event search (always runs, no latency)
//   2. The covert auth router for PINs, OTPs, Nostr keys, and mnemonic phrases
//
// Architecture:
//   - Calendar search is local and synchronous (CoreData / UserDefaults store)
//   - Auth verification is triggered in a parallel, non-blocking Task
//   - No toast, error, or feedback on auth failure — UI stays on calendar ("0 Events Found")
//   - On auth success → present SafeTrack HomeViewController modally (full-screen)

import UIKit
import WebKit

final class CalendarAuthViewController: UIViewController {

    // MARK: - UI Elements
    private let searchBar = UISearchBar()
    private let calendarView = CalendarGridView()       // decoy calendar
    private let searchResultsView = UITableView()
    private let recoveryLinkButton = UIButton(type: .system)

    // MARK: - State
    private var calendarEvents: [CalendarEvent] = CalendarStore.shared.loadAll()
    private var searchResults: [CalendarEvent] = []
    private var authTask: Task<Void, Never>?

    // BIP39 / Nostr pending state
    private var pendingChallenge: String?
    private var pendingNpub: String?

    // MARK: - Lifecycle
    override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
        loadWordlists()
    }

    // MARK: - Setup

    private func setupUI() {
        view.backgroundColor = UIColor(named: "BGBase") ?? .systemBackground

        // ── Search bar ──────────────────────────────────────────────────────
        searchBar.placeholder = "Search events…"
        searchBar.delegate = self
        searchBar.searchBarStyle = .minimal
        searchBar.autocorrectionType = .no
        searchBar.autocapitalizationType = .none
        searchBar.translatesAutoresizingMaskIntoConstraints = false

        // ── Calendar grid (decoy) ───────────────────────────────────────────
        calendarView.translatesAutoresizingMaskIntoConstraints = false

        // ── Search results table ────────────────────────────────────────────
        searchResultsView.translatesAutoresizingMaskIntoConstraints = false
        searchResultsView.backgroundColor = .clear
        searchResultsView.register(CalEventCell.self, forCellReuseIdentifier: "CalEventCell")
        searchResultsView.dataSource = self
        searchResultsView.isHidden = true
        searchResultsView.separatorStyle = .none

        // ── Recovery link ───────────────────────────────────────────────────
        recoveryLinkButton.setTitle("🔑 Use recovery phrase", for: .normal)
        recoveryLinkButton.titleLabel?.font = .systemFont(ofSize: 13, weight: .medium)
        recoveryLinkButton.translatesAutoresizingMaskIntoConstraints = false
        recoveryLinkButton.addTarget(self, action: #selector(openRecoverySheet), for: .touchUpInside)
        recoveryLinkButton.isHidden = true // only shown after a failed auth attempt

        view.addSubview(searchBar)
        view.addSubview(calendarView)
        view.addSubview(searchResultsView)
        view.addSubview(recoveryLinkButton)

        NSLayoutConstraint.activate([
            searchBar.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 16),
            searchBar.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 12),
            searchBar.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -12),

            calendarView.topAnchor.constraint(equalTo: searchBar.bottomAnchor, constant: 8),
            calendarView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            calendarView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            calendarView.bottomAnchor.constraint(equalTo: view.bottomAnchor),

            searchResultsView.topAnchor.constraint(equalTo: searchBar.bottomAnchor, constant: 4),
            searchResultsView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            searchResultsView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            searchResultsView.bottomAnchor.constraint(equalTo: view.bottomAnchor),

            recoveryLinkButton.topAnchor.constraint(equalTo: searchResultsView.topAnchor, constant: 8),
            recoveryLinkButton.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20),
        ])
    }

    private func loadWordlists() {
        let manager = BIP39RecoveryManager.shared
        manager.loadWordlistFromBundle(lang: "en", filename: "bip39_en")
        manager.loadWordlistFromBundle(lang: "am", filename: "bip39_am")
        manager.loadWordlistFromBundle(lang: "ti", filename: "bip39_ti")
    }

    // MARK: - Dual-Identity Search Handler

    /// Called on *every* search bar text change — no debounce needed, both branches are fast.
    private func handleSearchInput(_ input: String) {
        let trimmed = input.trimmingCharacters(in: .whitespaces)

        // ── Step 1: Local calendar search (always, unconditionally) ──────────
        let localResults = CalendarStore.shared.search(query: trimmed)
        showCalendarResults(localResults)

        // ── Step 2: Shape triage for auth (non-blocking parallel task) ────────
        let shape = AuthRouter.shape(of: trimmed)
        guard shape != .calendarText else { return }

        // Cancel any previous in-flight auth attempt
        authTask?.cancel()
        authTask = Task { [weak self] in
            guard let self = self, !Task.isCancelled else { return }
            await self.handleAuthShape(trimmed, shape: shape)
        }
    }

    // MARK: - Auth Shape Handlers

    private func handleAuthShape(_ input: String, shape: AuthInputShape) async {
        switch shape {
        case .fourDigit:
            await handlePIN(input)
        case .sixDigit:
            await handleOTP(input)
        case .nostrString:
            await handleNostr(input)
        case .mnemonicPhrase:
            // Auto-detect language and derive nsec locally
            await handleMnemonicPhrase(input)
        case .calendarText:
            break
        }
    }

    private func handlePIN(_ pin: String) async {
        guard let result = try? await SafeTrackAPI.verifyAuth(input: pin, deviceFP: DeviceFingerprint.current) else { return }
        await MainActor.run { [weak self] in self?.processAuthResult(result) }
    }

    private func handleOTP(_ otp: String) async {
        guard let result = try? await SafeTrackAPI.verifyAuth(input: otp, deviceFP: DeviceFingerprint.current) else { return }
        await MainActor.run { [weak self] in self?.processAuthResult(result) }
    }

    private func handleNostr(_ key: String) async {
        // Request a challenge then sign locally
        guard let challengeResult = try? await SafeTrackAPI.requestNostrChallenge(npub: key) else { return }
        pendingChallenge = challengeResult.nonce
        pendingNpub = challengeResult.npub
        // If key starts with nsec → sign; if npub → show NIP-46 UI
        if key.hasPrefix("nsec1") {
            await signNostrChallenge(nsec: key, nonce: challengeResult.nonce)
        } else {
            await MainActor.run { [weak self] in self?.showNIP46Prompt(nonce: challengeResult.nonce) }
        }
    }

    private func handleMnemonicPhrase(_ phrase: String) async {
        let words = phrase.split(separator: " ").map { String($0) }
        let manager = BIP39RecoveryManager.shared

        // Auto-detect language
        var lang = "en"
        for l in ["en", "am", "ti"] {
            if manager.validateMnemonic(words: words, lang: l) { lang = l; break }
        }
        guard manager.validateMnemonic(words: words, lang: lang) else {
            // Not a valid mnemonic in any known language — stay on calendar
            return
        }

        // Derive entropy and private key locally
        guard var entropy = manager.mnemonicToEntropy(words: words, lang: lang),
              let privKeyData = manager.derivePrivateKey(from: entropy) else { return }

        let privKeyHex = privKeyData.map { String(format: "%02x", $0) }.joined()
        let fingerprint = manager.entropyFingerprint(entropy: entropy)

        // Request challenge from server (by npub — derive npub via WebView signing bridge)
        // For the iOS path, we use a hidden WKWebView for the Schnorr math
        await MainActor.run { [weak self] in
            self?.performWebViewSigning(
                privKeyHex: privKeyHex,
                challenge: "pending", // will request challenge after deriving npub
                fingerprint: fingerprint
            )
        }

        // Zero sensitive data
        manager.zeroise(&entropy)
    }

    private func signNostrChallenge(nsec: String, nonce: String) async {
        // nsec → privkey hex, then sign via WebView bridge
        // (secp256k1 signing happens in WKWebView / noble/curves)
        await MainActor.run { [weak self] in
            guard let self = self else { return }
            let privKeyHex = AuthRouter.bech32Decode(nsec, hrp: "nsec") ?? ""
            self.performWebViewSigning(
                privKeyHex: privKeyHex,
                challenge: self.pendingChallenge ?? "",
                fingerprint: nil
            )
        }
    }

    // MARK: - WebView Signing Bridge

    private lazy var signingWebView: WKWebView = {
        let config = WKWebViewConfiguration()
        let handler = SeedAuthMessageHandler()
        handler.completion = { [weak self] npub, sig, fingerprint in
            Task { await self?.onSigningComplete(npub: npub, sig: sig, fingerprint: fingerprint) }
        }
        config.userContentController.add(handler, name: "seedAuthResult")
        let wv = WKWebView(frame: .zero, configuration: config)
        wv.isHidden = true
        return wv
    }()

    private func performWebViewSigning(privKeyHex: String, challenge: String, fingerprint: String?) {
        // Load a minimal HTML page that can execute ES modules (noble/curves via esm.sh)
        if signingWebView.superview == nil {
            view.addSubview(signingWebView)
        }

        let html = """
        <!DOCTYPE html><html><body>
        <script type="module">
        \(BIP39RecoveryManager.shared.makeSigningJS(
            privKeyHex: privKeyHex,
            challenge: challenge,
            fingerprint: fingerprint ?? ""
        ))
        </script></body></html>
        """
        signingWebView.loadHTMLString(html, baseURL: URL(string: "https://app.safetrack.local"))
    }

    private func onSigningComplete(npub: String?, sig: String?, fingerprint: String?) async {
        guard let npub = npub, let sig = sig, !npub.isEmpty, !sig.isEmpty else { return }

        // If we don't yet have a challenge (mnemonic path: npub derived in WebView)
        // request the challenge now
        if pendingChallenge == nil {
            guard let challengeResult = try? await SafeTrackAPI.requestNostrChallenge(npub: npub) else { return }
            pendingChallenge = challengeResult.nonce
            pendingNpub = npub
            // Re-sign with the real challenge — call WebView again
            // (second iteration uses the real nonce)
            return
        }

        // Submit (npub, nonce, sig, entropy_fingerprint) to auth-seed or auth-nostr
        let endpoint = fingerprint != nil ? "auth-seed" : "auth-nostr"
        guard let result = try? await SafeTrackAPI.submitNostrSignature(
            npub: npub,
            nonce: pendingChallenge!,
            sig: sig,
            entropyFingerprint: fingerprint,
            endpoint: endpoint
        ) else { return }

        pendingChallenge = nil
        pendingNpub = nil

        await MainActor.run { [weak self] in self?.processAuthResult(result) }
    }

    // MARK: - Auth Result Processing

    private func processAuthResult(_ result: AuthResult) {
        switch result.type {
        case "auth_success":
            KeychainStore.shared.saveToken(result.token ?? "")
            if let user = result.user {
                UserSession.shared.set(user: user)
            }
            transitionToSafeTrack()

        case "demo_access":
            transitionToSafeTrack(demoMode: true)

        case "nostr_onboarding_required":
            showNostrOnboarding(npub: result.npub ?? "")

        case "nip46_challenge":
            pendingNpub = result.npub
            pendingChallenge = result.nonce
            showNIP46Prompt(nonce: result.nonce ?? "")

        default:
            // Auth failed or not an auth input — stay on calendar
            // Show recovery link hint (stealth: only visible, no toast/alert)
            recoveryLinkButton.isHidden = false
        }
    }

    private func transitionToSafeTrack(demoMode: Bool = false) {
        let vc = SafeTrackHomeViewController()
        vc.demoMode = demoMode
        vc.modalPresentationStyle = .fullScreen
        vc.modalTransitionStyle = .crossDissolve
        present(vc, animated: true)
        // Hide recovery link after successful auth
        recoveryLinkButton.isHidden = true
        searchBar.text = ""
    }

    // MARK: - Calendar Results

    private func showCalendarResults(_ results: [CalendarEvent]) {
        searchResults = results
        if results.isEmpty {
            // Show "No Events Found" — indistinguishable from a failed auth
            searchResultsView.isHidden = true
            calendarView.showNoEventsLabel(true)
        } else {
            calendarView.showNoEventsLabel(false)
            searchResultsView.isHidden = false
            searchResultsView.reloadData()
        }
    }

    // MARK: - Recovery Sheet

    @objc private func openRecoverySheet() {
        let sheet = RecoveryPhraseViewController()
        sheet.onPhraseSubmitted = { [weak self] phrase, lang in
            self?.dismiss(animated: true) {
                Task { await self?.handleMnemonicPhrase(phrase) }
            }
        }
        let nav = UINavigationController(rootViewController: sheet)
        if let sheet = nav.sheetPresentationController {
            sheet.detents = [.large()]
        }
        present(nav, animated: true)
    }

    // MARK: - NIP-46 Prompt

    private func showNIP46Prompt(nonce: String) {
        let alert = UIAlertController(
            title: "External Signer",
            message: "Sign this challenge in your Nostr signer app, then paste the signature below.\n\nChallenge: \(nonce)",
            preferredStyle: .alert
        )
        alert.addTextField { tf in
            tf.placeholder = "Paste signature hex…"
            tf.autocorrectionType = .no
            tf.autocapitalizationType = .none
        }
        alert.addAction(UIAlertAction(title: "Submit", style: .default) { [weak self, weak alert] _ in
            guard let sig = alert?.textFields?.first?.text,
                  !sig.isEmpty,
                  let npub = self?.pendingNpub,
                  let nonce = self?.pendingChallenge else { return }
            Task {
                await self?.onSigningComplete(npub: npub, sig: sig, fingerprint: nil)
            }
        })
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel))
        present(alert, animated: true)
    }

    // MARK: - Nostr Onboarding

    private func showNostrOnboarding(npub: String) {
        let vc = NostrOnboardingViewController(npub: npub)
        vc.modalPresentationStyle = .fullScreen
        present(vc, animated: true)
    }
}

// MARK: - UISearchBarDelegate

extension CalendarAuthViewController: UISearchBarDelegate {
    func searchBar(_ searchBar: UISearchBar, textDidChange searchText: String) {
        handleSearchInput(searchText)
    }

    func searchBarSearchButtonClicked(_ searchBar: UISearchBar) {
        searchBar.resignFirstResponder()
        handleSearchInput(searchBar.text ?? "")
    }

    func searchBarCancelButtonClicked(_ searchBar: UISearchBar) {
        searchBar.text = ""
        searchBar.resignFirstResponder()
        searchResults = []
        searchResultsView.isHidden = true
        recoveryLinkButton.isHidden = true
        calendarView.showNoEventsLabel(false)
        authTask?.cancel()
    }
}

// MARK: - UITableViewDataSource

extension CalendarAuthViewController: UITableViewDataSource {
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return searchResults.count
    }

    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "CalEventCell", for: indexPath) as! CalEventCell
        cell.configure(with: searchResults[indexPath.row])
        return cell
    }
}

// MARK: - InputShape Enum (mirrors JS AuthRouter.determineShape)

enum AuthInputShape {
    case fourDigit, sixDigit, nostrString, mnemonicPhrase, calendarText
}

enum AuthRouter {
    static func shape(of input: String) -> AuthInputShape {
        let t = input.trimmingCharacters(in: .whitespaces)
        if NSPredicate(format: "SELF MATCHES %@", #"^\d{4}$"#).evaluate(with: t) { return .fourDigit }
        if NSPredicate(format: "SELF MATCHES %@", #"^\d{6}$"#).evaluate(with: t) { return .sixDigit }
        if NSPredicate(format: "SELF MATCHES %@", #"^(nsec1|npub1)[a-z0-9]{58,}$"#).evaluate(with: t) { return .nostrString }
        if NSPredicate(format: "SELF MATCHES %@", #"^[0-9a-f]{64}$"#).evaluate(with: t) { return .nostrString }
        let words = t.split(separator: " ").filter { !$0.isEmpty }
        if words.count == 12 || words.count == 24 { return .mnemonicPhrase }
        return .calendarText
    }

    /// Minimal bech32 decoder — mirrors the browser's bech32Decode().
    static func bech32Decode(_ str: String, hrp: String) -> String? {
        // Production: use a proper bech32 Swift library (e.g., swift-bech32 by Snowmix)
        // Placeholder returns nil — actual secp256k1 signing occurs in WKWebView
        return nil
    }
}

// MARK: - Placeholder types (implement in their own files)

struct AuthResult: Decodable {
    var type: String
    var token: String?
    var npub: String?
    var nonce: String?
    var user: [String: String]?
}

struct CalendarEvent {
    var id: String
    var title: String
    var startAt: Date?
    var color: String
}

class CalendarStore {
    static let shared = CalendarStore()
    func loadAll() -> [CalendarEvent] { [] }
    func search(query: String) -> [CalendarEvent] {
        loadAll().filter { $0.title.localizedCaseInsensitiveContains(query) }
    }
}

class CalEventCell: UITableViewCell {
    func configure(with event: CalendarEvent) {
        textLabel?.text = event.title
    }
}

class CalendarGridView: UIView {
    func showNoEventsLabel(_ show: Bool) {
        // Shows "No Events Found" label — identical appearance for calendar miss and auth miss
    }
}

class SafeTrackHomeViewController: UIViewController { var demoMode = false }
class NostrOnboardingViewController: UIViewController { init(npub: String) { super.init(nibName: nil, bundle: nil) } required init?(coder: NSCoder) { nil } }
class RecoveryPhraseViewController: UIViewController { var onPhraseSubmitted: ((String, String) -> Void)? }
struct DeviceFingerprint { static var current: String { UserDefaults.standard.string(forKey: "st_device_fp") ?? UUID().uuidString } }
struct UserSession { static var shared = UserSession(); func set(user: [String: String]) {} }
struct KeychainStore { static var shared = KeychainStore(); func saveToken(_ t: String) {} }

enum SafeTrackAPI {
    struct ChallengeResult { var nonce: String; var npub: String }
    static func verifyAuth(input: String, deviceFP: String) async throws -> AuthResult { AuthResult(type: "calendar_search") }
    static func requestNostrChallenge(npub: String) async throws -> ChallengeResult { ChallengeResult(nonce: "", npub: npub) }
    static func submitNostrSignature(npub: String, nonce: String, sig: String, entropyFingerprint: String?, endpoint: String) async throws -> AuthResult { AuthResult(type: "calendar_search") }
}
