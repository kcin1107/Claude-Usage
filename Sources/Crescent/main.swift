import AppKit
import ServiceManagement
import WebKit
import os

let log = Logger(subsystem: "local.crescent", category: "usage")

// MARK: - Keychain (via /usr/bin/security, the same way Claude Code reads/writes it)

let keychainService = "Claude Code-credentials"

@discardableResult
func security(_ args: [String], timeout: TimeInterval = 10) -> (ok: Bool, out: String, status: Int32?) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/bin/security")
    p.arguments = args
    let pipe = Pipe()
    p.standardOutput = pipe
    p.standardError = FileHandle.nullDevice
    guard (try? p.run()) != nil else { return (false, "", nil) }
    // `security` has been seen to hang on some macOS builds; don't let it block us forever.
    let deadline = Date().addingTimeInterval(timeout)
    while p.isRunning && Date() < deadline { usleep(50_000) }
    if p.isRunning {
        p.terminate()
        log.error("security \(args[0], privacy: .public) timed out")
        return (false, "", nil)
    }
    let out = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    return (p.terminationStatus == 0, out.trimmingCharacters(in: .whitespacesAndNewlines), p.terminationStatus)
}

enum CredentialRead {
    case found([String: Any]), missing, failed
}

func readCredentials() -> CredentialRead {
    let r = security(["find-generic-password", "-s", keychainService, "-a", NSUserName(), "-w"])
    if r.status == 44 { return .missing }  // errSecItemNotFound from the security CLI.
    guard r.ok, let data = r.out.data(using: .utf8),
          let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return .failed }
    return .found(root)
}

/// Returns false if the Keychain write failed. Waits up to 2 minutes, in case macOS is asking for access.
func writeCredentials(_ root: [String: Any]) -> Bool {
    guard let data = try? JSONSerialization.data(withJSONObject: root, options: [.sortedKeys]),
          let json = String(data: data, encoding: .utf8) else { return false }
    let ok = security(["add-generic-password", "-U", "-s", keychainService, "-a", NSUserName(), "-w", json],
                      timeout: 120).ok
    if !ok { log.error("Saving the renewed Claude Code token to the Keychain failed") }
    return ok
}

// MARK: - Token

enum UsageError: Error { case noCredentials, refreshFailed, notSignedIn, http(Int) }

func expiry(_ root: [String: Any]) -> Double {
    ((root["claudeAiOauth"] as? [String: Any])?["expiresAt"] as? Double ?? 0) / 1000
}

/// Hands out Claude Code's access token, renewing it when it has expired.
actor TokenStore {
    static let shared = TokenStore()

    /// Refresh tokens are single-use, so parallel refreshes (timer + menu) share one renewal.
    /// Two renewals with the same refresh token can get the whole login revoked.
    private var renewal: Task<String, Error>?
    /// Renewed credentials that couldn't be saved yet. The server has already rotated the
    /// refresh token, so losing these would log Claude Code out; keep them and retry saving.
    private var unsaved: (source: [String: Any], rotated: [String: Any])?

    func accessToken() async throws -> String {
        if let renewal { return try await renewal.value }

        let stored: [String: Any]
        switch readCredentials() {
        case .found(let root): stored = root
        case .missing:
            unsaved = nil  // Respect a logout instead of recreating the deleted login.
            throw UsageError.noCredentials
        case .failed:
            // Access can fail temporarily (e.g. a locked Keychain). Retain pending tokens,
            // but don't write until we can verify that the original login is still there.
            throw UsageError.noCredentials
        }
        var root: [String: Any]? = stored
        var source = stored
        if let pending = unsaved {
            if NSDictionary(dictionary: stored).isEqual(to: pending.source) {
                if writeCredentials(pending.rotated) {
                    unsaved = nil
                    source = pending.rotated
                }
                root = pending.rotated
            } else {
                unsaved = nil  // Another login replaced the credentials we renewed.
            }
        }
        guard let root, let oauth = root["claudeAiOauth"] as? [String: Any],
              let token = oauth["accessToken"] as? String else { throw UsageError.noCredentials }

        let expiresAt = expiry(root)
        if expiresAt == 0 || expiresAt > Date().timeIntervalSince1970 + 60 { return token }

        let task = Task { () -> String in
            let (newRoot, newToken) = try await renew(root)
            if !writeCredentials(newRoot) { self.unsaved = (source, newRoot) }
            return newToken
        }
        renewal = task
        defer { renewal = nil }
        return try await task.value
    }
}

/// Exchanges the refresh token for new tokens. Returns the updated credentials and the access token.
func renew(_ root: [String: Any]) async throws -> ([String: Any], String) {
    var root = root
    var oauth = root["claudeAiOauth"] as? [String: Any] ?? [:]
    guard let refreshToken = oauth["refreshToken"] as? String else { throw UsageError.refreshFailed }
    var req = URLRequest(url: URL(string: "https://platform.claude.com/v1/oauth/token")!)
    req.httpMethod = "POST"
    req.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
    var form = URLComponents()
    form.queryItems = [
        .init(name: "grant_type", value: "refresh_token"),
        .init(name: "refresh_token", value: refreshToken),
        .init(name: "client_id", value: "9d1c250a-e61b-44d9-88ed-5944d1962f5e"), // Claude Code's public client ID
    ]
    req.httpBody = Data((form.percentEncodedQuery ?? "").utf8)

    let (data, resp) = try await URLSession.shared.data(for: req)
    let status = (resp as? HTTPURLResponse)?.statusCode ?? 0
    guard status == 200,
          let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let newToken = json["access_token"] as? String else {
        // Error responses only describe the problem (e.g. invalid_grant); no tokens in them.
        let body = String(data: data.prefix(300), encoding: .utf8) ?? ""
        log.error("Claude Code token renewal failed: HTTP \(status) \(status == 200 ? "" : body, privacy: .public)")
        throw UsageError.refreshFailed
    }

    oauth["accessToken"] = newToken
    if let rt = json["refresh_token"] as? String { oauth["refreshToken"] = rt }
    let expiresIn = json["expires_in"] as? Double ?? 3600
    oauth["expiresAt"] = Int64((Date().timeIntervalSince1970 + expiresIn) * 1000)
    root["claudeAiOauth"] = oauth
    return (root, newToken)
}

// MARK: - Usage

struct Limit { var percent: Double; var resetsAt: Date? }
struct Usage { var session: Limit; var weekly: Limit }

enum Source { case claudeCode, web }

/// Prefers Claude Code's login; falls back to a claude.ai sign-in for chat-only users.
/// Testing aid: `defaults write local.crescent ignoreClaudeCode -bool YES` simulates a chat-only user.
func fetchUsage() async throws -> (Usage, Source) {
    var claudeCodeError: Error?
    if !UserDefaults.standard.bool(forKey: "ignoreClaudeCode") {
        var token: String?
        do {
            token = try await TokenStore.shared.accessToken()
        } catch UsageError.noCredentials {
            // Claude Code isn't set up: a chat-only user, go straight to claude.ai.
        } catch {
            log.error("Claude Code login unavailable: \(String(describing: error), privacy: .public)")
            claudeCodeError = error
        }
        if let token {
            do {
                do {
                    return (try await fetchFromUsageEndpoint(token), .claudeCode)
                } catch {
                    return (try await fetchFromMessageHeaders(token), .claudeCode)
                }
            } catch {
                guard await ClaudeWeb.shared.hasSession() else { throw error }
            }
        }
    }
    do {
        return (try await ClaudeWeb.shared.fetchUsage(), .web)
    } catch UsageError.notSignedIn where claudeCodeError != nil {
        // Not signed in to claude.ai either; the Claude Code problem is the more useful message.
        throw claudeCodeError!
    }
}

/// Free endpoint, same data as `/usage` in Claude Code.
func fetchFromUsageEndpoint(_ token: String) async throws -> Usage {
    var req = URLRequest(url: URL(string: "https://api.anthropic.com/api/oauth/usage")!)
    req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
    req.setValue("oauth-2025-04-20", forHTTPHeaderField: "anthropic-beta")
    let (data, resp) = try await URLSession.shared.data(for: req)
    let status = (resp as? HTTPURLResponse)?.statusCode ?? 0
    guard status == 200 else { throw UsageError.http(status) }
    return try parseUsage(data)
}

/// Both the Claude Code endpoint and claude.ai return the same JSON shape.
func parseUsage(_ data: Data) throws -> Usage {
    guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
    else { throw UsageError.http(0) }

    let iso = ISO8601DateFormatter()
    iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    func limit(_ key: String) -> Limit {
        let o = json[key] as? [String: Any] ?? [:]
        let reset = (o["resets_at"] as? String).flatMap {
            iso.date(from: $0) ?? ISO8601DateFormatter().date(from: $0)
        }
        return Limit(percent: (o["utilization"] as? NSNumber)?.doubleValue ?? 0, resetsAt: reset)
    }
    return Usage(session: limit("five_hour"), weekly: limit("seven_day"))
}

/// Fallback: a 1-token message returns the rate-limit utilization in its headers
/// (also on 429). Costs a sliver of quota, so only used if the endpoint above fails.
func fetchFromMessageHeaders(_ token: String) async throws -> Usage {
    var req = URLRequest(url: URL(string: "https://api.anthropic.com/v1/messages")!)
    req.httpMethod = "POST"
    req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
    req.setValue("oauth-2025-04-20", forHTTPHeaderField: "anthropic-beta")
    req.setValue("2023-06-01", forHTTPHeaderField: "anthropic-version")
    req.setValue("application/json", forHTTPHeaderField: "Content-Type")
    req.httpBody = try JSONSerialization.data(withJSONObject: [
        "model": "claude-haiku-4-5", "max_tokens": 1,
        "messages": [["role": "user", "content": "hi"]],
    ])
    let (_, resp) = try await URLSession.shared.data(for: req)
    guard let http = resp as? HTTPURLResponse,
          http.value(forHTTPHeaderField: "anthropic-ratelimit-unified-5h-utilization") != nil
    else { throw UsageError.http((resp as? HTTPURLResponse)?.statusCode ?? 0) }

    func limit(_ window: String) -> Limit {
        func h(_ field: String) -> Double? {
            http.value(forHTTPHeaderField: "anthropic-ratelimit-unified-\(window)-\(field)").flatMap(Double.init)
        }
        return Limit(percent: (h("utilization") ?? 0) * 100,
                     resetsAt: h("reset").map { Date(timeIntervalSince1970: $0) })
    }
    return Usage(session: limit("5h"), weekly: limit("7d"))
}

// MARK: - claude.ai sign-in (for people who only use the chat apps)

/// Uses claude.ai's own web session. Requests run inside a hidden web view, so to
/// claude.ai (and Cloudflare) they look like a normal browser tab. The login lives
/// in WebKit's persistent store, so it survives restarts without us storing anything.
@MainActor
final class ClaudeWeb: NSObject, WKHTTPCookieStoreObserver {
    static let shared = ClaudeWeb()
    var onSignIn: (() -> Void)?

    private lazy var hidden = makeWebView()
    private var pageReady: Task<Void, Never>?
    private var loginWindow: NSWindow?
    private var store: WKWebsiteDataStore { .default() }

    private func makeWebView() -> WKWebView {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = store
        let view = WKWebView(frame: .zero, configuration: config)
        // Google refuses to sign in inside web views it doesn't recognise as Safari.
        view.customUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15"
        return view
    }

    func hasSession() async -> Bool {
        await store.httpCookieStore.allCookies().contains { $0.name == "sessionKey" && $0.domain.hasSuffix("claude.ai") }
    }

    func fetchUsage() async throws -> Usage {
        guard await hasSession() else { throw UsageError.notSignedIn }
        await loadPage()
        let result = try await hidden.callAsyncJavaScript("""
            const orgs = await fetch('/api/organizations');
            if (!orgs.ok) return { status: orgs.status };
            const list = await orgs.json();
            const org = list.find(o => (o.capabilities || []).includes('chat')) || list[0];
            if (!org) return { status: 404 };
            const usage = await fetch(`/api/organizations/${org.uuid}/usage`);
            return { status: usage.status, body: usage.ok ? await usage.text() : '' };
            """, contentWorld: .defaultClient) as? [String: Any]

        let status = (result?["status"] as? NSNumber)?.intValue ?? 0
        if status == 401 || status == 403 { throw UsageError.notSignedIn }
        guard status == 200, let body = result?["body"] as? String else { throw UsageError.http(status) }
        return try parseUsage(Data(body.utf8))
    }

    /// Puts the hidden web view on claude.ai once; concurrent refreshes share the same load.
    private func loadPage() async {
        if pageReady == nil {
            pageReady = Task {
                hidden.load(URLRequest(url: URL(string: "https://claude.ai/robots.txt")!))
                for _ in 0..<150 where hidden.isLoading || hidden.url?.host != "claude.ai" {
                    try? await Task.sleep(nanoseconds: 100_000_000)
                }
            }
        }
        await pageReady?.value
    }

    func showLogin() async {
        if loginWindow == nil {
            // Drop any stale session so we only react to a fresh sign-in.
            for cookie in await store.httpCookieStore.allCookies() where cookie.name == "sessionKey" {
                await store.httpCookieStore.deleteCookie(cookie)
            }
            store.httpCookieStore.add(self)

            let view = makeWebView()
            view.load(URLRequest(url: URL(string: "https://claude.ai/login")!))
            let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 420, height: 600),
                                  styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
            window.title = "Sign in to Claude"
            window.contentView = view
            window.isReleasedWhenClosed = false
            window.center()
            loginWindow = window
        }
        loginWindow?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    nonisolated func cookiesDidChange(in cookieStore: WKHTTPCookieStore) {
        Task { @MainActor in
            // Check the window after the await: this event fires many times, only the first should win.
            guard await hasSession(), loginWindow != nil else { return }
            store.httpCookieStore.remove(self)
            loginWindow?.close()
            loginWindow = nil
            onSignIn?()
        }
    }

    func signOut() async {
        let types = WKWebsiteDataStore.allWebsiteDataTypes()
        let records = await store.dataRecords(ofTypes: types).filter { $0.displayName.contains("claude.ai") }
        await store.removeData(ofTypes: types, for: records)
        hidden.loadHTMLString("", baseURL: nil)
        pageReady = nil
    }
}

// MARK: - Rings

enum DisplayStyle: Int, CaseIterable {
    case text, ring, doubleRing
    var title: String { ["Percentages", "Ring", "Double Ring"][rawValue] }
}

/// Progress ring(s) as a template image, so macOS tints it for light/dark menu bars.
/// Outer ring is the session, the optional inner ring is weekly. Starts at 12 o'clock.
/// `outerElapsed`/`innerElapsed` (0–1) draw a tick showing how far into each window we are.
func ringImage(outer: Double, outerElapsed: Double?, inner: Double?, innerElapsed: Double?) -> NSImage {
    let size: CGFloat = 18
    let image = NSImage(size: NSSize(width: size, height: size), flipped: false) { _ in
        let center = NSPoint(x: size / 2, y: size / 2)
        func tick(radius: CGFloat, width: CGFloat, fraction: Double) {
            let angle = (90 - 360 * min(max(fraction, 0), 1)) * .pi / 180
            let from = radius - width / 2 - 1, to = min(radius + width / 2 + 0.75, size / 2)
            let path = NSBezierPath()
            path.move(to: NSPoint(x: center.x + from * cos(angle), y: center.y + from * sin(angle)))
            path.line(to: NSPoint(x: center.x + to * cos(angle), y: center.y + to * sin(angle)))
            // Cut a gap first so the tick stays visible on top of the filled arc.
            NSGraphicsContext.current?.compositingOperation = .clear
            path.lineWidth = 3
            path.stroke()
            NSGraphicsContext.current?.compositingOperation = .sourceOver
            path.lineWidth = 1.25
            NSColor.black.setStroke()
            path.stroke()
        }
        func ring(radius: CGFloat, width: CGFloat, percent: Double) {
            let track = NSBezierPath()
            track.appendArc(withCenter: center, radius: radius, startAngle: 0, endAngle: 360)
            track.lineWidth = width
            NSColor.black.withAlphaComponent(0.25).setStroke()
            track.stroke()

            let fraction = min(max(percent / 100, 0), 1)
            guard fraction > 0 else { return }
            let arc = NSBezierPath()
            arc.appendArc(withCenter: center, radius: radius, startAngle: 90,
                          endAngle: 90 - 360 * fraction, clockwise: true)
            arc.lineWidth = width
            arc.lineCapStyle = fraction < 1 ? .round : .butt
            NSColor.black.setStroke()
            arc.stroke()
        }
        let (radius, width): (CGFloat, CGFloat) = inner == nil ? (7, 2.5) : (7.5, 2)
        ring(radius: radius, width: width, percent: outer)
        if let inner { ring(radius: 3.75, width: 2, percent: inner) }
        if let outerElapsed { tick(radius: radius, width: width, fraction: outerElapsed) }
        if inner != nil, let innerElapsed { tick(radius: 3.75, width: 2, fraction: innerElapsed) }
        return true
    }
    image.isTemplate = true
    return image
}

// MARK: - Menu bar

/// A non-clickable menu row: "Session 59%" on the left in normal text color,
/// "resets 17:00" pushed to the right edge in grey.
final class InfoRow: NSView {
    private let left = NSTextField(labelWithString: "–")
    private let right = NSTextField(labelWithString: "")
    private let message = NSTextField(labelWithString: "")

    init() {
        super.init(frame: NSRect(x: 0, y: 0, width: 280, height: 22))
        let font = NSFont.menuFont(ofSize: 0)
        left.font = .monospacedDigitSystemFont(ofSize: font.pointSize, weight: .regular)
        right.font = left.font
        left.textColor = .labelColor
        right.textColor = .secondaryLabelColor
        message.font = left.font
        message.textColor = .secondaryLabelColor
        message.isHidden = true
        for label in [left, right, message] {
            label.translatesAutoresizingMaskIntoConstraints = false
            addSubview(label)
        }
        NSLayoutConstraint.activate([
            left.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 16),
            right.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -16),
            right.leadingAnchor.constraint(greaterThanOrEqualTo: left.trailingAnchor, constant: 16),
            left.centerYAnchor.constraint(equalTo: centerYAnchor),
            right.centerYAnchor.constraint(equalTo: centerYAnchor),
            message.centerXAnchor.constraint(equalTo: centerXAnchor),
            message.centerYAnchor.constraint(equalTo: centerYAnchor),
        ])
    }

    required init?(coder: NSCoder) { fatalError() }

    /// Replaces the row with one grey, centered message, as tall as both rows together.
    func showMessage(_ text: String) {
        message.stringValue = text
        message.isHidden = false
        left.isHidden = true
        right.isHidden = true
        setFrameSize(NSSize(width: frame.width, height: 44))
    }

    func set(left: String, right: String) {
        message.isHidden = true
        self.left.isHidden = false
        self.right.isHidden = false
        setFrameSize(NSSize(width: frame.width, height: 22))
        self.left.stringValue = left
        self.right.stringValue = right
    }

    func set(_ name: String, _ limit: Limit, format: String) {
        var reset = ""
        if let date = limit.resetsAt {
            let f = DateFormatter()
            f.dateFormat = format
            // Resets come as e.g. 16:59:59.9, so round to the minute to show 17:00.
            let rounded = Date(timeIntervalSinceReferenceDate: (date.timeIntervalSinceReferenceDate / 60).rounded() * 60)
            reset = "resets \(f.string(from: rounded))"
        }
        set(left: "\(name): \(Int(limit.percent.rounded()))%", right: reset)
    }
}

@MainActor
final class App: NSObject, NSApplicationDelegate, NSMenuDelegate {
    let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    let menu = NSMenu()
    let sessionRow = InfoRow()
    let weeklyRow = InfoRow()
    let intervalMenu = NSMenu()
    let displayMenu = NSMenu()
    let loginItem = NSMenuItem(title: "Launch at Login", action: #selector(toggleLaunchAtLogin), keyEquivalent: "")
    let accountItem = NSMenuItem(title: "Sign in to Claude…", action: #selector(account), keyEquivalent: "")
    var timer: Timer?
    var lastUsage: Usage?
    var source: Source?

    var displayStyle: DisplayStyle {
        get { DisplayStyle(rawValue: UserDefaults.standard.integer(forKey: "displayStyle")) ?? .text }
        set { UserDefaults.standard.set(newValue.rawValue, forKey: "displayStyle") }
    }

    /// Auto-refresh interval in minutes, remembered across launches.
    var refreshMinutes: Int {
        get { UserDefaults.standard.object(forKey: "refreshMinutes") as? Int ?? 5 }
        set { UserDefaults.standard.set(newValue, forKey: "refreshMinutes") }
    }

    func applicationDidFinishLaunching(_ note: Notification) {
        item.button?.title = "–"
        item.button?.font = .monospacedDigitSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)

        // Never shown (menu-bar-only app), but ⌘C/⌘V/⌘A in the sign-in window are routed through it.
        let edit = NSMenu(title: "Edit")
        edit.addItem(withTitle: "Undo", action: Selector(("undo:")), keyEquivalent: "z")
        edit.addItem(withTitle: "Redo", action: Selector(("redo:")), keyEquivalent: "Z")
        edit.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        edit.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        edit.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        edit.addItem(withTitle: "Close Window", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        let mainMenu = NSMenu()
        mainMenu.addItem(withTitle: "Edit", action: nil, keyEquivalent: "").submenu = edit
        NSApp.mainMenu = mainMenu

        for row in [sessionRow, weeklyRow] {
            let line = NSMenuItem()
            line.view = row
            menu.addItem(line)
        }
        menu.addItem(.separator())
        menu.addItem(withTitle: "Refresh", action: #selector(refresh), keyEquivalent: "r").target = self
        for minutes in [1, 5, 15, 30] {
            let option = intervalMenu.addItem(withTitle: "\(minutes) min", action: #selector(setInterval(_:)), keyEquivalent: "")
            option.target = self
            option.tag = minutes
        }
        menu.addItem(withTitle: "Refresh Every", action: nil, keyEquivalent: "").submenu = intervalMenu
        for style in DisplayStyle.allCases {
            let option = displayMenu.addItem(withTitle: style.title, action: #selector(setDisplayStyle(_:)), keyEquivalent: "")
            option.target = self
            option.tag = style.rawValue
        }
        menu.addItem(withTitle: "Display", action: nil, keyEquivalent: "").submenu = displayMenu
        updateDisplayChecks()
        menu.addItem(loginItem)
        loginItem.target = self
        menu.addItem(accountItem)
        accountItem.target = self
        accountItem.isHidden = true
        ClaudeWeb.shared.onSignIn = { [weak self] in self?.refresh() }
        menu.addItem(.separator())
        menu.addItem(withTitle: "Quit", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        menu.delegate = self
        item.menu = menu

        refresh()
        startTimer()
    }

    func startTimer() {
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: TimeInterval(refreshMinutes * 60), repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
        for option in intervalMenu.items { option.state = option.tag == refreshMinutes ? .on : .off }
    }

    @objc func setInterval(_ sender: NSMenuItem) {
        refreshMinutes = sender.tag
        startTimer()
    }

    @objc func setDisplayStyle(_ sender: NSMenuItem) {
        displayStyle = DisplayStyle(rawValue: sender.tag) ?? .text
        updateDisplayChecks()
        if let u = lastUsage { show(u) }
    }

    func updateDisplayChecks() {
        for option in displayMenu.items { option.state = option.tag == displayStyle.rawValue ? .on : .off }
    }

    @objc func toggleLaunchAtLogin() {
        let service = SMAppService.mainApp
        do {
            if service.status == .enabled {
                try service.unregister()
            } else {
                try service.register()
            }
        } catch {
            // Usually means macOS wants approval in System Settings → General → Login Items.
            SMAppService.openSystemSettingsLoginItems()
        }
    }

    /// Signs in to claude.ai, or signs out when that's the active login.
    @objc func account() {
        Task {
            if source == .web {
                await ClaudeWeb.shared.signOut()
                refresh()
            } else {
                await ClaudeWeb.shared.showLogin()
            }
        }
    }

    func menuWillOpen(_ menu: NSMenu) {
        // Read live status so changes made in System Settings show up too.
        loginItem.state = SMAppService.mainApp.status == .enabled ? .on : .off
        refresh()
    }

    @objc func refresh() {
        Task {
            do {
                let (u, source) = try await fetchUsage()
                log.notice("\(Int(u.session.percent))% · \(Int(u.weekly.percent))% via \(String(describing: source), privacy: .public)")
                self.source = source
                show(u)
            } catch {
                log.notice("failed: \(String(describing: error), privacy: .public)")
                showError(error)
            }
        }
    }

    func show(_ u: Usage) {
        lastUsage = u
        let button = item.button
        // How far we are into each window, e.g. 0.5 at 2.5 h of the 5-hour session.
        func elapsed(_ limit: Limit, window: TimeInterval) -> Double? {
            limit.resetsAt.map { 1 - $0.timeIntervalSinceNow / window }
        }
        let sessionElapsed = elapsed(u.session, window: 5 * 3600)
        let weeklyElapsed = elapsed(u.weekly, window: 7 * 24 * 3600)
        switch displayStyle {
        case .text:
            button?.image = nil
            button?.title = "\(Int(u.session.percent.rounded()))% · \(Int(u.weekly.percent.rounded()))%"
        case .ring:
            button?.title = ""
            button?.image = ringImage(outer: u.session.percent, outerElapsed: sessionElapsed, inner: nil, innerElapsed: nil)
        case .doubleRing:
            button?.title = ""
            button?.image = ringImage(outer: u.session.percent, outerElapsed: sessionElapsed,
                                      inner: u.weekly.percent, innerElapsed: weeklyElapsed)
        }
        weeklyRow.enclosingMenuItem?.isHidden = false
        sessionRow.set("Session", u.session, format: "HH:mm")
        weeklyRow.set("Weekly", u.weekly, format: "EEE HH:mm")
        accountItem.title = "Sign Out of claude.ai"
        accountItem.isHidden = source != .web
    }

    func showError(_ error: Error) {
        lastUsage = nil
        item.button?.image = nil
        item.button?.title = "–"
        let msg: String
        switch error {
        case UsageError.noCredentials, UsageError.refreshFailed, UsageError.notSignedIn:
            // An expired Claude Code login needs `claude` run once; signing in to claude.ai also works.
            if case UsageError.refreshFailed = error { msg = "Claude Code login expired" } else { msg = "Not signed in" }
            source = nil
            accountItem.title = "Sign in to Claude…"
            accountItem.isHidden = false
        default: msg = "Couldn't fetch usage"
        }
        sessionRow.showMessage(msg)
        weeklyRow.enclosingMenuItem?.isHidden = true
    }
}

// Top-level code runs on the main thread; tell the compiler so.
MainActor.assumeIsolated {
    let app = NSApplication.shared
    let delegate = App()
    app.delegate = delegate
    app.setActivationPolicy(.accessory)
    app.run()
}
