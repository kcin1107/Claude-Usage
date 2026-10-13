# Project structure

- `Sources/Crescent/main.swift` — app source.
- `Sources/Crescent/AppIcon.icon` — layered Icon Composer source.
- `Assets/Crescent-Icon.png` — README preview exported from the compiled icon.
- `Crescent.xcodeproj` — Xcode project and shared scheme.
- `Design/PreviousAppIcon` — earlier icon source retained for reference.
- `build.sh` — release build script.

## Login

Crescent first uses the Claude Code login from the Keychain item `Claude Code-credentials`. It renews expired tokens itself and writes the rotated tokens back so Claude Code keeps working. Concurrent requests share one renewal. Failed saves are retried only while the original credentials remain in the Keychain, so a later logout or replacement login is respected. If that login is missing or fails, it falls back to a claude.ai sign-in in an embedded web view. WebKit stores that session per bundle identifier, so changing the bundle identifier signs users out.

## Debugging

- Logs: `log show --predicate 'subsystem == "local.crescent"'`. Each refresh logs its result and which login it used. Failed token renewals log the HTTP status and the error response, and failed Keychain writes are logged too. Tokens are never logged.
- `defaults write local.crescent ignoreClaudeCode -bool YES` skips the Claude Code login to simulate a chat-only user. Remove it with `defaults delete local.crescent ignoreClaudeCode`.

The bundle identifier is `local.crescent`. Version 1.0.1 uses build number 2. The Xcode project uses Developer ID Application signing and the hardened runtime; `build.sh` requires a matching signing identity for the configured team. Release builds support Apple silicon and Intel. The target uses Xcode’s recommended macOS deployment version; the 1.0.1 release requires macOS 14 or later. Before publishing, submit the signed app to Apple for notarization, staple the accepted ticket, and verify it with Gatekeeper.

Generated `build/` and `Crescent.app/` are ignored by Git.
