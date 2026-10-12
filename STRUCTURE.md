# Project structure

- `Sources/Crescent/main.swift` — app source.
- `Sources/Crescent/AppIcon.icon` — layered Icon Composer source.
- `Assets/Crescent-Icon.png` — README preview exported from the compiled icon.
- `Crescent.xcodeproj` — Xcode project and shared scheme.
- `Design/PreviousAppIcon` — earlier icon source retained for reference.
- `build.sh` — release build script.

The bundle identifier is `local.crescent`. The `build.sh` output is signed for local development; the GitHub release is separately Developer ID-signed and notarized.

Generated `build/` and `Crescent.app/` are ignored by Git.
