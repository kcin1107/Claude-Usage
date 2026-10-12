# Project structure

- `Sources/Crescent/main.swift` — app source.
- `Sources/Crescent/AppIcon.icon` — layered Icon Composer source.
- `Crescent.xcodeproj` — Xcode project and shared scheme.
- `Design/PreviousAppIcon` — earlier icon source retained for reference.
- `build.sh` — release build script.

The bundle identifier remains `local.claudeusage` so existing app settings and sign-in data continue to work after the rename.

Generated `build/` and `Crescent.app/` are ignored by Git.
