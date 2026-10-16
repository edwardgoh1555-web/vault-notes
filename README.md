# Vault Notes

Ultra-light Android notepad. Each note can have its own PIN; locked notes are
encrypted on-device (PBKDF2-SHA256 → AES-256-GCM). No network permission,
no libraries, no backups — everything stays in the app's private storage.

Every push to `main` builds a signed APK and attaches it to a GitHub Release.
