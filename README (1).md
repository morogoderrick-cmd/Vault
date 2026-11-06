# My Vault

A simple password manager that runs entirely in your web browser. You save your websites, links, usernames and passwords, and everything is locked behind one master password.

There is **no backend and no server**. Nothing you type is ever sent anywhere.

## How it works

- You create a master password the first time you open the page.
- Your master password is turned into an encryption key (PBKDF2, 600,000 rounds).
- Your entries are encrypted with that key (AES-256-GCM) using the browser's built-in Web Crypto.
- The encrypted data is saved in your browser's local storage, on your device only.
- The master password itself is never stored.

## Features

- Save a website name, link, username and password
- Search your saved websites
- Show or hide a password, and copy it to the clipboard (the clipboard is cleared after 20 seconds)
- Generate strong random passwords
- Open a saved link in a new tab
- Auto-lock after 5 minutes without activity
- Export and import an encrypted backup

## Host it on GitHub Pages

1. Create a new repository on GitHub.
2. Upload `index.html` (and this README) to it.
3. Go to **Settings → Pages**.
4. Under **Branch**, choose `main` and the `/ (root)` folder, then save.
5. After a minute or two, your site is live at `https://YOUR-NAME.github.io/REPOSITORY-NAME`.

The site is public, but it contains no passwords. Your data exists only in the browser where you use it.

## Back up your vault (do this regularly)

Because there is no server, **your browser is the only place your data lives.** If it's lost or cleared, so is your vault, unless you have a backup.

1. Open the vault and click **Export backup**.
2. A file called `vault-backup.json` is downloaded. It is encrypted, so it is useless without your master password.
3. Keep copies in at least two places, such as a USB drive, a cloud drive, or an email to yourself.
4. Export again every time you add or change passwords.

## Restore on a new device

1. Open your site on the new phone or computer.
2. On the lock screen, tap **Import a backup** and choose your `vault-backup.json` file.
3. Enter your master password to unlock it.

## If you lose your phone

- **You have a backup:** open the site on a new device, import the backup, and unlock it with your master password. Nothing is lost.
- **You have no backup:** the vault can't be recovered, because it only existed on that phone. Use each website's "Forgot password" option to regain access to your accounts, then start a new vault and make a backup straight away.
- **Is my data safe on the lost phone?** The vault is encrypted, so someone who finds the phone can't read it without your master password. A long, unique master password protects you best. If you're worried, change the passwords of your most important accounts.

## Important to know

- **If you forget your master password, your data can't be recovered.** Nobody can reset it, because no server knows it.
- Use a long master password that you don't use anywhere else. Passphrases of four or more random words work well.
- Don't use it on shared or public computers.
- Clearing your browser data, or using private/incognito mode, will erase or hide your vault. Export a backup first.
- Your data does not sync between devices. Use Export and Import to move it.
- Never put your master password or `vault-backup.json` in a public repository.

## Files

| File | Purpose |
| --- | --- |
| `index.html` | The whole app (page, styles and code in one file) |
| `README.md` | This guide |
