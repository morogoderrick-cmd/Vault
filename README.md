# My Vault

A password manager with accounts. Log in from any phone or laptop and see the same vault.

**Your passwords are encrypted in your browser** with a key made from your master password. The server only stores scrambled data and a login token, so even the server owner can’t read your passwords. **Nobody can recover a forgotten master password.**

## Put it online (free, about 15 minutes)

### 1. Free database (Neon)
1. Go to neon.tech and sign up. Create a project.
2. Copy the **connection string** (it starts with `postgresql://`). Keep it private.

### 2. Put the files on GitHub
1. Create a new repository (a **private** one is best).
2. Upload everything in this folder, keeping the `public` folder: `server.js`, `package.json`, `README.md` and `public/` (with `index.html`, `app.js`, `style.css`).

### 3. Host it (Render)
1. Go to render.com, sign up, click **New → Web Service**, and connect your GitHub repository.
2. Build command: `npm install`  Start command: `npm start`
3. Under **Environment**, add three variables:
   - `DATABASE_URL` = your Neon connection string
   - `SESSION_SECRET` = any random text of 40+ characters
   - `NODE_ENV` = `production`
4. Deploy. Open the link Render gives you and create your account.

The free Render plan sleeps when unused, so the first visit after a break can take about a minute.

## Moving your old vault in
Log in, open **Settings and import**, choose your old `vault-backup.json`, type the old vault’s master password, and click Import.

## Good to know
- Use a long passphrase. 10 characters is the minimum, more is better.
- Export a backup now and then (**Export backup**). Keep it somewhere safe.
- You are logged out after 5 minutes of inactivity, or instantly when you press **Escape**.
- If you open the vault on two devices and change it on both, the second save is refused and the latest version reloads, so nothing is silently overwritten.
