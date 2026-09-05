# Applications — setup and how to read submissions

The Join section has a real application form. Submissions POST to `/api/apply`
and are stored in a **D1 database that ships with the site**.

You read them at **`/admin`** on your own site, behind a password.

---

## One-time setup

Run these from the project folder, in order.

### 1. Log in to Cloudflare

```sh
npx wrangler login
```

Opens a browser. Approve the request.

### 2. Create the database

```sh
npx wrangler d1 create designclub-applications
```

It prints a block ending in `database_id = "..."`. **Copy that id.**

### 3. Paste the id into the config

Open `wrangler.jsonc` and replace `REPLACE_WITH_DATABASE_ID` with that id.

### 4. Create the tables

```sh
npx wrangler d1 execute designclub-applications --remote --file=schema.sql
```

### 5. Set your admin password

```sh
npx wrangler secret put ADMIN_PASSWORD
```

It prompts for the password and stores it encrypted at Cloudflare. **It is
never written into the code or into git.** Pick something long — this is the
only thing standing between the public and every applicant's details.

### 6. Deploy

```sh
npx wrangler deploy
```

Done. The form is live, and `/admin` is your inbox.

---

## Reading applications

Go to **`https://your-site/admin`**, enter the password, and you get every
application newest-first: name, grade, role, email, experience, and their
reason. From there you can

- **filter** by name, email, role or grade as you type,
- **copy everything as CSV** to paste into Google Sheets or Excel,
- **delete** an application,
- **sign out**.

Signing in lasts 8 hours, then asks again.

### Changing the password

```sh
npx wrangler secret put ADMIN_PASSWORD
```

Anyone currently signed in is signed out immediately.

---

## Testing locally before deploying

```sh
npx wrangler d1 execute designclub-applications --local --file=schema.sql
npx wrangler dev --local
```

Open http://localhost:8788 to submit, and http://localhost:8788/admin to read.
The local password comes from the `.dev.vars` file (git-ignored); local data
lives in `.wrangler/` and is completely separate from the live site.

---

## What gets stored

| Column | Notes |
| --- | --- |
| `name`, `email`, `grade`, `role` | required |
| `experience` | optional |
| `why` | required |
| `ip`, `user_agent` | captured automatically, for spam triage |
| `created_at` | UTC timestamp |

## How it is protected

- **The password is a Cloudflare secret**, not a value in the code, so it never
  lands in git.
- **Sessions are signed cookies** — `HttpOnly` (JavaScript cannot read them),
  `SameSite=Strict`, `Secure` over HTTPS, 8-hour expiry. Forging one requires
  the password.
- **8 password attempts per IP per 15 minutes**, then a lockout.
- **The password check is constant-time**, so response timing leaks nothing.
- **No public read endpoint.** Every admin route returns 401 without a valid
  session.
- **Server code, SQL, config and `.dev.vars` are excluded from the public
  site** via `.assetsignore` — all verified returning 404.
- **Applicant spam control:** hidden honeypot field, 5 submissions per IP per
  hour, and server-side validation, so posting directly to the API cannot
  bypass the form.

## Changing the role list

The dropdown in `index.html` and the `ROLES` array in `src/worker.js` must
match, or the server rejects the new option. Update both.
