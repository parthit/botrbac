# Google OAuth verification

The app asks Google for `openid`, `email`, and `https://www.googleapis.com/auth/drive`.
That Drive scope is restricted. It lets this server see and change the signed-in account's
Drive. The allowlist is what an assistant can use. Brand verification, a production project,
and a public privacy policy still have to be finished in Google Cloud and Search Console.
Google can ask for a security assessment (CASA) because the scope is restricted. This page
is the list of those clicks. Nothing here changes Vercel secrets for you.

## What the server already does

- Google is asked twice. **Sign-in** (`/auth/login`) requests only `openid` and `email`, online
  access, and stores no token. **Connect Google Drive** (`/connect`, a separate click after
  sign-in) requests `https://www.googleapis.com/auth/drive` with offline access and incremental
  authorization (`include_granted_scopes=true`), pinned to the signed-in address with
  `login_hint`. A connect token that does not include the Drive scope, or that belongs to a
  different Google account than the one signed in, is revoked and refused. A stored token that only has
  `https://www.googleapis.com/auth/drive.file` keeps working for files that grant already
  covers, and the dashboard asks that person to sign in again.
- `/privacy` and `/terms` are public and linked from the home page, the sign-in page, and the footer.
- `APP_BASE_URL` is the only public origin. The OAuth redirect is `APP_BASE_URL/auth/callback`.
  Point a custom domain at the deployment, set `APP_BASE_URL` to `https://that-domain` (no trailing
  slash), and add that same callback URL on the OAuth client. `http://` is accepted only for
  `localhost` and `127.0.0.1`.
- The Google Picker is optional. It is enabled when both `GOOGLE_PICKER_API_KEY` and
  `GOOGLE_CLOUD_PROJECT_NUMBER` are set. Browse and approval use the signed-in Drive without it.
  The API key is visible to a signed-in browser. Restrict it by HTTP referrer to the production origin.
- Content-Security-Policy allows `https://apis.google.com` and `https://www.gstatic.com` scripts
  (the Picker script evaluates code) and frames from Drive, Docs, Accounts, and `content.googleapis.com`.

## Migration for people who already connected

Refresh tokens keep the scopes they were granted. The server does not send a new scope list on
refresh, so a `drive.file` token still cannot open the rest of Drive until that person signs in again.

1. Each person opens the dashboard. A banner says the saved connection cannot see the whole Drive.
2. They choose **Reconnect Google Drive** and allow Drive access. If Google keeps the narrower permission,
   they remove the app at [Google Account permissions](https://myaccount.google.com/permissions)
   and sign in once more.
3. If `GOOGLE_OAUTH_REFRESH_TOKEN` is set, it overrides the admin's dashboard sign-in. Replace it
   with `scripts/bootstrap_oauth.py` when that token was minted with `drive.file`.
4. The server allowlist is unchanged. A call still has to match an allowed id or an allowed parent.
   Approving a request adds that file. Files the assistant creates inside an allowed folder stay available.

The assistant tools, mailbox, and webhook routes are the same. Only the Google permission changed.

## Clicks left for the owner

Do these in a **separate production** Google Cloud project, not the one you used for experiments.

1. **Custom domain.** Attach the domain to the host. Set `APP_BASE_URL` to `https://your-domain`.
   Add `https://your-domain/auth/callback` as an authorized redirect URI. Remove preview-only
   redirect URIs from the production client.
2. **APIs.** In that project enable **Google Drive API**. Enable **Google Picker API** only if you
   want the optional picker.
3. **OAuth client.** Web application. Client id and secret become `GOOGLE_OAUTH_CLIENT_ID` and
   `GOOGLE_OAUTH_CLIENT_SECRET`. For the picker, create an API key for `GOOGLE_PICKER_API_KEY`,
   restricted to the Picker API and to your domain. Copy the project **number** (not the project id)
   into `GOOGLE_CLOUD_PROJECT_NUMBER`.
4. **Consent screen.** App name, support email, developer contact, logo, and home page
   `APP_BASE_URL`. Privacy policy `APP_BASE_URL/privacy`. Terms `APP_BASE_URL/terms`.
   Scopes: `openid`, `email`, `https://www.googleapis.com/auth/drive`. Audience: External.
   In the scope justification, say that sign-in uses only `openid` and `email`, and that the
   Drive scope is requested in a separate step only when the person chooses to connect Drive.
5. **Search Console.** Add the custom domain as a property and verify it (DNS is the durable
   method). Google uses this for brand verification of the domain on the consent screen.
6. **Brand verification.** In the Google Auth Platform / consent screen, submit the app for
   brand verification. Use the same domain Search Console shows as verified. The home page
   should show the app name, what it does, and a link to the privacy policy.
7. **Publish.** Set the app to **In production**. Testing mode expires refresh tokens after
   7 days. The full Drive scope is restricted, so Google can ask for a security assessment
   before the unverified-app screen goes away.

After the first production sign-in, allow one file, confirm an assistant can read it, and
confirm it cannot read a file you did not allow.
