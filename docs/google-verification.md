# Google OAuth verification

The app asks Google for `openid`, `email`, and `https://www.googleapis.com/auth/drive.file`.
`drive.file` is a non-restricted scope: files the person picks in the Google Picker, and files
this app creates. It does not by itself remove the "unverified app" screen. Brand verification,
a production project, and a public privacy policy still have to be finished in Google Cloud and
Search Console. This page is the list of those clicks. Nothing here changes Vercel secrets for you.

## What the server already does

- The sign-in URL requests only `openid`, `email`, and `drive.file`. A token that still includes
  `https://www.googleapis.com/auth/drive` is refused and revoked.
- `/privacy` and `/terms` are public and linked from the home page, the sign-in page, and the footer.
- `APP_BASE_URL` is the only public origin. The OAuth redirect is `APP_BASE_URL/auth/callback`.
  Point a custom domain at the deployment, set `APP_BASE_URL` to `https://that-domain` (no trailing
  slash), and add that same callback URL on the OAuth client. `http://` is accepted only for
  `localhost` and `127.0.0.1`.
- The Google Picker is enabled when both `GOOGLE_PICKER_API_KEY` and `GOOGLE_CLOUD_PROJECT_NUMBER`
  are set. The API key is visible to a signed-in browser. Restrict it by HTTP referrer to the
  production origin. The project number is what makes a picked file grant `drive.file` to this app.
- Content-Security-Policy allows `https://apis.google.com` and `https://www.gstatic.com` scripts
  (the Picker script evaluates code) and frames from Drive, Docs, Accounts, and `content.googleapis.com`.

## Migration for people who already connected

Refresh tokens keep the scopes they were granted. The server does not send a new scope list on
refresh, so an older full-Drive token still calls Drive until that person signs in again.

1. Each person opens the dashboard. A banner says the saved sign-in is from before per-file access.
2. They choose **Sign in again**. If Google still offers full Drive access, they remove the app at
   [Google Account permissions](https://myaccount.google.com/permissions) and sign in once more.
3. If `GOOGLE_OAUTH_REFRESH_TOKEN` is set, it overrides the admin's dashboard sign-in. Remove it,
   or mint a replacement with `scripts/bootstrap_oauth.py` (that script now requests `drive.file`)
   and put the new value in the host. Do not leave the old full-Drive token in place if you are
   submitting the app for verification.
4. Files that were only reachable because the old token could see the whole Drive must be picked
   again. Picking a folder shares that folder. Files already inside it may each need a pick.
   Files the assistant creates inside an allowed folder stay available. The server allowlist is
   unchanged: a call still has to match an allowed id or an allowed parent.

The assistant tools, mailbox, and webhook routes are the same. Only the Google permission and
the way files are added changed.

## Clicks left for the owner

Do these in a **separate production** Google Cloud project, not the one you used for experiments.

1. **Custom domain.** Attach the domain to the host. Set `APP_BASE_URL` to `https://your-domain`.
   Add `https://your-domain/auth/callback` as an authorized redirect URI. Remove preview-only
   redirect URIs from the production client.
2. **APIs.** In that project enable **Google Drive API** and **Google Picker API**.
3. **OAuth client.** Web application. Client id and secret become `GOOGLE_OAUTH_CLIENT_ID` and
   `GOOGLE_OAUTH_CLIENT_SECRET`. Create an API key for `GOOGLE_PICKER_API_KEY`, restricted to
   the Picker API and to your domain. Copy the project **number** (not the project id) into
   `GOOGLE_CLOUD_PROJECT_NUMBER`.
4. **Consent screen.** App name, support email, developer contact, logo, and home page
   `APP_BASE_URL`. Privacy policy `APP_BASE_URL/privacy`. Terms `APP_BASE_URL/terms`.
   Scopes: `openid`, `email`, `https://www.googleapis.com/auth/drive.file`. Remove
   `https://www.googleapis.com/auth/drive` if it is still listed. Audience: External.
5. **Search Console.** Add the custom domain as a property and verify it (DNS is the durable
   method). Google uses this for brand verification of the domain on the consent screen.
6. **Brand verification.** In the Google Auth Platform / consent screen, submit the app for
   brand verification. Use the same domain Search Console shows as verified. The home page
   should show the app name, what it does, and a link to the privacy policy.
7. **Publish.** Set the app to **In production**. Testing mode expires refresh tokens after
   7 days. Production with only non-restricted scopes can still show an unverified notice
   until brand verification finishes. You should not need a restricted-scope security
   assessment (CASA) for `drive.file` alone. If the full Drive scope is still on the consent
   screen, Google will ask for that assessment. Take it off.

After the first production sign-in, open a file with **Add from Google Drive**, allow it, and
confirm an assistant can read that file and cannot read a file you did not pick.
