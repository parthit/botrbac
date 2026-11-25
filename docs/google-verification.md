# Google OAuth setup and verification

The app asks Google for `openid`, `email`, and `https://www.googleapis.com/auth/drive.file`. That Drive
scope is **non-sensitive**: Google opens to the app only the files a person picks in Google's file picker
and the files the app creates. Google enforces it, so the rest of a person's Drive stays closed to this
server whatever the server does. Brand verification, a production project, and a public privacy policy
still have to be finished in Google Cloud and Search Console. Because no restricted scope is requested,
Google's restricted-scope security assessment (CASA) does not apply. This page is the list of those
clicks. Nothing here changes Vercel settings for you.

## What the server already does

- Google is asked twice. **Sign-in** (`/auth/login`) requests only `openid` and `email`, online access,
  and stores no token. **Connect Google Drive** (`/connect`, a separate click after sign-in) requests
  `drive.file` with offline access, **without** incremental authorization
  (`include_granted_scopes=false`), pinned to the signed-in address with `login_hint`.
- A connect token that lacks `drive.file`, or belongs to a different Google account than the one signed
  in, is refused. One that comes back with the full Drive scope (`https://www.googleapis.com/auth/drive`)
  is refused **and revoked**, and never stored.
- Every access token is refreshed as `drive.file` only, and the scopes Google reports are checked. A wider
  grant fails closed.
- `/privacy` and `/terms` are public and linked from the home page, the sign-in page, and the footer.
- `APP_BASE_URL` is the only public origin. The OAuth redirect is `APP_BASE_URL/auth/callback`. `http://`
  is accepted only for `localhost` and `127.0.0.1`.
- Google's file picker is required: it is how people add files. It is enabled when both
  `GOOGLE_PICKER_API_KEY` and `GOOGLE_CLOUD_PROJECT_NUMBER` are set; until then the admin overview lists
  them as missing. The API key is visible to a signed-in browser, so restrict it (step 4 below).
- Content-Security-Policy allows `https://apis.google.com` and `https://www.gstatic.com` scripts (the
  picker script evaluates code) and frames from Drive, Docs, Accounts, and `content.googleapis.com`.

## Google Cloud clicks

Do these in the Google Cloud project whose OAuth client is in `GOOGLE_OAUTH_CLIENT_ID`. For a public
deployment, use a separate production project, not one used for experiments.

1. **Custom domain.** Attach the domain to the host. Set `APP_BASE_URL` to `https://your-domain`. Add
   `https://your-domain/auth/callback` as an authorized redirect URI on the OAuth client. Remove
   preview-only redirect URIs from the production client.
2. **APIs.** APIs & Services → Library: enable **Google Drive API** and **Google Picker API**.
3. **OAuth client.** Web application. Its client ID and secret are `GOOGLE_OAUTH_CLIENT_ID` and
   `GOOGLE_OAUTH_CLIENT_SECRET`.
4. **Picker key.** APIs & Services → Credentials → **Create credentials → API key**. Open the key:
   - **Application restrictions:** Websites → `https://your-domain/*` and `https://docs.google.com/*`
     (add `http://localhost:8000/*` only on a development project). The picker runs in a frame on
     `docs.google.com`, and Safari can send that address to Google instead of yours. Without it, Safari
     users see "The API developer key is invalid". A development project's key needs
     `https://docs.google.com/*` too.
   - **API restrictions:** Restrict key → **Google Picker API** only.

   Save. The key is `GOOGLE_PICKER_API_KEY`.
5. **Project number.** Console home → Project info → **Project number** (the long number, not the
   project ID). It is `GOOGLE_CLOUD_PROJECT_NUMBER`. The picker needs it so that a file someone picks is
   opened to *this* app.
6. **Consent screen** (Google Auth Platform):
   - **Branding:** app name, support email, developer contact, logo, home page `APP_BASE_URL`, privacy
     policy `APP_BASE_URL/privacy`, terms `APP_BASE_URL/terms`.
   - **Audience:** External.
   - **Data access:** scopes `openid`, `email`, `https://www.googleapis.com/auth/drive.file`.
     **Remove** `https://www.googleapis.com/auth/drive` if it is listed. Justification: sign-in uses only
     `openid` and `email`; `drive.file` is requested in a separate step when the person chooses to connect
     Drive, and only files they pick in Google's file picker are opened to the app.
7. **Search Console.** Add the custom domain as a property and verify it (DNS is the durable method).
   Google uses this for brand verification.
8. **Brand verification.** Submit the app for brand verification on the same verified domain. The home
   page should show the app name, what it does, and a link to the privacy policy.
9. **Publish.** Set the app to **In production**. In *Testing*, Google expires refresh tokens after 7 days
   and only listed test users can connect.

After the first production connection: pick one file, allow it, confirm an assistant can read it, and
confirm it cannot read a file you did not pick.

## Moving from full Drive to drive.file

Earlier versions asked for the full Drive scope. After deploying this version:

1. **Old connections stop being used immediately.** A stored token that carries full Drive (or has no
   scope stamp) counts as not connected. Assistants get "Google Drive is not connected" until the person
   reconnects. No Drive call is made with it.
2. **Revoke them.** On `/admin`, **Revoke old connections** deletes every old token and ends it at Google.
   (Each person's own **Reconnect** or **Disconnect** also revokes theirs.)
3. **Each person reconnects.** Settings → **Reconnect Google Drive**. Their old token is revoked first,
   then Google asks for access to only the files they pick.
4. **Each person picks their files again.** Their allowed list is kept, but Google opens an item to the app
   only once it is picked. Files shows **Not opened yet** next to those items, with a **Pick again**
   button that opens Google's picker searching for that name. Files the app itself created keep working.
   Items shared with paired people work again once their owner picks them.
5. **Remove** `GOOGLE_OAUTH_REFRESH_TOKEN` from the server if it is set. (If kept, every access token it
   yields is still limited to `drive.file`, but it overrides the admin's own connection.)
6. **Remove the full Drive scope** from the consent screen's Data access (step 6 above), and update any
   verification submission that listed it.
