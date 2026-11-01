SUNDARABAHU - LOGIN SETUP (one time, about 10 minutes)
=======================================================

What is in this folder
  wrangler.jsonc     Cloudflare settings (worker name, static files, database)
  worker.js          The server: sign-up, sign-in, reset, admin panel, activity log
  public/index.html  The Sundarabahu app (only shown after sign-in)

STEP 1  Replace the files in your GitHub repo (pradeepprakash108-design/Sundarabahu)
  - Delete the old index.html and netlify.toml from the repo root.
  - Upload wrangler.jsonc, worker.js and the folder public/ (with index.html inside).
    (On github.com: Add file > Upload files; drag the three items in; Commit.)

STEP 2  Check the build settings in Cloudflare
  Workers & Pages > sundarabahu > Settings > Builds
  Deploy command must be:   npx wrangler deploy
  (If it contains --assets or a folder name, remove that part.) Save, then
  open Deployments and let the new commit finish building.
  Cloudflare creates the database (a KV namespace called DB) by itself.
  If the build complains about the KV namespace instead:
     Storage & Databases > KV > Create namespace "sundarabahu-db", copy its ID,
     then in GitHub edit wrangler.jsonc to:  { "binding": "DB", "id": "PASTE-ID-HERE" }

STEP 3  Set the administrator password (never put it in GitHub)
  Workers & Pages > sundarabahu > Settings > Variables and Secrets > Add
     Type: Secret    Name: ADMIN_PASSWORD    Value: (your admin password)
  Optional variable: ADMIN_USER (default is sundarabahuadmin).
  Click Deploy/Save. It takes effect immediately.

STEP 4  Use it
  Open https://sundarabahu.saketham.workers.dev
  Friends: Sign up (any username, password of 8+ characters) or Sign in.
  You:     sign in as  sundarabahuadmin  -> you land on the Admin page:
             Activity log  - sign-ups, sign-ins, wrong passwords, logouts, resets,
                             with date/time (IST), city, device. Filter + CSV download.
             Users         - sign-up date, last sign-in, sign-in count, and buttons
                             Reset code / Disable / Delete.

Forgot password
  Friend asks you -> Admin page > Users > "Reset code" next to their name ->
  give them the one-time code (valid 24 hours) -> on the sign-in page they tap
  "Forgot password", enter username + code + a new password.

Good to know
  - Passwords are stored only as salted PBKDF2 hashes; nobody (not even you) can read them.
  - 8 wrong passwords lock that username for 15 minutes.
  - The log stores username, time, city/country and browser/device - not IP addresses.
  - Cloudflare's free KV plan allows about 1,000 writes a day (each sign-in uses two);
    plenty for friends. Upgrade if you ever share it widely.
  - The offline Sundarabahu-Offline.html file and the claude.ai preview have NO login;
    login protects only the website above. Do not share the offline file if you
    want the website to be the only way in.
  - To update the app later, replace public/index.html in GitHub.
  - Because the admin password was typed in a chat, consider changing it in
    Variables and Secrets once everything works.
