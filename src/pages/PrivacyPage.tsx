export function PrivacyPage() {
  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-300">
      <div className="mx-auto max-w-2xl px-6 py-16 sm:py-24">
        <a
          href="/"
          className="mb-10 inline-flex items-center gap-2 text-sm text-zinc-500 transition-colors hover:text-zinc-300"
        >
          ← securl.online
        </a>

        <h1 className="mb-2 text-2xl font-semibold tracking-tight text-white">
          Privacy Policy
        </h1>
        <p className="mb-10 text-sm text-zinc-500">
          Last updated: June 2026
        </p>

        <div className="space-y-8 text-sm leading-7">
          <section>
            <h2 className="mb-3 text-base font-medium text-white">What SecURL does</h2>
            <p>
              SecURL analyses the external security posture of websites and web services. You
              provide a URL, our service checks it using publicly observable signals — HTTP
              response headers, TLS configuration, DNS records, certificate metadata, and
              related data — and returns a score and grade. No target credentials and no
              special access are required; SecURL only analyses information visible from
              the public internet.
            </p>
          </section>

          <section>
            <h2 className="mb-3 text-base font-medium text-white">Data we process</h2>
            <p>
              When you scan a URL, that URL is sent to our servers to perform the analysis.
              We store scan records, monitored targets, scan status, summary data, and the
              resulting report so you can reopen history, compare changes, and use monitoring
              across the web app, API, and companion apps.
            </p>
            <p className="mt-4">
              To allow you to retrieve your own scans and prevent abuse, each installation
              of the app generates a random scan-owner token. The token is stored on your
              device and sent with scan requests. On our servers it is stored as a salted
              fingerprint rather than the original token.
            </p>
            <p className="mt-4">
              If you create an account, we collect your email address, optional display name,
              password hash, session records, API key fingerprints, saved scans, and monitored
              targets. API keys and sessions are stored as one-way fingerprints; the original
              secret is only shown to you when it is created.
            </p>
            <p className="mt-4">
              We also collect minimal operational telemetry such as page-load counts, traffic
              source categories, funnel events, scan timing, failure classes, and rate-limit
              counters. We hash or truncate identifiers used for abuse prevention and avoid
              storing full target paths or query strings in telemetry.
            </p>
          </section>

          <section>
            <h2 className="mb-3 text-base font-medium text-white">What we do not collect</h2>
            <p>
              We do not collect credentials for the sites you scan. We do not require an
              account for basic scanning. We do not use advertising SDKs, sell personal data,
              or share data with third parties for marketing purposes.
            </p>
          </section>

          <section>
            <h2 className="mb-3 text-base font-medium text-white">Infrastructure</h2>
            <p>
              The SecURL backend runs on Railway with durable storage for account-backed
              scans and monitoring. Static web pages are hosted separately. Operational logs
              may include request metadata, hashed client identifiers, target origins, and
              failure details for debugging, reliability, and abuse prevention. These logs
              are not used for advertising or profiling.
            </p>
          </section>

          <section>
            <h2 className="mb-3 text-base font-medium text-white">Your data and sharing</h2>
            <p>
              Anonymous scan-owner tokens are stored locally in your browser or app. Browser
              account sessions are stored in session storage and are cleared when you sign
              out or the session expires. Companion apps may keep local scan history for
              offline access.
            </p>
            <p className="mt-4">
              If you copy or open a shared report link, the completed scan can be viewed by
              anyone who has that link. Shared report links do not require an account.
            </p>
          </section>

          <section>
            <h2 className="mb-3 text-base font-medium text-white">Changes to this policy</h2>
            <p>
              If we make material changes to how we handle data, we will update this page
              and revise the date at the top. Continued use of SecURL after changes are
              posted means you accept the updated policy.
            </p>
          </section>

          <section>
            <h2 className="mb-3 text-base font-medium text-white">Contact</h2>
            <p>
              Questions about this policy or your data can be sent to{" "}
              <a
                href="mailto:hello@securl.online"
                className="text-zinc-400 underline underline-offset-2 hover:text-white"
              >
                hello@securl.online
              </a>
              .
            </p>
          </section>
        </div>
      </div>
    </div>
  );
}
