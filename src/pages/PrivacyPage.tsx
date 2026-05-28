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
          Last updated: May 2026
        </p>

        <div className="space-y-8 text-sm leading-7">
          <section>
            <h2 className="mb-3 text-base font-medium text-white">What SecURL does</h2>
            <p>
              SecURL analyses the external security posture of websites and web services. You
              provide a URL, our service checks it using publicly observable signals — HTTP
              response headers, TLS configuration, DNS records, certificate metadata, and
              related data — and returns a score and grade. No credentials, no login, and no
              access to anything that isn't already visible from the public internet.
            </p>
          </section>

          <section>
            <h2 className="mb-3 text-base font-medium text-white">Data we process</h2>
            <p>
              When you scan a URL, that URL is sent to our servers to perform the analysis.
              We do not store URLs or scan results against any personal identity. Scan
              results returned to the app are stored locally on your device only and are
              not transmitted back to us.
            </p>
            <p className="mt-4">
              To allow you to retrieve your own scans and prevent abuse, each installation
              of the app generates an anonymous random identifier. This identifier is stored
              on your device and sent with scan requests. It contains no personal information
              and cannot be linked to you.
            </p>
          </section>

          <section>
            <h2 className="mb-3 text-base font-medium text-white">Data we do not collect</h2>
            <p>
              We do not collect your name, email address, location, device identifiers, or
              any other personal information. We do not require an account. We do not use
              advertising or tracking SDKs. We do not sell, share, or transfer any data to
              third parties for marketing purposes.
            </p>
          </section>

          <section>
            <h2 className="mb-3 text-base font-medium text-white">Infrastructure</h2>
            <p>
              The SecURL backend runs on Railway. Standard server logs may capture IP
              addresses and request metadata for a limited period for operational purposes
              such as debugging and abuse prevention. These logs are not used for
              profiling and are not retained long-term.
            </p>
          </section>

          <section>
            <h2 className="mb-3 text-base font-medium text-white">Your data on device</h2>
            <p>
              Scan history, monitored targets, and your anonymous scan token are stored
              locally on your device using standard app storage. This data never leaves
              your device except as described above. Uninstalling the app removes all
              locally stored data.
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
