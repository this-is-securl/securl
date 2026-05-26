Dev.to Article Draft #2
Title: DMARC explained: how to stop people spoofing your email domain
Tags: security, webdev, email, tutorial
Target keyword: "DMARC explained" / "DMARC setup"
CTA: Check your DMARC and full email posture at SecURL (free)

---

ARTICLE

Here is something most developers don't know about their own domain: even if your company never sends a single marketing email, someone else can send email pretending to be you. Without a DMARC record, anyone on the internet can craft an email that says it came from yourcompany.com, and most mail servers will deliver it.

This is not a theoretical risk. It is happening constantly. The attack is cheap to run, requires no special access, and the only defence is a DNS record that takes about twenty minutes to configure.

This article explains what DMARC is, how it works alongside SPF and DKIM, and how to set it up properly.


The problem: your domain is not protected by default

When an email server receives a message claiming to be from support@yourcompany.com, it has to decide whether to trust that claim. Without any guidance from you, it has almost no way to verify it. Some mail servers will look at whether the sending IP is plausible. Most will just deliver it.

That means a phisher can send "from" your domain to your customers, your partners, or your employees. They can impersonate your support team, your billing department, or your CEO. The email will show your domain in the From: field. The reply-to might even look legitimate.

DMARC is your way of publishing a policy that tells receiving mail servers what to do when a message claims to be from your domain but cannot be verified.


What DMARC actually does

DMARC stands for Domain-based Message Authentication, Reporting and Conformance. That name is accurate but not very illuminating, so here is the practical version.

When you publish a DMARC record in DNS, you are telling the world: "Messages that claim to come from my domain should be authenticated using SPF and DKIM. If they fail both checks, here is what you should do with them." The three options for that policy are none (monitor only), quarantine (send to spam), and reject (refuse delivery outright).

DMARC does not work in isolation. It depends on two other records being in place:

SPF (Sender Policy Framework) is a DNS record listing the IP addresses and services that are allowed to send email on behalf of your domain. When a mail server receives a message, it checks whether the sending IP is on that list.

DKIM (DomainKeys Identified Mail) is a cryptographic signature added to outgoing emails by your mail sending service. The receiving server looks up your public key in DNS and verifies the signature. A valid DKIM signature proves the message was sent by someone with access to your private key and has not been tampered with in transit.

DMARC ties these together. A message passes DMARC if it passes SPF and the SPF domain aligns with your From: domain, or if it passes DKIM and the DKIM domain aligns with your From: domain. If neither check passes, DMARC applies your policy.


Setting it up

There are three steps: SPF first, then DKIM, then DMARC.

For SPF, you add a TXT record to your DNS at your root domain. It looks like this:

```
v=spf1 include:_spf.google.com -all
```

Replace the include: part with whatever your email provider tells you to use. The -all at the end means "reject mail from any IP not listed here." Use -all, not ~all (softfail). Softfail is not a real policy — it just marks the message as suspicious, which most mail servers ignore.

For DKIM, your email sending service (Google Workspace, Postmark, SendGrid, etc.) will give you a public key to add as a TXT record in DNS. They will walk you through the specific steps. The key point is: every service you use to send email from your domain needs its own DKIM selector configured.

For DMARC, you add a TXT record at _dmarc.yourdomain.com. Start with a monitoring-only policy while you make sure everything is configured correctly:

```
v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com
```

The rua address is where aggregate reports get sent. These reports, which arrive daily from major mail providers, show you which services are sending mail claiming to be from your domain. Read them for a week or two before tightening the policy.

Once you have confirmed that all your legitimate sending sources are passing authentication, change p=none to p=quarantine, and eventually to p=reject. A reject policy is the correct end state. Quarantine is acceptable. None is not a policy — it is just monitoring.


Common mistakes

Publishing SPF without -all. The softfail ~all is almost useless. Use the hardfail -all.

Not configuring DKIM for every sending service. If you send transactional email through Postmark, marketing email through Mailchimp, and internal alerts through SendGrid, each of those needs its own DKIM record. Missing one means those messages will fail DMARC.

Setting pct to less than 100. DMARC has a percentage field that lets you apply the policy to only a fraction of failing messages. It exists for gradual rollout. Do not leave it below 100 permanently.

Thinking p=none is fine. A lot of domains have DMARC records with p=none and consider the job done. None means "do nothing, just report." Anyone can still spoof your domain and it will be delivered. The goal is p=reject.

Not monitoring the reports. The aggregate reports are how you find out if a legitimate service is misconfigured before you tighten the policy. There are free tools to parse them (dmarcian has a free tier). Read them.


What a good configuration looks like

Once everything is set up correctly, your DMARC record should look something like:

```
v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@yourdomain.com; ruf=mailto:dmarc-forensic@yourdomain.com
```

And your deliverability posture will include: SPF with hardfail (-all), DKIM records for every sending service, DMARC with reject policy at 100%.

From there, if you want to go further: MTA-STS publishes a policy telling senders to only deliver over encrypted connections. TLS-RPT gives you reports when delivery over TLS fails. BIMI lets you attach a brand logo to authenticated emails in supported mail clients.

Most teams do not get that far. But SPF + DKIM + DMARC with p=reject is the baseline. Without it, your domain is open to impersonation.


Checking what you have now

You can check your current DMARC, SPF, DKIM, and related DNS setup with SecURL. Paste your domain at app.securl.online and the DNS and email trust section will show you exactly what is published, what the policy is, what is missing, and what to fix.

It reads the same signals a receiving mail server would see, so you get an accurate picture of what the real world sees when it evaluates mail from your domain.
