# Distraction Guard: for the friend holding the keys

Jack has asked you to hold the keys to a content-filtering system on their
laptop. This document is for you. Read it before you enroll the
authenticator app or set the root password — everything here explains what
you're agreeing to and how to do it safely.

## What this system does

It's a network filter that blocks distracting categories of content
(adult sites, social media feeds, and topics Jack has chosen) on Jack's
laptop, all the time, for every app and browser. Jack can make it *stricter* any time,
instantly, with no help from you. Making it *less strict* — unblocking a
site, allowing something temporarily, changing a setting — always needs a
one-time code from your phone.

You are not a content moderator. You don't see what Jack is blocking or
why. You see a request like "unblock example.com" or "allow example.com
for 30 minutes," and you decide whether to read out the 6-digit code your
authenticator app is showing. That's the whole job, day to day.

## What you're holding

1. **A TOTP secret** in an authenticator app on your phone (Aegis, 2FAS,
   Ente Auth, or similar — anything that can export/back up the secret).
   This generates a new 6-digit code every 30 seconds. It's the only way
   to loosen any rule once the system is locked.
2. **The root password** for the laptop, set by you (`sudo passwd root`
   during the lock ceremony), known only to you. This is break-glass —
   for when the system itself is broken, not for day-to-day unblocking.

## Day to day: what a request looks like

Jack will text or otherwise tell you they want to run a command like:

```
sudo guardctl unblock example.com
sudo guardctl allow-temp example.com 30
```

The terminal will print exactly what the command does (e.g. "Allow
example.com for 30 minutes") *before* asking for a code — Jack sees this
too, and if notifications are set up, you get a message with the same
summary once a code is actually used. **Read that summary before you give
a code out.** If a text just says "give me a code" with no explanation of
what it's for, ask what it's for. You're allowed to say no.

The code your app shows is valid for about a minute and can only be used
once. If Jack tries to use the same code again, it fails.

**Five wrong codes in a row locks the system out** for 15 minutes, then 30,
then 1 hour, doubling each time up to 24 hours. If you get a notification
about a lockout and you didn't give out a code, someone (probably Jack, in
the moment) is guessing. That's expected to happen occasionally and isn't
an emergency — just don't give them a code until they explain.

## What you should NOT do

- **Don't give a code "just to make the notifications stop."** A code
  either does what the printed summary says or it doesn't get given.
- **Don't give out the root password for a normal unblock request.** Root
  is break-glass — for when `guardctl` itself is broken, not a shortcut
  around the code system. If you find yourself using it routinely,
  something about the setup should change; talk to Jack about it (or
  reach out to whoever helped set this up).
- **Don't re-enroll the authenticator without Jack physically present**
  (`sudo guardctl totp-enroll` overwrites the current secret). This is a
  security-sensitive action and one of the LOOSEN commands, so it needs a
  *current* valid code to run in the first place — which is exactly the
  safety check it's protecting.

## Notifications

If Jack turned on notifications, you'll get a message on your phone for:

- every time a code is used (what it unlocked, for how long)
- every lockout (5 wrong codes in a row)
- the system switching to "degraded mode" (the content proxy is down;
  DNS-level and browser-level blocking are still active, but the smarter
  checks are paused) and switching back
- a daily "still here" heartbeat

**A missing heartbeat for more than a day or two is the main thing to
watch for.** It usually means something mundane (laptop off, no internet),
but it's also what you'd see if someone physically tampered with the
machine to disable the filter. If you notice one missing and can't reach
Jack, that's worth following up on.

## If Jack asks you to remove the whole thing

That's a legitimate request they're allowed to make — this is their
system, and you holding the keys doesn't mean you get to override taking
it down entirely if that's genuinely what they want, done with a clear
head, not in the middle of an urge. A reasonable bar: talk about it when
neither of you is walking away from a text mid-conversation, and if it's
really a longer-term reversal, do it in person the same way you locked it.
To actually remove everything: `sudo bash uninstall.sh` (needs the root
password once jack's own sudo is gone), or `sudo guardctl emergency-off`
if it's not fully locked yet.

## The lock ceremony (what you're about to do together)

Do this together, in person, in this order. Allow about 20 minutes.

1. Jack runs `sudo guardctl doctor`. Every line should say OK.
2. `sudo guardctl notify-setup`. Subscribe to the link it prints in the
   **ntfy** app on your phone, and confirm the test message arrives.
3. `sudo guardctl totp-enroll`. Jack looks away. You scan the QR code into
   your authenticator app and **back it up** (export/backup in the app; if
   your phone is lost with no backup, only the root password gets back in).
   Then type the current code at the prompt. Enrollment only counts once a
   code from your app is accepted.
4. You run `sudo passwd root` yourself and set a password only you know.
   Save it in your own password manager. This is the break-glass.
5. Reboot into the firmware setup (F2 at the Dell logo). Set an
   administrator password, and disable booting from USB/external devices.
   Otherwise a USB stick bypasses everything.
6. Jack runs `sudo guardctl lock --dry-run` and you read it together: all
   prechecks OK, and the list of changes it will make.
7. Jack runs `sudo guardctl lock`. You type a code. It removes Jack from
   the wheel (sudo) and docker groups, leaves him sudo for `guardctl` and
   `guard-pkg` only, turns off the boot menu editor, and makes the audit
   log append-only. If anything fails, it undoes itself and says why.
8. Reboot (the old login still carries the old groups).
9. Checklist, together:
   - `sudo guardctl doctor`: every line OK, including the `lock:` lines.
   - `sudo -l` lists only guardctl and guard-pkg; `sudo pacman -Syu` is
     refused, while `sudo guard-pkg update` works.
   - `sudo guardctl unblock example.com` asks for a code; a wrong one fails.
   - `su` asks for your root password.
   - Pressing `e` at the boot menu does nothing.
10. **Rehearse getting out:** `sudo guardctl unlock` with your code, check
    `sudo -l` shows full access after a re-login, then lock again (steps 6
    to 8). Now you both know the way back works.

## Unlocking later (e.g. end of semester)

`sudo guardctl unlock`, plus one code from you. Jack's full sudo, wheel and
docker groups, and the boot editor come back after a re-login. If guardctl
itself is broken: log in as root with your password and run
`bash /home/jack/.distraction-guard-setup/uninstall.sh`.

## What the lock can't stop

It's a strong speed bump, not a vault. Jack could still pull the drive,
reset the firmware (the CMOS battery), or use another device. If the
filter process dies for 5 minutes, it falls back to a weaker DNS and
Firefox block list, and you get a notification every time that happens.
