// Credential trap ("canary auto-fill"). In the sandbox only, we type OBVIOUSLY
// FAKE credentials into a login form and let the page try to submit them — then we
// intercept and ABORT the outbound request so nothing ever leaves. This proves,
// dynamically, exactly where a phishing kit would ship a victim's password without
// ever sending a real one.

import { randomBytes } from "crypto";

/**
 * Build a fresh canary identity. The password carries a unique, easy-to-spot token
 * so we can recognise the submission in an outbound request's body/URL.
 */
export function makeCanary() {
  const token = `SANDBOX-DECOY-${randomBytes(6).toString("hex")}`;
  return {
    email: "canary@sandbox.invalid",
    password: token,
    token,
  };
}

/**
 * Fill the first login form with canary values and attempt to submit it.
 * Runs entirely in the page; never throws back to the caller.
 * @returns {Promise<boolean>} whether a password field was found + filled.
 */
export async function fillCredentialForm(page, canary) {
  try {
    return await page.evaluate((c) => {
      const pwd = document.querySelector('input[type="password"]');
      if (!pwd) return false;

      const fire = (el, value) => {
        const setter = Object.getOwnPropertyDescriptor(
          window.HTMLInputElement.prototype,
          "value"
        )?.set;
        if (setter) setter.call(el, value);
        else el.value = value;
        el.dispatchEvent(new Event("input", { bubbles: true }));
        el.dispatchEvent(new Event("change", { bubbles: true }));
      };

      const form = pwd.form;

      // Identify the username/email field: prefer one inside the same form, else
      // the first text/email/tel input on the page.
      const candidates = Array.from(
        (form || document).querySelectorAll(
          'input[type="text"], input[type="email"], input[type="tel"], input:not([type])'
        )
      );
      const userField = candidates[0] || null;

      if (userField) fire(userField, c.email);
      fire(pwd, c.password);

      // Submit without relying on the user. requestSubmit() runs validation +
      // submit handlers; fall back to clicking a submit control, then form.submit().
      if (form) {
        if (typeof form.requestSubmit === "function") {
          form.requestSubmit();
        } else {
          const btn = form.querySelector(
            'button[type="submit"], input[type="submit"], button:not([type])'
          );
          if (btn) btn.click();
          else form.submit();
        }
      } else {
        // No <form>: many SPA logins wire a button handler instead.
        const btn = document.querySelector(
          'button[type="submit"], input[type="submit"], button'
        );
        if (btn) btn.click();
      }
      return true;
    }, canary);
  } catch {
    return false;
  }
}

/**
 * Decide whether an intercepted request is the canary credential submission.
 * Matches when the unique token appears in the POST body or the URL (GET forms).
 * @returns {{url,host,method,crossDomain,sentPassword}|null}
 */
export function matchCanaryHit(req, token, finalHost) {
  try {
    const url = req.url();
    if (!/^https?:/i.test(url)) return null;

    const postData = typeof req.postData === "function" ? req.postData() : null;
    const inBody = postData && postData.includes(token);
    const inUrl = url.includes(token);
    if (!inBody && !inUrl) return null;

    const host = new URL(url).hostname.replace(/^www\./, "");
    const fh = (finalHost || "").replace(/^www\./, "");
    return {
      url,
      host,
      method: (req.method && req.method()) || "POST",
      crossDomain: !!host && !!fh && host !== fh,
      sentPassword: true,
    };
  } catch {
    return null;
  }
}
