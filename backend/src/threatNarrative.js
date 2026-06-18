// AI threat narrative. Turns the structured detonation report into a punchy,
// plain-English "what this link would do to you" story using Gemini. Opt-in
// (needs GEMINI_API_KEY) and best-effort: any failure returns null and the
// detonation result is unaffected.

import { GoogleGenAI } from "@google/genai";
import { isTrustedDomain } from "./intel/trustedDomains.js";

const NARRATIVE_MODEL = process.env.NARRATIVE_MODEL || "gemini-2.5-flash";
const NARRATIVE_MAX_TOKENS = Number(process.env.NARRATIVE_MAX_TOKENS || 400);

let client = null;
function getClient() {
  if (client) return client;
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return null;
  client = new GoogleGenAI({ apiKey });
  return client;
}

const SYSTEM_PROMPT =
  "You are a cybersecurity analyst explaining the result of a URL detonation to a " +
  "non-technical person. You are given a structured analysis of a link that was " +
  "opened in a sandbox. Write a punchy 2-3 sentence plain-English explanation of " +
  "what this link is and what it would do to a victim who clicked it on their own device. " +
  "CRITICAL: base every claim ONLY on the JSON signals provided. Do NOT say the site " +
  "steals passwords, logs keystrokes, impersonates a brand, or downloads malware unless " +
  "the matching field actually shows it: passwordFields > 0, crossDomainCredPost true, " +
  "credentialTrap.blocked true, brandImpersonation non-empty, phishing.phishing true, or " +
  "downloads non-empty. If those fields are empty or zero, those threats were NOT observed — " +
  "do not invent them. Be concrete only where the data supports it (if it impersonates a " +
  "brand, name it; if credentials would be exfiltrated, say where). " +
  "Your bottom line MUST agree with the `verdict` field: 'safe' => say it looks low-risk and " +
  "no scam/theft signals were found (never say 'do not trust' or imply danger); " +
  "'suspicious' => urge caution; 'dangerous' => say plainly not to trust it. " +
  "Respond with only the explanation: no preamble, no markdown, no reasoning.";

/**
 * Pull just the fields worth handing to the model — keeps the prompt small and
 * avoids shipping base64 screenshots / replay frames.
 */
function summarizeReport(result) {
  const s = result.signals || {};
  const trap = result.credentialTrap || null;
  return {
    verdict: result.verdict,
    score: result.score,
    finalHost: result.finalHost || null,
    trustedHost: isTrustedDomain(result.finalHost || ""),
    requestedUrl: result.requestedUrl || null,
    pageTitle: result.title || null,
    redirectCount: result.redirectCount ?? 0,
    redirectChain: (result.redirectChain || []).slice(0, 8),
    domainAgeDays:
      result.intel && result.intel.domainAge && typeof result.intel.domainAge.ageDays === "number"
        ? result.intel.domainAge.ageDays
        : null,
    brandImpersonation: s.brandImpersonation || [],
    passwordFields: s.passwordFields || 0,
    paymentFields: s.paymentFields || 0,
    crossDomainCredPost: !!s.crossDomainCredPost,
    phishing: result.phishing || null,
    credentialTrap: trap
      ? { blocked: !!trap.blocked, crossDomain: !!trap.crossDomain, host: trap.host || null }
      : null,
    downloads: (result.downloads || []).map((d) => d.suggestedFilename || d.url).slice(0, 5),
    reasons: (result.reasons || []).map((r) => r.reason).slice(0, 12),
  };
}

/**
 * Generate the narrative. Returns a string, or null if the feature is disabled
 * (no API key) or the call fails for any reason.
 */
export async function explainThreat(result) {
  const ai = getClient();
  if (!ai) return null;

  const s = result.signals || {};
  const trustedHost = isTrustedDomain(result.finalHost || s.finalHost || "");
  const hardDanger = Boolean(
    (result.phishing && result.phishing.phishing === true) ||
    (result.credentialTrap && result.credentialTrap.blocked) ||
    (result.downloads && result.downloads.length > 0) ||
    (result.blockedRequests && result.blockedRequests.length > 0) ||
    (s.brandImpersonation && s.brandImpersonation.length > 0) ||
    s.crossDomainCredPost
  );

  // Don't let the AI story contradict the deterministic verdict. When the scan
  // came back clean — a trusted host, or a "safe" verdict with no hard-danger
  // signals — return a grounded low-risk line instead of letting the model
  // confabulate a phishing/keylogging story the signals don't support.
  if (!hardDanger && (trustedHost || result.verdict === "safe")) {
    if (trustedHost) {
      return (
        `This is ${result.finalHost || "a trusted site"}. The signals here look like anti-automation or bot-detection behavior ` +
        `rather than proof of keylogging or phishing, which is common on major services like X/Twitter. ` +
        `Based on these signals alone, I would not treat it as malware.`
      );
    }
    const host = result.finalHost || "this site";
    const title = result.title ? ` ("${result.title}")` : "";
    return (
      `In the sandbox, ${host}${title} didn't trip the scam checks — no brand impersonation, ` +
      `no credential theft, no malicious downloads, and no risky redirects — so it scored ${result.score ?? 0}/100 (safe). ` +
      `Based on these signals it looks low-risk, but only enter personal info on sites you already trust.`
    );
  }

  try {
    const response = await ai.models.generateContent({
      model: NARRATIVE_MODEL,
      contents:
        "Here is the sandbox analysis as JSON:\n\n" +
        JSON.stringify(summarizeReport(result), null, 2),
      config: {
        systemInstruction: SYSTEM_PROMPT,
        maxOutputTokens: NARRATIVE_MAX_TOKENS,
        thinkingConfig: { thinkingBudget: 0 }, // short, fast summary — no thinking needed
      },
    });

    const text = (response.text || "").trim();
    return text || null;
  } catch (err) {
    console.error("threat narrative failed (non-fatal):", err.message || err);
    return null;
  }
}
