// AI threat narrative. Turns the structured detonation report into a punchy,
// plain-English "what this link would do to you" story using Gemini. Opt-in
// (needs GEMINI_API_KEY) and best-effort: any failure returns null and the
// detonation result is unaffected.

import { GoogleGenAI } from "@google/genai";

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
  "what this link is and what it would do to a victim who clicked it on their own " +
  "device. Be concrete and specific: name the brand it impersonates, how many " +
  "redirects it bounces through, and where a typed password would actually be sent. " +
  "Do not hedge. End with a one-line bottom line on whether to trust it. " +
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
