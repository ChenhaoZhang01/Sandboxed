// Spot-the-Phish training scenarios. Each renders a realistic artifact (email,
// text, scanned URL, login page, or social DM) that the player judges as
// "legit" or "phishing". `answer` is the ground truth; `flags` are the teaching
// points shown in the feedback panel afterward.
//
// difficulty: 1 = obvious, 2 = needs a closer look, 3 = subtle / deceptive.
const scenarios = [
  // ---------- difficulty 1 ----------
  {
    id: "sms-usps",
    category: "sms",
    difficulty: 1,
    answer: "phish",
    sms: {
      sender: "+1 (830) 214-0099",
      lines: [
        "USPS: Your package is on hold. A $1.99 redelivery fee is required.",
        "Pay now to release it: usps-redelivery.xyz/pay",
      ],
    },
    explanation: "Real carriers don't text you a random number to collect a fee on a sketchy domain.",
    flags: [
      "Sender is an unknown personal mobile number, not USPS",
      "Domain is usps-redelivery.xyz — not usps.com",
      "Tiny fee + urgency is a classic lure to capture your card",
    ],
  },
  {
    id: "email-teacher",
    category: "email",
    difficulty: 1,
    answer: "safe",
    email: {
      fromName: "Ms. Rivera",
      fromAddr: "k.rivera@yourschool.edu",
      subject: "Friday field trip permission form",
      lines: [
        "Hi everyone — attached is the permission slip for Friday's museum trip.",
        "Please bring it back signed by Thursday. Thanks!",
      ],
    },
    explanation: "Expected message, from your school's real domain, with no link or credential request.",
    flags: [
      "Sender is on your school's real @yourschool.edu domain",
      "It matches something you're actually expecting",
      "No links, no urgency, no request for passwords",
    ],
  },
  {
    id: "sms-otp",
    category: "sms",
    difficulty: 1,
    answer: "safe",
    sms: {
      sender: "VERIFY (32665)",
      lines: [
        "Your verification code is 838213.",
        "Don't share this code with anyone. We will never call to ask for it.",
      ],
    },
    explanation: "A one-time code with no link is normal — the danger is only if someone asks you to read it back.",
    flags: [
      "It's a one-time passcode you requested, not a link to click",
      "No link or attachment to interact with",
      "It explicitly warns you never to share the code",
    ],
  },

  // ---------- difficulty 2 ----------
  {
    id: "email-paypal",
    category: "email",
    difficulty: 2,
    answer: "phish",
    email: {
      fromName: "PayPal Service",
      fromAddr: "service@paypal-secure-team.com",
      subject: "Your account access has been limited",
      lines: [
        "We noticed unusual activity. Your account is limited until you confirm your details.",
        "Restore your account within 24 hours to avoid permanent suspension.",
      ],
      link: { text: "Restore my account", url: "https://paypal-secure-team.com/login" },
    },
    explanation: "The real PayPal only ever lives on paypal.com — 'paypal-secure-team.com' is an attacker's domain.",
    flags: [
      "Sender/link domain is paypal-secure-team.com, not paypal.com",
      "Threatens permanent suspension to rush you",
      "Generic greeting and a 24-hour deadline",
    ],
  },
  {
    id: "url-amazon-real",
    category: "url",
    difficulty: 2,
    answer: "safe",
    url: {
      caption: "You scanned a QR code. It wants to open:",
      address: "https://www.amazon.com/gp/css/order-history",
    },
    explanation: "The registered domain is amazon.com — the long path after it is just a normal page.",
    flags: [
      "Registered domain is exactly amazon.com",
      "https with a real, well-known host",
      "The path (/gp/css/order-history) is normal, not a red flag by itself",
    ],
  },
  {
    id: "url-amazon-fake",
    category: "url",
    difficulty: 2,
    answer: "phish",
    url: {
      caption: "You scanned a QR code. It wants to open:",
      address: "https://amaz0n-account-verify.com/signin",
    },
    explanation: "Read the domain left of the first single slash: amaz0n-account-verify.com is not amazon.com.",
    flags: [
      "'amaz0n' uses a zero to imitate amazon",
      "Real domain is amaz0n-account-verify.com, not amazon.com",
      "'account-verify' + 'signin' is built to harvest logins",
    ],
  },
  {
    id: "email-google-real",
    category: "email",
    difficulty: 2,
    answer: "safe",
    email: {
      fromName: "Google",
      fromAddr: "no-reply@accounts.google.com",
      subject: "Security alert: new sign-in on Windows",
      lines: [
        "Your Google Account was just signed in to on a new Windows device.",
        "If this was you, you don't need to do anything.",
      ],
      link: { text: "Check activity", url: "https://myaccount.google.com/notifications" },
    },
    explanation: "Sender and link both stay on google.com, and it doesn't pressure you or ask for a password.",
    flags: [
      "Sender is accounts.google.com; link is myaccount.google.com",
      "'If this was you, do nothing' — no pressure",
      "Never asks you to type your password into the email",
    ],
  },
  {
    id: "social-ig-video",
    category: "social",
    difficulty: 2,
    answer: "phish",
    social: {
      app: "Instagram · DM",
      name: "Jordan (backup)",
      handle: "@jordan_m_backup2",
      lines: [
        "omg is this you?? 😳 someone posted this video of you",
        "ig-view-clip.com/u/you",
      ],
    },
    explanation: "A 'backup' account + shocking bait + off-platform link is a hijacked-account scam.",
    flags: [
      "It's a 'backup' account, not your friend's real handle",
      "Shock-bait ('is this you?') to make you click fast",
      "Link leaves Instagram to ig-view-clip.com to steal your login",
    ],
  },

  // ---------- difficulty 3 ----------
  {
    id: "email-ms365",
    category: "email",
    difficulty: 3,
    answer: "phish",
    email: {
      fromName: "Microsoft 365",
      fromAddr: "admin@m1crosoft-support.com",
      subject: "Action required: your mailbox storage is full",
      lines: [
        "Your mailbox is 99% full and you will stop receiving email.",
        "Re-validate your account to receive 5 GB of additional storage.",
      ],
      link: { text: "Re-validate mailbox", url: "https://m1crosoft-support.com/owa/verify" },
    },
    explanation: "'m1crosoft' swaps an i for a 1 — a homoglyph trick. Microsoft uses microsoft.com / office.com.",
    flags: [
      "'m1crosoft-support.com' uses a 1 in place of the i",
      "Storage-full + re-validate is a known credential-phish script",
      "Offer of 'free storage' to bait the click",
    ],
  },
  {
    id: "login-netflix",
    category: "login",
    difficulty: 3,
    answer: "phish",
    login: {
      brand: "NETFLIX",
      address: "https://netflix.com.account-billing.info/login",
      note: "Update your payment details to continue watching.",
    },
    explanation: "The real domain is the part before the first single slash: account-billing.info. 'netflix.com.' is just a subdomain on it.",
    flags: [
      "Actual registered domain is account-billing.info",
      "'netflix.com.' is a fake subdomain placed to fool you",
      "Jumps straight to asking for payment details",
    ],
  },
  {
    id: "email-helpdesk",
    category: "email",
    difficulty: 3,
    answer: "phish",
    email: {
      fromName: "IT Help Desk",
      fromAddr: "helpdesk@yourschool.edu",
      subject: "[Action Needed] Mailbox quota exceeded",
      lines: [
        "Your mailbox has exceeded its storage limit. Re-validate within 24 hours or lose access.",
        "Confirm your credentials here:",
      ],
      link: { text: "Re-validate account", url: "https://yourschool-helpdesk.net/login" },
    },
    explanation: "The 'from' address can be spoofed — judge the link. It leaves your school for yourschool-helpdesk.net.",
    flags: [
      "Link domain is yourschool-helpdesk.net, NOT yourschool.edu",
      "A 'from' address is easy to forge — trust the link, not the name",
      "Quota + 24-hour deadline + 'confirm your credentials' = phish",
    ],
  },
  {
    id: "url-github-real",
    category: "url",
    difficulty: 3,
    answer: "safe",
    url: {
      caption: "A link in a forum post points to:",
      address: "https://github.com/login",
    },
    explanation: "github.com is the real registered domain and /login is GitHub's genuine sign-in path.",
    flags: [
      "Registered domain is exactly github.com",
      "No lookalike characters or extra subdomains",
      "A login page on the brand's own domain is expected",
    ],
  },
  {
    id: "sms-family",
    category: "sms",
    difficulty: 3,
    answer: "phish",
    sms: {
      sender: "+1 (475) 002-8841",
      lines: [
        "Hi mom, I dropped my phone in the toilet 😭 this is my temporary number.",
        "Can you help me pay a bill? I'll send the details — don't call my old phone.",
      ],
    },
    explanation: "The 'new number / don't call my old phone' family-emergency script is a money scam — verify on the known number.",
    flags: [
      "Unknown number claiming to be family on a 'new phone'",
      "Tells you NOT to call the old (real) number — to block verification",
      "Pivots quickly to sending money",
    ],
  },
  {
    id: "login-chase-real",
    category: "login",
    difficulty: 3,
    answer: "safe",
    login: {
      brand: "CHASE",
      address: "https://secure.chase.com",
      note: "Sign in to your account.",
    },
    explanation: "secure.chase.com is a real subdomain of chase.com — the registered domain is genuinely chase.com.",
    flags: [
      "Registered domain is chase.com (secure. is its real subdomain)",
      "https on the bank's own domain",
      "No lookalike characters or deceptive extra domain after it",
    ],
  },
];
