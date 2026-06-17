import './style.css'
import gsap from 'gsap'

// =============================================================================
// Sandboxed snap-scroll engine
// Snap mechanic + feel ported from reference.html (the user's verified demo):
//   - coupled full slide, duration 0.7s, ease power3.inOut
//   - input locked during a transition, with a short cooldown afterwards
//   - inputs: wheel, 50px touch swipe, arrows/PageUp-Down/Space/Home/End, dots, nav
// Per-layer animations are ADAPTED to flat background images: each background
// fades in + slow-zooms (idle) using the locked bg values, and the text reveals
// in using the locked entrance values. These run INDEPENDENTLY of the slide
// timeline so the long idle-zoom never holds the input lock open.
// =============================================================================

const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches

const panels = Array.from(document.querySelectorAll('.panel'))
const dots = Array.from(document.querySelectorAll('.dot'))
const curEl = document.getElementById('cur')
const total = panels.length

let current = 0
let isAnimating = false

// Per-section background values (from the LOCKED table — bg entrance opacity +
// parallel continuous idle-scale). Index matches section order.
const BG = [
  { opacityDur: 1.6, scale: 1.12, scaleDur: 11.6 }, // 1 — The problem
  { opacityDur: 1.4, scale: 1.22, scaleDur: 8.4 },  // 2 — How it works
  { opacityDur: 1.6, scale: 1.17, scaleDur: 10.6 }, // 3 — Get started
]

const layers = (p) => ({
  bg: p.querySelector('.layer-bg'),
  reveals: p.querySelectorAll('.reveal'),
})

// Initial layout: first panel centered, the rest parked one screen below;
// all backgrounds/text start hidden so they can animate in.
panels.forEach((p, i) => {
  gsap.set(p, { yPercent: i === 0 ? 0 : 100, zIndex: 1 })
  const { bg, reveals } = layers(p)
  gsap.set(bg, { opacity: 0, scale: 1 })
  gsap.set(reveals, { opacity: 0, yPercent: 30 })
})

// Play a panel's entrance. Runs as its own (independent) tweens so the long
// idle-zoom does NOT gate the snap's input lock. Called at the same instant as
// the slide, so entrance + idle still run in parallel with the snap.
function animateIn(index) {
  const p = panels[index]
  const { bg, reveals } = layers(p)
  const cfg = BG[index] || BG[0]

  gsap.killTweensOf([bg, ...reveals])

  if (reduce) {
    gsap.set(bg, { opacity: 1, scale: 1 })
    gsap.set(reveals, { opacity: 1, yPercent: 0 })
    return
  }

  // TWO parallel bg tweens: opacity (short, snappy) and scale (long = continuous
  // idle zoom). This is the locked two-tween-at-t0 pattern.
  gsap.fromTo(bg, { opacity: 0 }, { opacity: 1, duration: cfg.opacityDur, ease: 'power3.out' })
  gsap.fromTo(bg, { scale: 1 }, { scale: cfg.scale, duration: cfg.scaleDur, ease: 'none' })
  // Text reveal — locked entrance values (yPercent 30→0, opacity 0→1, 1.2s,
  // delay 0.2s, power3.out), lightly staggered when a section has two blocks.
  gsap.fromTo(
    reveals,
    { opacity: 0, yPercent: 30 },
    { opacity: 1, yPercent: 0, duration: 1.2, delay: 0.2, ease: 'power3.out', stagger: 0.08 }
  )
}

function updateUI() {
  dots.forEach((d, i) => d.classList.toggle('is-active', i === current))
  panels.forEach((p, i) => p.classList.toggle('is-active', i === current))
  curEl.textContent = String(current + 1).padStart(2, '0')
}

function goTo(target) {
  if (isAnimating || target === current || target < 0 || target >= total) return
  isAnimating = true

  const dir = target > current ? 1 : -1 // 1 = downward
  const outgoing = panels[current]
  const incoming = panels[target]

  gsap.set(outgoing, { zIndex: 1 })
  gsap.set(incoming, { zIndex: 2, yPercent: dir * 100 })

  const d = reduce ? 0.45 : 0.7
  const ease = reduce ? 'power2.out' : 'power3.inOut'

  // entrance + idle for the incoming panel, started now (independent timeline)
  animateIn(target)

  // the slide timeline alone controls the input lock — it finishes at ~0.7s
  const tl = gsap.timeline({
    onComplete: () => {
      current = target
      updateUI()
      // brief cooldown so trailing trackpad momentum doesn't trigger a 2nd jump
      gsap.delayedCall(reduce ? 0 : 0.12, () => { isAnimating = false })
    },
  })

  // panels slide together, one full screen (the reference feel)
  tl.to(outgoing, { yPercent: -dir * 100, duration: d, ease }, 0)
    .to(incoming, { yPercent: 0, duration: d, ease }, 0)

  if (!reduce) {
    // fade the outgoing text so it doesn't linger during the slide
    tl.to(layers(outgoing).reveals, { opacity: 0, duration: d * 0.4, ease: 'power1.in' }, 0)
  }
}

// ---------- input: wheel ----------
window.addEventListener('wheel', (e) => {
  e.preventDefault()
  if (isAnimating) return
  if (Math.abs(e.deltaY) < 8) return
  goTo(current + (e.deltaY > 0 ? 1 : -1))
}, { passive: false })

// ---------- input: touch (50px swipe) ----------
let touchY = null
window.addEventListener('touchstart', (e) => { touchY = e.touches[0].clientY }, { passive: true })
window.addEventListener('touchmove', (e) => { e.preventDefault() }, { passive: false })
window.addEventListener('touchend', (e) => {
  if (touchY === null || isAnimating) return
  const dy = touchY - e.changedTouches[0].clientY
  if (Math.abs(dy) > 50) goTo(current + (dy > 0 ? 1 : -1))
  touchY = null
}, { passive: true })

// ---------- input: keyboard ----------
window.addEventListener('keydown', (e) => {
  if (isAnimating) return
  switch (e.key) {
    case 'ArrowDown': case 'PageDown': case ' ':
      e.preventDefault(); goTo(current + 1); break
    case 'ArrowUp': case 'PageUp':
      e.preventDefault(); goTo(current - 1); break
    case 'Home': e.preventDefault(); goTo(0); break
    case 'End': e.preventDefault(); goTo(total - 1); break
  }
})

// ---------- input: dots + nav links ----------
dots.forEach((dot) => dot.addEventListener('click', () => goTo(parseInt(dot.dataset.index, 10))))
document.querySelectorAll('[data-go]').forEach((a) =>
  a.addEventListener('click', (e) => { e.preventDefault(); goTo(parseInt(a.dataset.go, 10)) })
)

// CTA links — point these at the real Sandboxed app URL when it's deployed.
document.querySelectorAll('[data-cta]').forEach((a) =>
  a.addEventListener('click', (e) => { e.preventDefault(); /* TODO: window.location = app URL */ })
)

// ---------- boot ----------
animateIn(0) // play section 1's entrance on load
updateUI()
