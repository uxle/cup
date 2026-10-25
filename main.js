/**
 * CuteFish Universal Package (CUP v3.0)
 * GitHub Pages Interactive Script
 * Created by UXLE • Follows Cutefish OS Design Guidelines
 */

document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initTerminalTabs();
  initCopyButtons();
  initShowcaseTabs();
  initSimulator();
});

/* ==========================================================================
   1. Theme Management (Light / Dark with Cutefish OS Palette)
   ========================================================================== */
function initTheme() {
  const themeToggle = document.getElementById('themeToggle');
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)');
  const savedTheme = localStorage.getItem('cup_theme');

  const currentTheme = savedTheme || (prefersDark.matches ? 'dark' : 'light');
  applyTheme(currentTheme);

  if (themeToggle) {
    themeToggle.addEventListener('click', () => {
      const nextTheme = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      applyTheme(nextTheme);
      localStorage.setItem('cup_theme', nextTheme);
    });
  }

  prefersDark.addEventListener('change', (e) => {
    if (!localStorage.getItem('cup_theme')) {
      applyTheme(e.matches ? 'dark' : 'light');
    }
  });
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  const themeToggle = document.getElementById('themeToggle');
  if (!themeToggle) return;

  const sunIcon = `
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="12" cy="12" r="5"></circle>
      <line x1="12" y1="1" x2="12" y2="3"></line>
      <line x1="12" y1="21" x2="12" y2="23"></line>
      <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
      <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
      <line x1="1" y1="12" x2="3" y2="12"></line>
      <line x1="21" y1="12" x2="23" y2="12"></line>
      <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
      <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
    </svg>`;

  const moonIcon = `
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
    </svg>`;

  themeToggle.innerHTML = theme === 'dark' ? sunIcon : moonIcon;
  themeToggle.setAttribute('aria-label', theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode');
}

/* ==========================================================================
   2. Terminal Tabs (Interactive Shell Snippets)
   ========================================================================== */
const TERMINAL_SNIPPETS = {
  run: {
    command: 'chmod +x cutefish-calc.cup\n./cutefish-calc.cup',
    html: `
      <div class="cmd-comment"># Native kernel execution via binfmt_misc (Zero-overhead)</div>
      <div class="cmd-line">
        <span class="cmd-prompt">lion@cutefish:~$</span>
        <span class="cmd-text">chmod +x cutefish-calc.cup</span>
      </div>
      <div class="cmd-line">
        <span class="cmd-prompt">lion@cutefish:~$</span>
        <span class="cmd-text">./cutefish-calc.cup</span>
      </div>
      <div class="cmd-output">
        <span class="text-green">[✓] Magic Header verified:</span> CUP v3.0 (Little-Endian)<br>
        <span class="text-green">[✓] Cryptographic Seal:</span> Ed25519 valid (signer: cutefish-team)<br>
        <span class="text-green">[✓] Direct EROFS Mount:</span> 0.8ms zero-copy page cache mount<br>
        <span class="text-cyan">[★] Sandbox:</span> bubblewrap profile initialized (network=isolated)<br>
        <span class="text-amber">[▶] Launching GUI:</span> Cutefish Calculator (C++20 Toolkit)
      </div>`
  },
  verify: {
    command: 'cup verify cutefish-calc.cup --verbose',
    html: `
      <div class="cmd-comment"># Cryptographic integrity & metadata verification</div>
      <div class="cmd-line">
        <span class="cmd-prompt">lion@cutefish:~$</span>
        <span class="cmd-text">cup verify cutefish-calc.cup --verbose</span>
      </div>
      <div class="cmd-output">
        <span class="text-green">Package:</span> com.cutefish.calculator (v1.0.0)<br>
        <span class="text-green">Payload:</span> EROFS 128KB compressed payload, LZ4 block compression<br>
        <span class="text-green">Signature:</span> ED25519-SHA512 OK [KeyID: 0x9AF83E12BC]<br>
        <span class="text-green">Checksum:</span> sha256:d8a4f1bc... MATCH<br>
        <span class="text-cyan">Status:</span> Sealed & Untampered. Safe for isolated execution.
      </div>`
  },
  build: {
    command: 'cup pack ./calculator-build --out cutefish-calc.cup --sign ~/.cup/keys/dev.key',
    html: `
      <div class="cmd-comment"># Pack directory into an atomic signed .cup container</div>
      <div class="cmd-line">
        <span class="cmd-prompt">lion@cutefish:~$</span>
        <span class="cmd-text">cup pack ./calculator-build --out cutefish-calc.cup --sign ~/.cup/keys/dev.key</span>
      </div>
      <div class="cmd-output">
        <span class="text-cyan">[1/4]</span> Generating EROFS compressed filesystem image...<br>
        <span class="text-cyan">[2/4]</span> Parsing AppStream & Cutefish desktop manifest...<br>
        <span class="text-cyan">[3/4]</span> Signing with Ed25519 private key...<br>
        <span class="text-cyan">[4/4]</span> Embedding ELF stub & binfmt_misc magic header...<br>
        <span class="text-green">[✓] Successfully generated cutefish-calc.cup (48.2 KB)</span>
      </div>`
  },
  gui: {
    command: 'cup-gui',
    html: `
      <div class="cmd-comment"># Open Cutefish Toolkit native Software Center</div>
      <div class="cmd-line">
        <span class="cmd-prompt">lion@cutefish:~$</span>
        <span class="cmd-text">cup-gui</span>
      </div>
      <div class="cmd-output">
        <span class="text-green">[✓] Initializing Cutefish Window & Theme Engine...</span><br>
        <span class="text-green">[✓] Discovered 3 installed CUP applications.</span><br>
        <span class="text-cyan">[★] Ready. Displaying Cutefish Package Store.</span>
      </div>`
  }
};

let currentTerminalTab = 'run';

function initTerminalTabs() {
  const tabs = document.querySelectorAll('.terminal-tab');
  const body = document.getElementById('terminalBody');

  if (!tabs.length || !body) return;

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');

      const target = tab.getAttribute('data-tab');
      if (TERMINAL_SNIPPETS[target]) {
        currentTerminalTab = target;
        body.innerHTML = TERMINAL_SNIPPETS[target].html;
      }
    });
  });
}

/* ==========================================================================
   3. Copy to Clipboard
   ========================================================================== */
function initCopyButtons() {
  const copyBtn = document.getElementById('terminalCopyBtn');
  if (copyBtn) {
    copyBtn.addEventListener('click', () => {
      const snippet = TERMINAL_SNIPPETS[currentTerminalTab]?.command || '';
      navigator.clipboard.writeText(snippet).then(() => {
        const originalText = copyBtn.innerHTML;
        copyBtn.innerHTML = `
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="20 6 9 17 4 12"></polyline>
          </svg>
          Copied!
        `;
        copyBtn.style.color = 'var(--accent-green)';
        setTimeout(() => {
          copyBtn.innerHTML = originalText;
          copyBtn.style.color = '';
        }, 2000);
      });
    });
  }

  // Quick command copy buttons (in download / quick start section)
  document.querySelectorAll('.copy-cmd-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const textToCopy = btn.getAttribute('data-cmd');
      if (!textToCopy) return;

      navigator.clipboard.writeText(textToCopy).then(() => {
        const originalText = btn.textContent;
        btn.textContent = 'Copied!';
        btn.classList.add('copied');
        setTimeout(() => {
          btn.textContent = originalText;
          btn.classList.remove('copied');
        }, 2000);
      });
    });
  });
}

/* ==========================================================================
   4. Cutefish Toolkit GUI Showcase Tabs
   ========================================================================== */
const SHOWCASE_DATA = {
  home: {
    title: 'Cutefish Store & Dashboard',
    desc: 'Native C++20 Cutefish Toolkit application presenting installed and featured CUP packages. Displays verified badges, developer signatures, and instant one-click launch capabilities.',
    img: 'docs/screenshots/home.png',
    pills: ['Cutefish::Window', 'Native C++20', 'Glassmorphism', 'Package Discovery']
  },
  app: {
    title: 'Detailed Package Inspector',
    desc: 'Deep inspection view examining AppStream metadata, verified developer signatures, sandboxing permissions, file system contents, and update history.',
    img: 'docs/screenshots/app.png',
    pills: ['AppStream 1.0', 'Ed25519 Badge', 'Sandboxing Matrix', 'Rollback History']
  },
  install: {
    title: 'Zero-Lag Atomic Installer',
    desc: 'Interactive installation modal with real-time EROFS verification progress bar, binfmt registration check, desktop shortcut generator, and safe sandboxing controls.',
    img: 'docs/screenshots/install.png',
    pills: ['Atomic Unpack', 'Zero Duplicate Copies', 'Desktop Integration', 'Safe Sandbox']
  }
};

function initShowcaseTabs() {
  const tabs = document.querySelectorAll('.showcase-tab');
  const titleEl = document.getElementById('showcaseTitle');
  const descEl = document.getElementById('showcaseDesc');
  const pillsEl = document.getElementById('showcasePills');
  const imgEl = document.getElementById('showcaseImg');

  if (!tabs.length || !imgEl) return;

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');

      const key = tab.getAttribute('data-view');
      const data = SHOWCASE_DATA[key];
      if (!data) return;

      imgEl.style.opacity = '0';
      setTimeout(() => {
        imgEl.src = data.img;
        imgEl.alt = data.title;
        if (titleEl) titleEl.textContent = data.title;
        if (descEl) descEl.textContent = data.desc;
        if (pillsEl) {
          pillsEl.innerHTML = data.pills.map(p => `<span class="showcase-pill">${p}</span>`).join('');
        }
        imgEl.style.opacity = '1';
      }, 150);
    });
  });
}

/* ==========================================================================
   5. Interactive Verification Simulator
   ========================================================================== */
function initSimulator() {
  const startBtn = document.getElementById('simStartBtn');
  const logScreen = document.getElementById('simLogScreen');
  const steps = [
    document.getElementById('simStep1'),
    document.getElementById('simStep2'),
    document.getElementById('simStep3'),
    document.getElementById('simStep4')
  ];

  if (!startBtn || !logScreen) return;

  let isRunning = false;

  const logs = [
    {
      stepIdx: 0,
      log: '<span class="text-cyan">[STAGE 1]</span> Scanning ELF header & magic bytes...\n<span class="text-green">[PASS]</span> Valid CUP magic 0x43 0x55 0x50 0x01 (Version 3.0.0 detected)'
    },
    {
      stepIdx: 1,
      log: '\n<span class="text-cyan">[STAGE 2]</span> Checking cryptographic signature chunk...\n<span class="text-green">[PASS]</span> Ed25519 signature validated with trusted keyring (UXLE / Cutefish)'
    },
    {
      stepIdx: 2,
      log: '\n<span class="text-cyan">[STAGE 3]</span> Verifying EROFS filesystem integrity & superblocks...\n<span class="text-green">[PASS]</span> EROFS 128KB LZ4 compression verified. Direct zero-copy memory mount ready.'
    },
    {
      stepIdx: 3,
      log: '\n<span class="text-cyan">[STAGE 4]</span> Enforcing Bubblewrap & AppArmor isolation policies...\n<span class="text-green">[PASS]</span> Sandbox initialized: unshare(CLONE_NEWNET | CLONE_NEWPID). Ready to execute.'
    }
  ];

  startBtn.addEventListener('click', () => {
    if (isRunning) return;
    isRunning = true;
    startBtn.disabled = true;
    startBtn.textContent = 'Verifying Package...';

    // Reset steps
    steps.forEach(s => {
      if (s) {
        s.classList.remove('active', 'passed');
      }
    });
    logScreen.innerHTML = '<span class="text-amber">[INIT]</span> Target: cutefish-calc.cup (48.2 KB)\nConnecting to local CUP engine...';

    let current = 0;

    function runNext() {
      if (current >= logs.length) {
        logScreen.innerHTML += '\n\n<span class="text-green">✔ RESULT: All 4 checks PASSED. Execution granted in 3.8ms!</span>';
        startBtn.disabled = false;
        startBtn.textContent = 'Run Verifier Again';
        isRunning = false;
        return;
      }

      const item = logs[current];
      const stepEl = steps[item.stepIdx];

      if (stepEl) {
        stepEl.classList.add('active');
      }

      setTimeout(() => {
        logScreen.innerHTML += '\n' + item.log;
        logScreen.scrollTop = logScreen.scrollHeight;

        if (stepEl) {
          stepEl.classList.remove('active');
          stepEl.classList.add('passed');
        }

        current++;
        setTimeout(runNext, 450);
      }, 400);
    }

    setTimeout(runNext, 300);
  });
}
