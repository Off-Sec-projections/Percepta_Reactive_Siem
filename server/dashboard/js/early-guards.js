    (function earlyGuards() {
      const getUiLang = () => {
        try {
          const v = localStorage.getItem('percepta.ui.lang.v1');
          const s = String(v || '').trim().toLowerCase();
          if (s === 'ur' || s.startsWith('ur-')) return 'ur';
        } catch {}
        return 'en';
      };

      const EARLY_I18N = {
        en: {
          fatal_default_title: 'Dashboard error',
          fatal_open_console: 'Open DevTools Console for the full stack trace.',
          js_error_title: 'JavaScript error (dashboard)',
          unhandled_promise_title: 'Unhandled promise rejection (dashboard)',
          unknown_error: 'Unknown error',
          init_failed_title: 'Dashboard failed to initialize',
          init_hint_started: 'Dashboard started but did not finish initializing. Open DevTools Console for details.',
          init_hint_not_started: 'Dashboard JavaScript did not start. This is often caused by a browser extension, strict policies/CSP, or an unsupported browser.',
          file_opened: 'Opened via <strong>file://</strong>. API + WebSocket connectivity will not work. Open the dashboard from the running server instead: <strong>{host}</strong>',
        },
        ur: {
          fatal_default_title: 'ڈیش بورڈ خرابی',
          fatal_open_console: 'مکمل اسٹیک ٹریس کے لیے DevTools Console کھولیں۔',
          js_error_title: 'جاوا اسکرپٹ خرابی (ڈیش بورڈ)',
          unhandled_promise_title: 'غیر ہینڈلڈ پرامس ریجیکشن (ڈیش بورڈ)',
          unknown_error: 'نامعلوم خرابی',
          init_failed_title: 'ڈیش بورڈ شروع نہیں ہو سکا',
          init_hint_started: 'ڈیش بورڈ شروع ہوا مگر مکمل طور پر initialize نہیں ہو سکا۔ تفصیلات کے لیے DevTools Console کھولیں۔',
          init_hint_not_started: 'ڈیش بورڈ جاوا اسکرپٹ شروع نہیں ہوا۔ یہ اکثر براؤزر ایکسٹینشن، سخت پالیسی/CSP، یا غیر معاون براؤزر کی وجہ سے ہوتا ہے۔',
          file_opened: '<strong>file://</strong> کے ذریعے کھولا گیا۔ API + WebSocket کنیکٹیوٹی کام نہیں کرے گی۔ ڈیش بورڈ کو چلتے ہوئے سرور سے کھولیں: <strong>{host}</strong>',
        },
      };

      const tEarly = (key, vars) => {
        const lang = getUiLang();
        const dict = EARLY_I18N[lang] || EARLY_I18N.en;
        let s = String(dict[key] ?? EARLY_I18N.en[key] ?? key);
        if (vars && typeof vars === 'object') {
          for (const [name, value] of Object.entries(vars)) {
            s = s.replaceAll(`{${name}}`, String(value));
          }
        }
        return s;
      };

      const mkBar = (html, z = 2000) => {
        try {
          const bar = document.createElement('div');
          bar.setAttribute('role', 'status');
          bar.style.position = 'fixed';
          bar.style.left = '12px';
          bar.style.right = '12px';
          bar.style.top = '12px';
          bar.style.zIndex = String(z);
          bar.style.padding = '10px 12px';
          bar.style.borderRadius = '12px';
          bar.style.border = '1px solid var(--stroke2)';
          bar.style.background = 'linear-gradient(180deg, var(--bg1), var(--bg2))';
          bar.style.boxShadow = 'var(--shadow)';
          bar.style.color = 'var(--text)';
          bar.style.fontSize = '13px';
          bar.innerHTML = html;
          return bar;
        } catch {
          return null;
        }
      };

      const showFatal = (title, details) => {
        try {
          const msg = String(details || '').slice(0, 400);
          const html = `<strong>${String(title || tEarly('fatal_default_title'))}</strong><div class="fatal-banner-details">${msg}</div><div class="fatal-banner-hint">${tEarly('fatal_open_console')}</div>`;
          const el = mkBar(html, 3000);
          if (!el) return;
          document.addEventListener('DOMContentLoaded', () => {
            // Avoid duplicating banners.
            if (document.getElementById('fatalJsBanner')) return;
            el.id = 'fatalJsBanner';
            document.body.appendChild(el);
          });
        } catch {}
      };

      // Catch runtime exceptions that prevent the UI from attaching click handlers.
      try {
        window.addEventListener('error', (ev) => {
          try {
            const msg = ev?.error?.stack || ev?.message || String(ev || tEarly('unknown_error'));
            showFatal(tEarly('js_error_title'), msg);
          } catch {}
        });
        window.addEventListener('unhandledrejection', (ev) => {
          try {
            const r = ev?.reason;
            const msg = (r && r.stack) ? r.stack : String(r || tEarly('unhandled_promise_title'));
            showFatal(tEarly('unhandled_promise_title'), msg);
          } catch {}
        });
      } catch {}

      // Detect cases where the main dashboard script never starts (e.g., blocked JS, parse error, CSP).
      try {
        document.addEventListener('DOMContentLoaded', () => {
          // Give the main script a moment to run.
          setTimeout(() => {
            try {
              if (window.__PERCEPTA_DASH_BOOT_OK) return;
              const started = window.__PERCEPTA_DASH_BOOT_STARTED;
              const hint = started ? tEarly('init_hint_started') : tEarly('init_hint_not_started');
              showFatal(tEarly('init_failed_title'), hint);
            } catch {}
          }, 1200);
        });
      } catch {}

      // Common mistake: opening the HTML directly from disk.
      try {
        if (String(location.protocol || '') !== 'file:') return;
        document.addEventListener('DOMContentLoaded', () => {
          const hostHint = 'https://<server-host>:8080/dashboard';
          const html = tEarly('file_opened', { host: hostHint });
          const bar = mkBar(html, 2500);
          if (bar) document.body.appendChild(bar);
        });
      } catch {}
    })();
