// پیکربندی Vite.
//
// چرا لازم است: فایل‌های JS از بسته‌هایی مثل `@tauri-apps/api/core` import می‌کنند.
// مرورگر خودش این نام‌ها را نمی‌شناسد؛ باید قبل از بیلد یکجا شوند.
// بدون این مرحله، پنجرهٔ برنامه سفید بالا می‌آمد.
import { defineConfig } from 'vite'

const LINUX_REPLACEMENTS = [
  ['QR codes are not supported on Windows (no camera or image scanner). Use a link, a subscription or a file instead.', 'QR codes from camera are not supported on Linux desktop. Use a link, a subscription or an image file instead.'],
  ['کد <bdi>QR</bdi> در ویندوز پشتیبانی نمی‌شود (اسکنر تصویر ندارد). به‌جای آن از لینک، اشتراک یا فایل استفاده کنید.', 'اسکن <bdi>QR</bdi> با دوربین در لینوکس پشتیبانی نمی‌شود. به‌جای آن از لینک، اشتراک یا فایل تصویر استفاده کنید.'],
  ['the bundled Xray core (engine\\\\xray\\\\xray.exe) is missing — reinstall Aether', 'the bundled Xray core (engine/xray/xray) is missing — reinstall Aether'],
  ['هستهٔ Xrayِ همراه (engine\\\\xray\\\\xray.exe) پیدا نشد — اتر را دوباره نصب کنید', 'هستهٔ Xrayِ همراه (engine/xray/xray) پیدا نشد — اتر را دوباره نصب کنید'],
  ['This custom config is locked to mobile data by its author, so it cannot run on Windows.', 'This custom config is locked to mobile data by its author, so it cannot run on Linux.'],
  ['سازندهٔ این کانفیگ آن را به اینترنتِ موبایل محدود کرده، پس روی ویندوز اجرا نمی‌شود.', 'سازندهٔ این کانفیگ آن را به اینترنتِ موبایل محدود کرده، پس روی لینوکس اجرا نمی‌شود.'],
  ['Custom configs need the bundled Xray core (engine\\\\xray\\\\xray.exe), which this installation is missing. Reinstall Aether.', 'Custom configs need the bundled Xray core (engine/xray/xray), which this installation is missing. Reinstall Aether.'],
  ['کانفیگ‌های سفارشی به هستهٔ همراهِ <bdi>Xray</bdi> (<bdi>engine\\\\xray\\\\xray.exe</bdi>) نیاز دارند که در این نصب نیست. اتر را دوباره نصب کنید.', 'کانفیگ‌های سفارشی به هستهٔ همراهِ <bdi>Xray</bdi> (<bdi>engine/xray/xray</bdi>) نیاز دارند که در این نصب نیست. اتر را دوباره نصب کنید.'],
  ['this npvt config is restricted by its author to mobile data only, which a Windows PC cannot honour', 'this npvt config is restricted by its author to mobile data only, which a Linux PC cannot honour'],
  ['که روی ویندوز ممکن نیست', 'که روی لینوکس ممکن نیست'],
  ['Iranian sites (.ir and Iranian IP ranges) open directly on this Windows PC only; shared devices stay in the tunnel.', 'Iranian sites (.ir and Iranian IP ranges) open directly on this Linux PC only; shared devices stay in the tunnel.'],
  ['سایت‌های ایرانی (<bdi>.ir</bdi> و رنج آی‌پی ایران) فقط روی همین ویندوز مستقیم باز می‌شوند؛ دستگاه‌های اشتراکی داخل تونل می‌مانند.', 'سایت‌های ایرانی (<bdi>.ir</bdi> و رنج آی‌پی ایران) فقط روی همین سیستم لینوکس مستقیم باز می‌شوند؛ دستگاه‌های اشتراکی داخل تونل می‌مانند.'],
  ['The key is stored sealed on this PC with Windows DPAPI and is never written to the log.', 'The key is stored encrypted on this Linux PC and is never written to the log.'],
  ['کلید روی همین رایانه با <bdi>DPAPI</bdi> ویندوز مهر و ذخیره می‌شود و هرگز در لاگ نوشته نمی‌شود.', 'کلید روی همین رایانه به‌صورت رمزشده در لینوکس ذخیره می‌شود و هرگز در لاگ نوشته نمی‌شود.'],
  ['پروکسیِ در حال اجرا روی همین ویندوز', 'پروکسیِ در حال اجرا روی همین لینوکس'],
  ['Reads the name from the first bytes (TLS SNI or HTTP Host), so domain rules keep working even though Windows hands the tunnel an IP address.', 'Reads the name from the first bytes (TLS SNI or HTTP Host), so domain rules keep working even when the tunnel sees only an IP address.'],
  ['وقتی ویندوز فقط یک آی‌پی به تونل می‌دهد', 'وقتی تونل فقط یک آی‌پی دریافت می‌کند'],
  ['Windows edition — QW-AI-Code', 'Linux (Ubuntu) edition — Aether Desktop'],
  ['نسخهٔ ویندوز — <bdi>QW-AI-Code</bdi>', 'نسخهٔ لینوکس (اوبونتو) — <bdi>Aether Desktop</bdi>'],
  ['The native Windows desktop edition of Aether — what we upgraded in this build', 'The native Linux (Ubuntu 26.x) desktop edition of Aether — ported for Debian/Ubuntu'],
  ['نسخهٔ بومی ویندوزِ <bdi>Aether</bdi> — بهبودهای همین بیلد', 'نسخهٔ بومی لینوکس (اوبونتو ۲۶) از <bdi>Aether</bdi> — پورت کامل دسکتاپ'],
  ['Full native Windows desktop app — upstream is CLI-only (no Windows GUI)', 'Full native Linux (Ubuntu) desktop app — upstream is CLI-only (no Linux GUI)'],
  ['One-click system-wide tunnel via the Wintun TUN driver — no manual proxy setup', 'One-click system-wide tunnel via Linux TUN & GNOME system proxy — no manual proxy setup'],
  ['برنامهٔ کاملاً بومی دسکتاپ ویندوز — پروژهٔ اصلی فقط خط فرمان دارد و رابط گرافیکی ویندوز ندارد', 'برنامهٔ کاملاً بومی دسکتاپ لینوکس (اوبونتو) — پروژهٔ اصلی فقط خط فرمان دارد و رابط گرافیکی ندارد'],
  ['تونل سراسری سیستم با یک کلیک از طریق درایور <bdi>Wintun</bdi> — بدون نیاز به تنظیم دستی پروکسی', 'تونل سراسری سیستم با یک کلیک از طریق <bdi>TUN</bdi> لینوکس و پروکسی سیستم — بدون نیاز به تنظیم دستی پروکسی'],
  ['placeholder="chrome.exe&#10;telegram.exe"', 'placeholder="google-chrome&#10;telegram-desktop&#10;firefox"'],
  ['ویندوز یا فایروال/آنتی‌ویروس اجازهٔ اتصال شبکه به این برنامه را نداد (خطای ۱۰۰۱۳). برنامه را در فایروال مجاز کنید، VPN/پروکسی دیگر را خاموش کنید یا حالت «Config → Psiphon» را امتحان کنید.', 'فایروال لینوکس (nftables/ufw) یا دسترسی شبکه اجازهٔ اتصال به این برنامه را نداد. قوانین فایروال را بررسی کنید، VPN/پروکسی دیگر را خاموش کنید یا حالت «Config → Psiphon» را امتحان کنید.'],
  ['دانلودکنندهٔ خود ویندوز هم موفق نشد.', 'دانلودکنندهٔ سیستم هم موفق نشد.'],
  ['رابط ویندوز دقیقاً مثل موبایل شد', 'رابط لینوکس دقیقاً مثل موبایل شد'],
  ['پنجرهٔ ویندوز', 'پنجرهٔ دسکتاپ'],
  ['رابط کاربری ویندوز', 'رابط کاربری دسکتاپ لینوکس'],
  ['در ویندوز نیستند', 'در دسکتاپ نیستند'],
  ['در ویندوز، کارت شبکه', 'در اوبونتو/لینوکس، اتصال شبکه'],
]

function aetherLinuxStrings() {
  return {
    name: 'aether-linux-strings',
    transform(code, id) {
      if (process.platform !== 'linux') return null
      if (!id.endsWith('.js')) return null
      let out = code
      for (const [from, to] of LINUX_REPLACEMENTS) {
        if (out.includes(from)) out = out.split(from).join(to)
      }
      return out === code ? null : { code: out, map: null }
    },
  }
}

export default defineConfig({
  root: 'src',
  plugins: [aetherLinuxStrings()],
  build: {
    outDir: '../dist-web',
    emptyOutDir: true,
    target: 'chrome110',
    sourcemap: false,
  },
  clearScreen: false,
  server: { port: 5173, strictPort: true },
})
