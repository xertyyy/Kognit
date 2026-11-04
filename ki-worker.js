// Kognit – KI-Hilfe für alle Fächer: Code-Feedback, „Erklär’s mir anders“, Bewertung freier Antworten, Lern-Chat
// Läuft als Cloudflare Worker. Prüft, ob die Anfrage von einem angemeldeten Kognit-Nutzer kommt,
// und fragt dann ein Modell bei OpenRouter. Der OpenRouter-Schlüssel bleibt geheim auf dem Server.
//
// Einstellungen im Worker (Settings → Variables and Secrets):
//   OPENROUTER_KEY  (Secret)  dein Schlüssel von openrouter.ai
//   MODEL           (Text)    Hauptmodell, z. B. deepseek/deepseek-v4-flash (bezahlt, günstig) oder ein „:free“-Modell
//   MODEL2          (Text)    optional: Ersatzmodell, falls MODEL überlastet ist oder nicht antwortet

const PROJECT = 'kognit-cb4f4';
const ORIGIN = 'https://xertyyy.github.io';
const JWKS_URL = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';
const PER_MINUTE = 8;            // Anfragen pro Nutzer und Minute
let jwks = null, jwksAt = 0;
const hits = new Map();

const cors = { 'Access-Control-Allow-Origin': ORIGIN, 'Access-Control-Allow-Methods': 'POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Vary': 'Origin' };
const json = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { ...cors, 'Content-Type': 'application/json' } });

function b64url(str) {
  const s = str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4);
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}
async function verifyFirebaseToken(token) {
  const [h, p, sig] = token.split('.');
  if (!h || !p || !sig) throw new Error('token');
  const head = JSON.parse(new TextDecoder().decode(b64url(h)));
  const body = JSON.parse(new TextDecoder().decode(b64url(p)));
  const now = Date.now() / 1000;
  if (head.alg !== 'RS256' || body.aud !== PROJECT || body.iss !== 'https://securetoken.google.com/' + PROJECT || !body.sub || body.exp < now || body.iat > now + 60) throw new Error('claims');
  if (!jwks || Date.now() - jwksAt > 3600e3) { jwks = (await (await fetch(JWKS_URL)).json()).keys; jwksAt = Date.now(); }
  const jwk = jwks.find(k => k.kid === head.kid);
  if (!jwk) throw new Error('kid');
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64url(sig), new TextEncoder().encode(h + '.' + p));
  if (!ok) throw new Error('sig');
  return body.sub;
}

const ROLE = 'Du bist eine freundliche, geduldige Lehrkraft an einer kaufmännischen Berufsschule.';
const RULES = 'Antworte auf Deutsch in Du-Form, in einfacher Sprache mit kurzen Sätzen. Bleib fachlich korrekt. Erfinde nichts: Wenn du dir unsicher bist, sag das ehrlich.';
const cut = (x, n) => String(x == null ? '' : x).slice(0, n);

const FORMAT_SPEC = `Multiple Choice: {"t":"mc","q":"Frage","o":["A","B","C","D"],"a":Index der einzigen richtigen Antwort (0 bis 3),"e":"1 bis 2 Sätze Erklärung","h":"kurzer Tipp, der zum Denkweg führt, aber die Antwort nicht verrät"}
Freie Frage: {"t":"free","q":"Frage, die man in 2 bis 5 Sätzen beantwortet","m":"Musterlösung mit allen Punkten, die in der Antwort vorkommen sollen","h":"kurzer Tipp, der die Antwort nicht verrät"}
Bei Programmier-Themen: Programmcode NIE in "q" schreiben, sondern ins optionale Feld "code" (mit \n für Zeilenumbrüche und 4 Leerzeichen Einrückung). Sind die Antwortmöglichkeiten selbst Code oder Programmausgaben, setze zusätzlich "mono":true. Prüfe jede Programmausgabe Zeichen für Zeichen.
Soll die Person selbst Code schreiben, lass "code" weg: Die Lösung steht NUR in "m", nie in "code" oder "q".
Jede falsche Antwortmöglichkeit muss nach dem Lernstoff eindeutig falsch sein, nicht nur unüblich oder schlechter Stil. Es darf keine zweite Antwort geben, die man auch als richtig verteidigen kann.
Der Tipp "h" darf die richtige Antwort weder nennen noch zeigen noch umschreiben.
Alles auf Deutsch, auch in Antwortmöglichkeiten (z. B. „Fehler“ statt „Error“).`;

function buildPrompt(mode, d) {
  if (mode === 'questions') {
    return { tokens: 6000, think: true, list: true, prompt: `Du erstellst Übungsaufgaben für eine Klassenarbeit an einer kaufmännischen Berufsschule in Deutschland. Die Person fängt fast bei null an: einfache, klare Sprache, Du-Form, keine Fangfragen.
Thema: ${cut(d.title, 200)}
Es gilt NUR dieser Lernstoff: """${cut(d.page, 8000)}"""
Erzeuge genau 5 neue Aufgaben: 4 Multiple-Choice-Fragen und 1 freie Frage, von leicht nach schwer.
Antworte nur mit einem JSON-Array, ohne Codeblock und ohne weiteren Text.
${FORMAT_SPEC}
Prüfe bei jeder Multiple-Choice-Frage, dass genau eine Antwort richtig ist und "a" auf genau diese zeigt. Prüfe jede Zahl und jede Programmausgabe doppelt.
Wiederhole diese vorhandenen Aufgaben nicht: ${cut(d.existing, 3000)}` };
  }
  if (mode === 'explain') {
    const prev = cut(d.prev, 1500);
    return { tokens: 800, prompt: `${ROLE} Eine Person hat die Lernseite gelesen und das Thema noch nicht ganz verstanden. Erkläre es noch einmal ganz anders.
Thema: ${cut(d.title, 200)}
Lernseite: """${cut(d.page, 6000)}"""
${prev ? 'Diese Erklärung hatte sie schon, nimm ein anderes Beispiel: """' + prev + '"""' : ''}
Regeln: ein neues, anschauliches Alltagsbeispiel, höchstens 200 Wörter. Halte dich inhaltlich an die Lernseite. ${RULES} Bei Programmierthemen ein kurzes Codebeispiel in <pre><code>, prüfe die Ausgabe genau.
Antworte nur mit HTML, ohne Markdown und ohne Codeblock drumherum. Erlaubte Tags: <p>, <b>, <ul>, <li>, <pre>, <code>. Der letzte Absatz beginnt mit <b>Merke:</b>` };
  }
  if (mode === 'grade') {
    return { tokens: 300, json: true, prompt: `${ROLE} Du bewertest eine Übungsantwort für eine Klassenarbeit. Bewerte wohlwollend wie eine Lehrkraft in der Klassenarbeit: Entscheidend ist, ob der Kern verstanden ist. Steht der Kern sinngemäß oder indirekt in der Antwort, gib die volle Punktzahl, auch wenn Fachbegriffe fehlen oder es umständlich formuliert ist. Zieh nur ab, wenn etwas sachlich falsch ist oder ein wichtiger Punkt ganz fehlt. Fehlende Details oder Beispiele kosten höchstens 0.25. Rechtschreibung zählt nicht. Die Musterlösung ist der Maßstab; andere Formulierungen mit gleichem Inhalt sind genauso richtig.
Frage: ${cut(d.question, 1000)}
Musterlösung: ${cut(d.model, 2000)}
Antwort: """${cut(d.answer, 3000)}"""
Antworte nur mit JSON, ohne Codeblock: {"score": 0, 0.25, 0.5, 0.75 oder 1, "feedback": "2 bis 3 Sätze in Du-Form: was stimmt und was fehlt; bei voller Punktzahl kurz loben und höchstens einen Ergänzungstipp"}` };
  }
  if (mode === 'chat') {
    const hist = Array.isArray(d.history) ? d.history.slice(-6).map(m => (m && m.r === 'a' ? 'Du: ' : 'Schüler: ') + cut(m && m.t, 600)).join('\n') : '';
    const q = cut(d.question, 600);
    if (!q.trim()) return null;
    return { tokens: 500, prompt: `${ROLE} Du hilfst beim Lernen für die Schule.
Thema: ${cut(d.title, 200)}
Lernseite: """${cut(d.page, 6000)}"""
${hist ? 'Bisheriges Gespräch:\n' + hist + '\n' : ''}Neue Frage: """${q}"""
Regeln: Beantworte die Frage auf Grundlage der Lernseite, höchstens 150 Wörter. ${RULES} Wenn die Frage wirklich über die Lernseite hinausgeht, darfst du allgemein antworten und sagst kurz dazu, dass das nicht auf der Lernseite steht; sonst erwähnst du das nicht. Bei einer Begrüßung oder unklaren Nachricht grüßt du kurz zurück und fragst in einem Satz, wobei du helfen kannst. Wenn die Frage nichts mit Schule oder Lernen zu tun hat, sag freundlich, dass du nur beim Lernen hilfst. Kein Markdown, keine Überschriften. Code nur, wenn es ums Programmieren geht.` };
  }
  // Standard: Code-Feedback
  const code = cut(d.code, 4000);
  if (!code.trim()) return null;
  const tests = Array.isArray(d.tests) ? d.tests.slice(0, 6).map((x, i) => `Test ${i + 1}: ${x && x.ok ? 'bestanden' : 'nicht bestanden'}${x && x.why ? ' (' + cut(x.why, 200) + ')' : ''}`).join('\n') : '';
  return { tokens: 4000, think: true, prompt: `${ROLE} Eine Person hat diese Python-Übungsaufgabe gelöst.

Aufgabe: ${cut(d.task, 600)}

Code:
\`\`\`python
${code}
\`\`\`

Ergebnis der automatischen Tests:
${tests}

Gib kurzes Feedback, höchstens 120 Wörter. ${RULES}
1. Was ist schon gut?
2. Was ist falsch oder fehlt, mit Zeilenangabe, falls möglich?
3. Ein konkreter Tipp für den nächsten Versuch.
Verrate nicht die komplette Lösung. Kein Markdown, keine Überschriften.
Wichtig: Die Testergebnisse sind die Wahrheit. Wenn alle Tests bestanden sind, behaupte keinen Fehler, sondern gib höchstens einen Stil-Tipp. Erfinde keine Fehler und keine Zeilen, die es nicht gibt.` };
}

// Liefert { text, why }: why sagt, warum keine Antwort kam (busy, slow, key, junk, gone)
async function ask(env, prompt, tokens, think) {
  let why = '';
  // Ersatzmodell bekommt zwei Versuche (der Gratis-Router nimmt beim zweiten Mal oft ein anderes Modell).
  // MODEL und MODEL2 dürfen mehrere Modelle durch Komma getrennt enthalten.
  const split = v => String(v || '').split(',').map(x => x.trim()).filter(Boolean);
  const list = split(env.MODEL).concat(split(env.MODEL2).flatMap(m => m.startsWith('openrouter/') ? [m, m] : [m]));
  for (const model of list) {
    // Manche Modelle (v. a. über openrouter/free) erlauben kein Abschalten des Denkmodus: dann kurz denken, Gedanken nicht zurückgeben.
    const router = model.startsWith('openrouter/'), paid = !router && !model.endsWith(':free');
    // Bezahlte Modelle denken nur kurz: schneller und günstiger
    const reasoning = think ? (paid ? { effort: 'low', exclude: true } : { enabled: true, exclude: true }) : router ? { effort: 'low', exclude: true } : { enabled: false };
    const maxTokens = router && !think ? tokens + 2000 : tokens;
    try {
      const r = await fetch('https://openrouter.ai/api/v1/chat/completions', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + env.OPENROUTER_KEY, 'Content-Type': 'application/json', 'HTTP-Referer': ORIGIN + '/Kognit/', 'X-Title': 'Kognit' },
        body: JSON.stringify({ model, messages: [{ role: 'user', content: prompt }], max_tokens: maxTokens, temperature: 0.2, reasoning }),
        signal: AbortSignal.timeout(think || router ? 60000 : 25000)
      });
      const out = await r.json().catch(() => ({}));
      const t = out && out.choices && out.choices[0] && out.choices[0].message && out.choices[0].message.content;
      const txt = String(t || '').trim();
      // Unbrauchbare Antworten verwerfen (z. B. ein Sicherheits-Prüfmodell, das nur „User Safety: safe“ meldet).
      if (r.ok && txt.length >= 15 && !/^\W*(user|response)?\s*safety\s*:/i.test(txt)) return { text: txt };
      if (r.ok) { console.log('KI-Fehler', model, 'unbrauchbare Antwort', txt.slice(0, 100)); why = why || 'junk'; continue; }
      if (r.status === 429) why = 'busy';
      else if ([401, 402, 403].includes(r.status)) why = why || 'key';
      else why = why || 'gone';
      console.log('KI-Fehler', model, r.status, JSON.stringify(out.error || out).slice(0, 500));
    } catch (e) { console.log('KI-Fehler', model, e.name, e.message); if (why !== 'busy') why = 'slow'; }
  }
  return { text: '', why };
}

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { headers: cors });
    if (req.method !== 'POST') return json({ error: 'Nur POST.' }, 405);
    if (!env.OPENROUTER_KEY || !env.MODEL) return json({ error: 'Der KI-Server ist noch nicht fertig eingerichtet.' }, 500);

    let uid;
    try { uid = await verifyFirebaseToken((req.headers.get('Authorization') || '').replace(/^Bearer\s+/, '')); }
    catch (e) { return json({ error: 'Bitte melde dich in Kognit an.' }, 401); }

    const t = Date.now(), list = (hits.get(uid) || []).filter(x => t - x < 60000);
    if (list.length >= PER_MINUTE) return json({ error: 'Kurz durchatmen: zu viele Anfragen. Versuch es in einer Minute noch einmal.' }, 429);
    list.push(t); hits.set(uid, list);

    let data;
    try { data = await req.json(); } catch (e) { return json({ error: 'Ungültige Anfrage.' }, 400); }
    const mode = ['explain', 'grade', 'chat', 'questions'].includes(data && data.mode) ? data.mode : 'code';
    const job = buildPrompt(mode, data || {});
    if (!job) return json({ error: 'Die Anfrage ist leer.' }, 400);

    const res = await ask(env, job.prompt, job.tokens, job.think);
    let text = res.text;
    if (!text) {
      const msg = {
        busy: 'Die KI ist gerade überlastet, weil viele Leute die kostenlosen Modelle nutzen. Versuch es in ein, zwei Minuten noch einmal.',
        slow: 'Die KI hat zu lange gebraucht. Versuch es gleich noch einmal.',
        key: 'Der KI-Zugang ist gerade gesperrt oder aufgebraucht. Sag bitte dem Admin Bescheid.',
        junk: 'Die KI hat eine unbrauchbare Antwort geliefert. Probier es noch einmal.'
      }[res.why] || 'Die KI ist gerade nicht erreichbar. Versuch es später noch einmal.';
      return json({ error: msg }, res.why === 'busy' ? 503 : 502);
    }
    text = text.replace(/^```[a-z]*\s*/i, '').replace(/\s*```$/, '').trim();

    if (job.list) {
      try {
        const arr = JSON.parse((text.match(/\[[\s\S]*\]/) || [''])[0]);
        if (!Array.isArray(arr) || !arr.length) throw new Error('leer');
        return json({ items: arr.slice(0, 8) });
      } catch (e) { return json({ error: 'Die KI hat keine brauchbaren Fragen geliefert. Probier es noch einmal.' }, 502); }
    }
    if (job.json) {
      try {
        const o = JSON.parse((text.match(/\{[\s\S]*\}/) || [''])[0]);
        const score = Number(o.score);
        if (!isFinite(score)) throw new Error('score');
        return json({ score: Math.max(0, Math.min(1, score)), feedback: cut(o.feedback, 600) });
      } catch (e) { return json({ error: 'Die KI-Bewertung war unklar. Vergleiche selbst mit der Musterlösung.' }, 502); }
    }
    return json({ text: text.slice(0, mode === 'explain' ? 4000 : 2000) });
  }
};
