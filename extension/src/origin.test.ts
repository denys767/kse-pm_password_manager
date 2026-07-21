import { matchesOrigin } from './origin';
const cases: Array<[string | null, string | undefined, boolean]> = [
    ['https://portal.kse.org.ua/login', 'https://portal.kse.org.ua/a', true],
    ['https://portal.kse.org.ua', 'http://portal.kse.org.ua', false],
    ['https://portal.kse.org.ua', 'https://evil-portal.kse.org.ua', false],
    ['https://portal.kse.org.ua:8443', 'https://portal.kse.org.ua', false],
    ['https://portal.kse.org.ua', 'https://portal.kse.org.ua.evil.test', false],
    ['notaurl', 'https://portal.kse.org.ua', false],
];
for (const [item, tab, expected] of cases) if (matchesOrigin(item, tab) !== expected) throw new Error(`Origin fixture failed: ${item} / ${tab}`);
console.log(`origin fixtures: ${cases.length} passed`);
