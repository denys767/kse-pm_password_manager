/*
 * End User License Agreement (EULA) the user must confirm before creating a
 * Vault Passphrase (first creation or a Vault Reset — both mint a fresh
 * passphrase-encrypted keypair). Canonical legal text lives in LICENSE at the
 * repo root; this is the same text rendered inside the app, in both uk and en,
 * so acceptance can be captured at the point of use. Keep both in sync when
 * the wording changes.
 *
 * Acceptance is recorded client-side (localStorage), keyed by email + version,
 * so returning users on the same device are not asked again until the text
 * changes. This is a UX convenience only — it does not by itself constitute
 * server-side proof of acceptance. Mirrors termsOfService.ts exactly.
 */

export const EULA_VERSION = '2026-07-23';

const STORAGE_PREFIX = 'pm.eula-accepted.';

export function hasAcceptedEula(email: string): boolean {
    return localStorage.getItem(`${STORAGE_PREFIX}${email.toLowerCase()}`) === EULA_VERSION;
}

export function recordEulaAcceptance(email: string): void {
    localStorage.setItem(`${STORAGE_PREFIX}${email.toLowerCase()}`, EULA_VERSION);
}

export const EULA_SECTIONS: { title: { uk: string; en: string }; paragraphs: { uk: string; en: string }[] }[] = [
    {
        title: { uk: '1. Визначення', en: '1. Definitions' },
        paragraphs: [
            {
                uk: '«ПЗ» — програмне забезпечення «KSE Password Manager», включно з вихідним і об’єктним кодом, виконуваними файлами, скриптами, конфігурацією, інтерфейсами, документацією, а також усіма оновленнями, доповненнями та новими версіями, наданими Автором.',
                en: '"Software" means the "KSE Password Manager" application, including its source and object code, executables, scripts, configuration, interfaces, documentation, and all updates, additions, and new versions provided by the Author.',
            },
            {
                uk: '«Використання» — встановлення, запуск, доступ, відтворення або будь-яка інша дія щодо ПЗ.',
                en: '"Use" means installing, running, accessing, reproducing, or any other action performed on the Software.',
            },
        ],
    },
    {
        title: { uk: '2. Правова природа та інтелектуальна власність', en: '2. Legal nature and intellectual property' },
        paragraphs: [
            {
                uk: 'ПЗ є пропрієтарним (закритим) програмним забезпеченням. ПЗ надається у користування за ліцензією, а НЕ продається.',
                en: 'The Software is proprietary (closed-source). It is licensed for use, NOT sold.',
            },
            {
                uk: 'Усі майнові та особисті немайнові права інтелектуальної власності на ПЗ належать Автору і охороняються Законом України «Про авторське право і суміжні права», Цивільним кодексом України та міжнародними договорами.',
                en: 'All economic and moral intellectual property rights in the Software belong to the Author and are protected under the Law of Ukraine "On Copyright and Related Rights", the Civil Code of Ukraine, and international treaties.',
            },
            {
                uk: 'Ця Угода не передає Користувачу жодних прав інтелектуальної власності на ПЗ, окрім прямо наданого нею обмеженого права використання.',
                en: 'This Agreement does not transfer to the User any intellectual property rights in the Software other than the limited right of use expressly granted herein.',
            },
        ],
    },
    {
        title: { uk: '3. Надання ліцензії', en: '3. Grant of license' },
        paragraphs: [
            {
                uk: 'Автор надає Користувачу невиключну, відкличну, непередавану, обмежену ліцензію на використання ПЗ виключно за його функціональним призначенням та відповідно до умов цієї Угоди.',
                en: 'The Author grants the User a non-exclusive, revocable, non-transferable, limited license to use the Software solely for its intended functional purpose and in accordance with the terms of this Agreement.',
            },
            {
                uk: 'Обсяг, строк та територія використання визначаються цією Угодою і окремими домовленостями з Автором (за наявності).',
                en: 'The scope, term, and territory of use are defined by this Agreement and any separate arrangements with the Author (if applicable).',
            },
        ],
    },
    {
        title: { uk: '4. Обмеження', en: '4. Restrictions' },
        paragraphs: [
            {
                uk: 'Якщо інше прямо не дозволено чинним законодавством України або письмовим дозволом Автора, Користувачу забороняється: (а) копіювати, відтворювати, поширювати, публікувати або передавати ПЗ третім особам; (б) продавати, здавати в оренду, надавати в субліцензію, передавати чи іншим чином комерціалізувати ПЗ; (в) здійснювати декомпіляцію, дизасемблювання, зворотну розробку (reverse engineering) або в інший спосіб намагатися отримати вихідний код чи структуру ПЗ; (г) видаляти або змінювати повідомлення про авторські права та інші позначення прав; (ґ) використовувати ПЗ у спосіб, що порушує законодавство України.',
                en: 'Unless expressly permitted by applicable Ukrainian law or the Author’s written consent, the User is prohibited from: (a) copying, reproducing, distributing, publishing, or transferring the Software to third parties; (b) selling, leasing, sublicensing, transferring, or otherwise commercializing the Software; (c) decompiling, disassembling, reverse engineering, or otherwise attempting to derive the source code or structure of the Software; (d) removing or altering copyright notices or other rights markings; (e) using the Software in a manner that violates the laws of Ukraine.',
            },
        ],
    },
    {
        title: { uk: '5. Відмова від гарантій. Стан «Як є» (As Is)', en: '5. Disclaimer of warranties. "As is"' },
        paragraphs: [
            {
                uk: 'ПЗ надається за принципом «ЯК Є» (AS IS) та «ЯК ДОСТУПНО» (AS AVAILABLE), з усіма наявними недоліками, без будь-яких гарантій — прямих чи непрямих.',
                en: 'The Software is provided "AS IS" and "AS AVAILABLE", with all faults, without any warranties — express or implied.',
            },
            {
                uk: 'У максимальному обсязі, дозволеному чинним законодавством України, Автор відмовляється від усіх гарантій, зокрема гарантій придатності для конкретної мети, товарної якості, безперебійної та безпомилкової роботи, відповідності очікуванням Користувача.',
                en: 'To the maximum extent permitted by applicable Ukrainian law, the Author disclaims all warranties, including warranties of fitness for a particular purpose, merchantability, uninterrupted or error-free operation, and conformity with the User’s expectations.',
            },
            {
                uk: 'Автор НЕ гарантує, що ПЗ є повністю захищеним чи безпомилковим, що його робота буде безперервною, своєчасною чи вільною від помилок, і що будь-які дефекти будуть виправлені.',
                en: 'The Author does NOT warrant that the Software is completely secure or error-free, that its operation will be continuous, timely, or free of errors, or that any defects will be corrected.',
            },
        ],
    },
    {
        title: { uk: '6. Відмова від гарантій безпеки', en: '6. Disclaimer of security warranties' },
        paragraphs: [
            {
                uk: 'Автор НЕ гарантує відсутність у ПЗ вразливостей, дефектів безпеки чи помилок, а також стійкість ПЗ до несанкціонованого доступу, зламу, перехоплення, шкідливого програмного забезпечення чи інших протиправних дій третіх осіб.',
                en: 'The Author does NOT warrant the absence of vulnerabilities, security defects, or bugs in the Software, nor its resistance to unauthorized access, hacking, interception, malware, or other unlawful acts of third parties.',
            },
            {
                uk: 'Користувач усвідомлює, що жодне програмне забезпечення не може бути абсолютно захищеним, і приймає на себе всі ризики, пов’язані з використанням ПЗ, включно з ризиком витоку, втрати чи пошкодження даних.',
                en: 'The User acknowledges that no software can be absolutely secure and assumes all risks associated with using the Software, including the risk of data leakage, loss, or corruption.',
            },
            {
                uk: 'Користувач самостійно відповідає за створення резервних копій своїх даних, застосування власних заходів безпеки та належне зберігання паролів, ключів і фраз доступу.',
                en: 'The User is solely responsible for backing up their own data, applying their own security measures, and properly safeguarding passwords, keys, and passphrases.',
            },
        ],
    },
    {
        title: { uk: '7. Обмеження відповідальності (Limitation of Liability)', en: '7. Limitation of liability' },
        paragraphs: [
            {
                uk: 'У максимальному обсязі, дозволеному чинним законодавством України, Автор не несе відповідальності за будь-які прямі, непрямі, випадкові, побічні, штрафні чи інші збитки (зокрема упущену вигоду, втрату даних, витік чи розголошення інформації, збитки від зламу чи несанкціонованого доступу, переривання діяльності), що виникли внаслідок використання або неможливості використання ПЗ, навіть якщо Автора було попереджено про можливість таких збитків.',
                en: 'To the maximum extent permitted by applicable Ukrainian law, the Author is not liable for any direct, indirect, incidental, consequential, punitive, or other damages (including lost profits, data loss, data leakage or disclosure, damages from hacking or unauthorized access, or business interruption) arising from the use or inability to use the Software, even if the Author was advised of the possibility of such damages.',
            },
            {
                uk: 'У максимальному обсязі, дозволеному законодавством, сукупна відповідальність Автора за цією Угодою та у зв’язку з ПЗ за будь-яких обставин обмежується сумою, фактично сплаченою Користувачем Автору за ПЗ за останні 12 (дванадцять) місяців, а якщо ПЗ надано безоплатно — обмежується сумою 1 (одна) гривня.',
                en: 'To the maximum extent permitted by law, the Author’s aggregate liability under this Agreement and in connection with the Software is, under all circumstances, limited to the amount actually paid by the User to the Author for the Software over the preceding 12 (twelve) months, or, if the Software was provided free of charge, limited to UAH 1 (one hryvnia).',
            },
            {
                uk: 'ІМПЕРАТИВНЕ ЗАСТЕРЕЖЕННЯ. Ніщо у цій Угоді не виключає і не обмежує відповідальність Автора у випадках, коли таке виключення чи обмеження заборонено імперативними нормами законодавства України, зокрема за шкоду, завдану життю або здоров’ю фізичної особи, а також за шкоду, завдану умисно. У таких випадках відповідальність Автора визначається згідно з чинним законодавством України.',
                en: 'MANDATORY LAW CARVE-OUT. Nothing in this Agreement excludes or limits the Author’s liability where such exclusion or limitation is prohibited by mandatory provisions of Ukrainian law, in particular for harm to life or health of a natural person or for damage caused intentionally. In such cases, the Author’s liability is determined in accordance with applicable Ukrainian law.',
            },
            {
                uk: 'Обмеження відповідальності, встановлені цим розділом, є істотною умовою Угоди та застосовуються незалежно від підстави відповідальності (договір, делікт тощо) у межах, дозволених законом.',
                en: 'The limitations of liability set out in this section are a material term of the Agreement and apply regardless of the basis of liability (contract, tort, etc.) to the extent permitted by law.',
            },
        ],
    },
    {
        title: { uk: '8. Персональні дані', en: '8. Personal data' },
        paragraphs: [
            {
                uk: 'Обробка персональних даних під час використання ПЗ здійснюється відповідно до Закону України «Про захист персональних даних».',
                en: 'Processing of personal data during use of the Software is carried out in accordance with the Law of Ukraine "On Personal Data Protection".',
            },
            {
                uk: 'Користувач, який є володільцем чи розпорядником персональних даних інших осіб, самостійно забезпечує наявність правових підстав для їх обробки за допомогою ПЗ та несе відповідальність за дотримання законодавства про захист персональних даних.',
                en: 'A User who is a controller or processor of other individuals’ personal data is solely responsible for ensuring a lawful basis for processing that data via the Software and for compliance with personal data protection law.',
            },
        ],
    },
    {
        title: { uk: '9. Строк дії та припинення', en: '9. Term and termination' },
        paragraphs: [
            {
                uk: 'Угода діє з моменту початку використання ПЗ і до її припинення.',
                en: 'The Agreement is effective from the moment Use of the Software begins and remains in effect until terminated.',
            },
            {
                uk: 'Угода та надана ліцензія автоматично припиняються у разі порушення Користувачем будь-якої з її умов, без окремого повідомлення.',
                en: 'The Agreement and the license granted hereunder automatically terminate if the User breaches any of its terms, without separate notice.',
            },
            {
                uk: 'У разі припинення Угоди Користувач зобов’язаний припинити використання ПЗ та знищити всі його копії, що перебувають у його розпорядженні.',
                en: 'Upon termination of the Agreement, the User must stop using the Software and destroy all copies of it in their possession.',
            },
            {
                uk: 'Положення розділів 2, 4–8, 10 зберігають чинність після припинення Угоди.',
                en: 'Sections 2, 4–8, and 10 survive termination of the Agreement.',
            },
        ],
    },
    {
        title: { uk: '10. Застосовне право та вирішення спорів', en: '10. Governing law and dispute resolution' },
        paragraphs: [
            {
                uk: 'Ця Угода регулюється та тлумачиться відповідно до матеріального права України, без урахування колізійних норм.',
                en: 'This Agreement is governed by and construed in accordance with the substantive law of Ukraine, without regard to conflict-of-laws principles.',
            },
            {
                uk: 'Усі спори, що виникають з цієї Угоди або у зв’язку з нею, вирішуються шляхом переговорів, а в разі недосягнення згоди — у судах України згідно з чинним процесуальним законодавством України.',
                en: 'All disputes arising out of or in connection with this Agreement shall be resolved through negotiation, and failing agreement, in the courts of Ukraine in accordance with applicable procedural law.',
            },
        ],
    },
    {
        title: { uk: '11. Інші положення', en: '11. Miscellaneous' },
        paragraphs: [
            {
                uk: 'Якщо будь-яке положення цієї Угоди буде визнане недійсним чи таким, що не підлягає примусовому виконанню, це не впливає на дійсність решти положень; недійсне положення застосовується у максимально можливому дозволеному законом обсязі, що найближче відповідає намірам сторін.',
                en: 'If any provision of this Agreement is held invalid or unenforceable, this does not affect the validity of the remaining provisions; the invalid provision applies to the maximum extent permitted by law that most closely reflects the parties’ intent.',
            },
            {
                uk: 'Автор має право в односторонньому порядку змінювати умови цієї Угоди, публікуючи нову редакцію. Продовження використання ПЗ після набрання чинності змінами означає згоду Користувача з ними.',
                en: 'The Author may unilaterally amend the terms of this Agreement by publishing a new version. Continued use of the Software after amendments take effect constitutes the User’s agreement to them.',
            },
            {
                uk: 'Ця Угода становить повну домовленість сторін щодо предмета Угоди та замінює всі попередні домовленості щодо нього.',
                en: 'This Agreement constitutes the entire agreement between the parties regarding its subject matter and supersedes all prior arrangements concerning it.',
            },
            {
                uk: 'Незастосування Автором будь-якого права за Угодою не є відмовою від нього.',
                en: 'The Author’s failure to exercise any right under the Agreement does not constitute a waiver of that right.',
            },
        ],
    },
];
