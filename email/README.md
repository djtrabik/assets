# Online API – Kalkulačka E-liquidů 2.6

Toto je první samostatný základ ONLINE backendu. Neobsahuje databázové heslo ani tajné klíče.

## Nasazení

1. Vytvoř PostgreSQL databázi na Neonu.
2. Spusť `schema.sql` v SQL editoru Neonu.
3. Nainstaluj závislosti z `requirements.txt`.
4. Nastav serverové proměnné `DATABASE_URL` a `JWT_SECRET` (náhodný klíč alespoň 32 znaků).
5. Spusť `uvicorn app:app --host 0.0.0.0 --port 8000`.

`DATABASE_URL` a `JWT_SECRET` patří pouze do tajné konfigurace hostingu. Nikdy je nevkládej do desktopového klienta, webového JavaScriptu ani ZIP distribuce.

## Režimy

- ONLINE: klient komunikuje pouze s tímto API; identita uživatele se odvozuje z ověřeného Bearer tokenu.
- HOST: zůstává v původním lokálním SQLite jádru; toto API se v HOST režimu nepoužívá.

## Stav

Backend obsahuje účty a ověřování, zálohování, uživatelsky oddělené datové endpointy a přenos úplného lokálního SQLite snímku mezi zařízeními. Desktopový klient používá pro přenos zařízení synchronizační dokumenty (`/sync/*`); nejde zatím o úplné přepnutí všech lokálních operací do normalizovaných online tabulek `/data/*`. Před produkčním nasazením je nutné dokončit testy proti skutečné PostgreSQL/Neon databázi, Make.com webhooku a nasazení HTTPS.

## API skladových položek (první CRUD část)

- `GET /data/materials` – seznam položek přihlášeného uživatele.
- `POST /data/materials` – vytvoření položky.
- `PATCH /data/materials/{id}` – změna položky.
- `DELETE /data/materials/{id}` – odstranění položky.
- `GET /data/materials/count` – počet položek.

Všechny operace odvozují `owner_id` výhradně z ověřeného tokenu. ID položky jiného uživatele se chová jako nenalezené. API používá parametrizované SQL dotazy; názvy aktualizovaných sloupců jsou omezené pevnou allowlist sadou.

## Rozšířené endpointy pracovní verze 2.6

Všechny následující endpointy vyžadují `Authorization: Bearer <token>` a pracují pouze s daty přihlášeného uživatele:

- `GET /data/recipes` – seznam receptur
- `POST /data/recipes` – vytvoření receptury (`name`, `payload`)
- `PUT /data/recipes/{recipe_id}` – úplná aktualizace receptury
- `DELETE /data/recipes/{recipe_id}` – odstranění receptury
- `GET /settings/preferences` – načtení uživatelských nastavení
- `PUT /settings/preferences/{key}` – uložení jednoho nastavení
- `PUT /settings/language` – změna jazyka CS/EN/DE/FR/PL/ES

Poznámka: jde o serverové API pracovní verze. Před nasazením je nutné provést integrační testy proti skutečné PostgreSQL databázi a napojit klientské rozhraní. Zatím není dokončen přenos všech datových operací z lokálního API.


## Skladové pohyby (doplnění 2.5)

Aplikace může zapisovat příjem (`IN`), výdej (`OUT`) a inventurní korekci (`ADJUSTMENT`).
Změna skladu a auditní záznam se zapisují v jedné transakci. Řádek materiálu se zamyká
`FOR UPDATE`; výdej, který by vedl k zápornému skladu, je odmítnut. Korekce používá
`quantity` jako cílový absolutní stav, nikoliv jako rozdíl. Historii lze načíst přes
`GET /data/materials/{material_id}/movements`.

Před spuštěním je nutné aplikovat celé `schema.sql` na novou databázi.

## CORS a webové nasazení

Před nasazením nastavte `ALLOWED_ORIGINS` na přesný seznam HTTPS originů webové aplikace, oddělený čárkami, například `https://app.example.cz`. Nepoužívejte `*`. Pokud proměnná není nastavena, cross-origin požadavky nejsou povoleny. Desktopový HOST režim komunikuje s lokálním API a CORS pro něj není potřeba.

Příklad dalších povinných proměnných: `DATABASE_URL` a `JWT_SECRET` (alespoň 32 náhodných znaků). Tajné hodnoty patří do secrets konfigurace hostingu, nikdy do klientského JavaScriptu ani instalačního balíčku.


## Účty: ověření e-mailu a obnova hesla

Registrace vytvoří neověřený účet a odešle jednorázový ověřovací kód. Přihlášení je povoleno až po ověření adresy. Kód se ukládá pouze jako SHA-256 hash a má omezenou platnost. Obnova hesla používá samostatný jednorázový kód s kratší platností; po změně hesla se zneplatní všechny další účtové kódy.

Na Renderu nastavte secrets `MAKE_WEBHOOK_URL` a `MAKE_API_KEY` a veřejnou adresu API `PUBLIC_API_URL`. Backend posílá Make webhooku JSON s poli `email`, `type` (`verify`, `resend`, `reset`), `lang` (`cs`, `en`, `de`, `fr`, `pl`, `es`), `link`, `code`, `requestId` a `timestamp`. VERIFY/RESEND používají jednorázový ověřovací odkaz v URL fragmentu; RESET posílá osmimístný číselný kód v poli `code`, který uživatel zadává přímo v aplikaci. Resetovací kód platí 15 minut, je jednorázový, na serveru se ukládá pouze jeho SHA-256 hash, po pěti chybných pokusech se zneplatní a nové odeslání je omezeno 60sekundovou prodlevou. API klíč se posílá pouze v HTTP hlavičce `x-make-apikey`. Make pouze doručuje e-mail; kódy generuje a ověřuje backend. Nikdy nevkládejte Make API klíč do klienta ani e-mailové šablony.

Endpointy:

- `POST /auth/verify-email` – JSON `{ "token": "..." }`
- `POST /auth/verification/resend` – JSON `{ "email": "..." }`
- `POST /auth/password/forgot` – JSON `{ "email": "..." }`
- `POST /auth/password/reset` – JSON `{ "email": "...", "code": "12345678", "new_password": "..." }` (kód 8 číslic, heslo min. 12 znaků; starší tokenové odkazy jsou dočasně podporovány)

## Online zálohování účtu

- `GET /account/backup` – export kompletního uživatelského obsahu v JSON včetně kontrolního SHA-256 součtu.
- `POST /account/backup/restore` – kontrola formátu, velikosti, struktury a kontrolního součtu; obnova proběhne v jediné transakci a při chybě se celá vrátí. Data se vždy přiřadí přihlášenému účtu; `owner_id`, hesla a autentizační tokeny se ze zálohy nepřebírají.
- `GET /account/backup/verify` – kontrola dostupnosti a počtů obnovitelných záznamů.

Záloha obsahuje sklad, receptury, várky, skladové pohyby a uživatelská nastavení. Před produkčním spuštěním proveďte test exportu a obnovy na oddělené testovací databázi.

## Relace a změna hesla

Přístupové tokeny obsahují verzi relace (`auth_version`). Server ji ověřuje při každém autentizovaném požadavku. Po úspěšné obnově hesla se verze zvýší, čímž se zneplatní dříve vydané přístupové tokeny a všechna zařízení se musí znovu přihlásit.


## Kontejnerové nasazení

V adresáři `server` je připraven `Dockerfile` a `.env.example`. Při nasazení nastavte proměnné jako secrets hostingu; `.env.example` obsahuje pouze zástupné hodnoty a nesmí být používán jako skutečná konfigurace. Kontejner naslouchá na portu z proměnné `PORT` (výchozí 8000), běží pod neprivilegovaným uživatelem a poskytuje liveness `/health` a databázovou readiness `/health/ready`.

Před spuštěním produkční služby aplikujte celé `schema.sql` v Neon SQL Editoru. Doporučené pořadí: založit Neon databázi, aplikovat schéma, nakonfigurovat server secrets, nasadit kontejner, nastavit přesné `ALLOWED_ORIGINS`, ověřit `/health/ready`, doručení přes Make a testovací registraci/obnovu hesla.


## Synchronizace mezi zařízeními (nové)

- `GET /sync/state` vrátí poslední uloženou revizi účtu a synchronizační snímek.
- `GET /sync/history` vypíše posledních 20 předchozích revizí. `PUT /sync/state` přijímá `{ "base_revision": 0, "snapshot": ... }`.
- Každý snímek obsahuje kompletní uživatelské tabulky lokální aplikace (sklad, nákupy, pohyby, receptury, várky, položky várek a nastavení), verzi formátu 2 a dva SHA-256 součty: stabilní otisk obsahu a kontrolu celého přenosového dokumentu.
- Server kontroluje formát verze 2, stabilní kontrolní součet obsahu, kontrolní součet celého snímku, přesné sloupce tabulek, vazby mezi záznamy a limit 20 MB.
- Optimistická revize odmítne souběžný zápis HTTP 409; klient musí nejprve načíst aktuální stav.
- Snímek je izolován podle přihlášeného uživatele. V datech není heslo ani autentizační token.

V desktopové aplikaci se synchronizace spouští automaticky po přihlášení. První zařízení automaticky inicializuje prázdný synchronizační dokument; další zařízení stáhne existující ONLINE snímek. Změny se oznamují přes WebSocket a přenášejí přes HTTPS API. Ruční upload/download zůstávají pouze jako servisní akce; uživatel nemusí provádět ruční první propojení.

Každé načtení vytváří lokální zálohu. Server používá optimistické revize a PostgreSQL zámek, vrací HTTP 409 při souběžném zápisu a uchovává posledních 20 předchozích snímků. Před použitím je nutné znovu spustit celý `schema.sql` na Neon databázi, aby se vytvořily tabulky `sync_documents` a `sync_document_history`.


Email delivery uses the authenticated Make.com HTTPS webhook. Configure `MAKE_WEBHOOK_URL`, `MAKE_API_KEY` and `PUBLIC_API_URL` in the hosting environment.

## Automatická synchronizace přes WebSocket (DEV balíček 48)

- Po přihlášení se synchronizace spouští automaticky; uživatel nevolí směr prvního přenosu.
- První zařízení automaticky založí prázdný ONLINE synchronizační dokument. Další zařízení, které účet otevře bez lokální synchronizační historie, automaticky stáhne existující ONLINE snímek. Před nahrazením lokálních dat se vytvoří lokální záloha.
- `WS /sync/ws` přijímá autentizaci uvnitř zabezpečeného WebSocket spojení a po úspěšném zápisu `PUT /sync/state` oznamuje připojeným zařízením novou revizi (`sync_changed`). Klient pak stáhne nový snímek přes HTTPS API.
- Klient posílá heartbeat, automaticky obnovuje WebSocket spojení a při nedostupném WebSocketu používá záložní kontrolu revize přes REST API každých 15 sekund.
- Změna na klientovi se po krátké slučovací prodlevě 350 ms odešle jako úplný ověřený snímek. Cílová doba změna → druhé zařízení je nejvýše 3 sekundy při běžném připojení a dostupném serveru; nejde o garantovanou dobu při pomalé síti, studeném startu hostingu nebo výpadku.
- WebSocket fan-out v tomto DEV balíčku je procesní (jedna instance API). Pokud se API později horizontálně škáluje na více instancí, je nutné doplnit sdílené doručování událostí přes PostgreSQL `LISTEN/NOTIFY` nebo externí pub/sub. REST záložní kontrola zajišťuje následné dohnání revize.
- Adresa API je pevně nastavena v klientovi a není zobrazena v uživatelském nastavení. V ostré verzi je vhodné přesunout ji do build konfigurace, aby nebyla editovatelná uživatelem.


## Ověření účtu jedním kliknutím a reset hesla kódem v aplikaci (Make.com)

- VERIFY a RESEND posílají odkaz na `/account/verify?lang=...#token=...`.
- RESET posílá osmimístný jednorázový kód do pole `code`; uživatel zadá nové heslo, potvrzení a kód přímo v aplikaci.
- GET stránka token nespotřebuje. Token je v části URL za znakem `#`, takže se neposílá serveru v prvním GET požadavku; stránka jej předá API až po výslovném kliknutí uživatele. Tím se omezí riziko předčasné aktivace bezpečnostními skenery e-mailových schránek i úniku tokenu do běžných serverových access logů.
- Stránky jsou lokalizované v CS/EN/DE/FR/PL/ES a používají `no-store`, `no-referrer` a CSP.
- Make e-mailová šablona musí použít `link` jako `href` hlavního tlačítka. Samostatné pole s tokenem se do Make neposílá a token se nemá zobrazovat jako opisovací kód.
- Ověřovací odkaz načte stránku, která po načtení automaticky odešle potvrzení na backend; běžný uživatel nemusí klikat podruhé. RESET zůstává celý v aplikaci.

## Změna přihlašovacích údajů – verze 2.6

- `POST /auth/password/change` – vyžaduje platný Bearer token, současné heslo a nové heslo o délce nejméně 12 znaků. Po změně se zvýší `auth_version` a staré relace se zneplatní.
- `POST /auth/email/change` – vyžaduje současné heslo a novou e-mailovou adresu. Server odešle ověřovací e-mail přes stávající Make VERIFY větev. Adresa se změní až po potvrzení jednorázového odkazu; při změně se zneplatní staré relace.
- `account_tokens.pending_email` uchovává cílovou adresu do dokončení ověření. Povolené účely tokenů nově zahrnují `email_change`.
- Před nasazením 2.6 spusťte `NEON_MIGRATION_2.6.sql`, která bezpečně přidá `pending_email` a rozšíří kontrolní omezení účelu tokenu. Existující tokeny ani uživatelská data se nemažou.
