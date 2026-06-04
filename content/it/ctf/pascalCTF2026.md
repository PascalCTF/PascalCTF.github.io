---
title: "Pascal CTF 2026"
date: 2026-01-31T00:00:00+00:00
# weight: 1
# aliases: ["/first"]
tags: ["pascalCTF", "ctf", "binary", "crypto", "web", "ai", "pascalCTF2026"]
author: "Paolo"
# author: ["Me", "You"] # multiple authors
showToc: true
TocOpen: false
draft: false
hidemeta: false
comments: false
description: "Alcune writeup della PascalCTF CTF 2026."
canonicalURL: "https://pascalctf.github.io/it/ctf/"
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
    alt: "Pascal CTF 2026" # alt text
    caption: "Alcune writeup della PascalCTF CTF 2026." # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
editPost:
    URL: "https://github.com/PascalCTF/PascalCTF.github.io/blob/main/content/it"
    Text: "Suggerisci Modifiche" # edit text
    appendFilePath: true # to append file path to Edit link
---

# Pascal CTF 2026
![pascalCTF logo](/images/pascalCTF.png)

La PascalCTF 2026 è stata una competizione di Capture The Flag (CTF) organizzata dal nostro team [Paolo](https://pascalctf.github.io/). Si è svolta dal `31 gennaio 2026` al `1 febbraio 2026` e ha visto la partecipazione di numerosi team provenienti da tutto il mondo.

Gran parte delle challenge è stata realizzata per l'edizione **Beginner**, ospitata nello stesso mese presso l'[ITT Pascal](https://www.ispascalcomandini.it/pagine/pascal-ctf). Le sfide erano suddivise in diverse categorie, tra cui *Web Security*, *Cryptography*, *Binary Exploitation*, *Reverse Engineering*, *Miscellaneous* e *Intelligenza Artificiale*, con difficoltà variabile e adatte sia a principianti sia a esperti.

![pascalCTF 2026](/images/pascalctf2026.jpeg)

Desideriamo inoltre ringraziare tutti i **partecipanti** per l'entusiasmo e la dedizione dimostrati, così come i nostri [**sponsors**](/it/sponsors#2026) per il loro supporto.

## Web 🌐

### JSHit
* Autore: `Alan Davide Bovo`[`@AlBovo`](https://github.com/AlBovo)

Come suggerisce il nome, questa challenge era basata su un semplice script JSFuck, che poteva essere "deoffuscato" con un banale `toString()`:

```javascript
let f = [][(![]+[])[+!+[]]+(!![]+[]) ... ];
console.log(f.toString())
```

Una volta deoffuscato, lo script risultava essere il seguente:

```javascript
() => {
    const pageElement = document.getElementById('page');
    const flag = document.cookie.split('; ').find(row => row.startsWith('flag='));
    const pageContent = `<div class="container"><h1 class="mt-5">Welcome to JSHit</h1><p class="lead">${flag && flag.split('=')[1] === 'pascalCTF{1_h4t3_j4v4scr1pt_s0o0o0o0_much}' ? 'You got the flag gg' : 'You got no flag yet lol'}</p></div>`;
    pageElement.innerHTML = pageContent;
    console.log("where's the page gone?");
    document.getElementById('code').remove();
}
```

Nonostante ciò, il modo più veloce per risolvere una challenge del genere era semplicemente usare un qualsiasi LLM disponibile, ad esempio ChatGPT, chiedendogli di deoffuscare il codice e ottenendo così la flag in pochi secondi.

### ZazaStore
* Autore: `Enea Maroncelli`[`@ZazaMan`](https://github.com/Eneamaroncelli27)
* Autore: `Alan Davide Bovo`[`@AlBovo`](https://github.com/AlBovo)

ZazaStore era un sito scritto in *NodeJS* che implementava alcune funzionalità molto semplici tipiche di un e-commerce.

In sintesi, il sito permetteva di acquistare alcuni oggetti, tra cui anche la **flag**:

```javascript
const content = {
    "RealZa": process.env.FLAG,
    "FakeZa": "pascalCTF{this_is_a_fake_flag_like_the_fake_za}",
    "ElectricZa": "<img src='images/ElectricZa.jpeg' alt='Electric Za'>",
    "CartoonZa": "<img src='images/CartoonZa.png' alt='Cartoon Za'>"
};
const prices = { "FakeZa": 1, "ElectricZa": 65, "CartoonZa": 35, "RealZa": 1000 };
```

Osservando il modo in cui veniva inizializzato un utente, si notava che nessun giocatore disponeva ovviamente di abbastanza denaro per acquistare la flag in `RealZa`...
```javascript
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (username && password) {
        req.session.user = true;
        req.session.balance = 100;
        req.session.inventory = {};
        req.session.cart = {};
        return res.json({ success: true });
    } else {
        res.json({ success: false });
    }
});
```

Analizzando gli altri endpoint, però, saltava subito all'occhio `/add-cart`, che permetteva di aggiungere un prodotto al carrello salvato nella sessione tramite un oggetto `product`.
```javascript
app.post('/add-cart', (req, res) => {
    const product = req.body;
    if (!req.session.cart) {
        req.session.cart = {};
    }
    const cart = req.session.cart;
    if ("product" in product) {
        const prod = product.product;
        const quantity = product.quantity || 1;
        if (quantity < 1) {
            return res.json({ success: false });
        }
        if (prod in cart) {
            cart[prod] += quantity;
        } else {
            cart[prod] = quantity;
        }
        req.session.cart = cart;
        return res.json({ success: true });
    }
    res.json({ success: false });
});
```

Prestando attenzione si può notare che viene controllato solo il nome del prodotto, e quindi di fatto sanitizzato, mentre la quantità non viene mai verificata per accertarsi che sia un `Number` e rimane quindi completamente non sanitizzata. 

Per capire il vero exploit bisogna però guardare anche l'endpoint `/checkout`, che usa la sessione inizializzata da `/login` e modificata da `/add-cart` per calcolare il totale dei prodotti e verificare che sia inferiore al saldo disponibile.

Solo nel caso in cui il saldo disponibile sia sufficiente, i prodotti vengono aggiunti all'inventario dell'utente e quindi mostrati:
```javascript
app.post('/checkout', (req, res) => {
    if (!req.session.inventory) {
        req.session.inventory = {};
    }
    if (!req.session.cart) {
        req.session.cart = {};
    }
    const inventory = req.session.inventory;
    const cart = req.session.cart;

    let total = 0;
    for (const product in cart) {
        total += prices[product] * cart[product];
    }

    if (total > req.session.balance) {
        res.json({ "success": true, "balance": "Insufficient Balance" });
    } else {
        req.session.balance -= total;
        for (const property in cart) {
            if (inventory.hasOwnProperty(property)) {
                inventory[property] += cart[property];
            }
            else {
                inventory[property] = cart[property];
            }
        }
        req.session.cart = {};
        req.session.inventory = inventory;
        res.json({ "success": true });
    }
});
```

La domanda spontanea è però: *come faccio ad avere abbastanza soldi per comprare la flag?*

Questo, però, è il punto di vista sbagliato per risolvere la challenge: grazie ai dettagli notati in `/add-cart`, possiamo infatti impostare la quantità di un prodotto su un qualunque oggetto (`"stringa"`, `0`, `{}`, `[]`).

A questo punto vogliamo bypassare due controlli:
1. L'`if` presente in `/add-cart` il quale controlla che `quantity < 1`
2. L'`if` presente in `/checkout` il quale controlla che `total > req.session.balance`

Per superare il primo `if` si possono usare tutti e tre i casi tra **stringhe**, **array** (con almeno un oggetto) e un **oggetto** vuoto (`{}`).

Nel secondo `if`, invece, il metodo intended per rendere sufficiente il bilancio era usare una **stringa** oppure un **oggetto**, così che la moltiplicazione `prices[product] * cart[product]` producesse **`NaN`**.

Per definizione, `NaN < x` e `NaN > x` restituiscono entrambe `false` e, in questo caso specifico, poiché il sito controlla se l'utente ha superato il proprio bilancio, il fatto che questa verifica ritorni `false` consente di acquistare qualsiasi cosa!

### Travel Playlist
* Autore: `Alan Davide Bovo`[`@AlBovo`](https://github.com/AlBovo)

Il codice di questo sito era davvero minimale ed era sostanzialmente il seguente:
```python
from flask import Flask, jsonify, request, render_template

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/pages/<int:index>")
def page(index):
    return render_template("pages.html", index=index)

@app.route("/api/get_json", methods=["POST"])
def get_json():
    index = request.json.get("index")
    if not index:
        return jsonify({"error": "Index is required"}), 400
    
    path = f"static/{index}"
    try:
        with open(path, "r") as file:
            data = file.read()
        return data, 200
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
```

Un po' come nella challenge precedente, l'endpoint interessante era `/api/get_json`, che accettava un JSON e restituiva il contenuto del file `static/{index}`.

Guardando la cartella *static* si trovano 7 file con indici da **1** a **7**, ma il loro contenuto non è particolarmente interessante.

La flag, infatti, si trova in `flag.txt` e non in `static/flag.txt`.

L'aspetto rilevante per risolvere la challenge è che questa normalissima path traversal non implementa nemmeno un controllo sull'indice, che può assumere qualsiasi valore e non solo un intero.

Di conseguenza, il sito risponde senza problemi a un normale `{"index": "../flag.txt"}`, restituendo direttamente la flag.

## Cryptography 🔒

### XorD
* Autore: `Filippo Boschi`[`@pllossi`](https://github.com/pllossi)

La challenge forniva un semplice script Python che implementava una cifratura XOR tramite un One-Time Pad (OTP) inizializzato con un seed fisso:

```python
import os
import random

def xor(a, b):
    return bytes([a ^ b])

flag = os.getenv('FLAG', 'pascalCTF{REDACTED}')
encrypted_flag = b''

random.seed(1337)
for i in range(len(flag)):
    random_key = random.randint(0, 255)
    encrypted_flag += xor(ord(flag[i]), random_key)

with open('output.txt', 'w') as f:
    f.write(encrypted_flag.hex())
```

Il file `output.txt` conteneva la flag cifrata in formato esadecimale. L'obiettivo era recuperarla partendo da questo file.

La vulnerabilità risiedeva nell'uso di un seed fisso (`1337`). Poiché la sequenza del generatore pseudo-casuale di Python è deterministica, era possibile rigenerare esattamente la stessa sequenza di chiavi utilizzate per la cifratura. Ricostruendo questa sequenza e applicando l'operazione XOR inversa ai byte cifrati, era possibile recuperare il testo in chiaro della flag.

### Ice Cramer
* Autore: `Alan Davide Bovo`[`@AlBovo`](https://github.com/AlBovo)

Come suggerisce il nome, questa challenge si basava interamente sulla risoluzione di un normale sistema di equazioni lineari, in cui le incognite erano i singoli byte della flag. Il sistema veniva generato in modo casuale, ma con la garanzia di avere una soluzione unica, e veniva fornito al giocatore sotto forma di stringa:

```python
def generate_system(values):
    for _ in values:
        eq = []
        sol = 0
        for i in range(len(values)):
            k = randint(-100, 100)
            eq.append(f"{k}*x_{i}")
            sol += k * values[i]

        streq = " + ".join(eq) + " = " + str(sol)
        print(streq)
```

Per risolvere il sistema era sufficiente usare un qualsiasi software di algebra computazionale, ad esempio Wolfram Alpha, oppure scrivere un semplice solver con librerie come [`z3`](https://ericpony.github.io/z3py-tutorial/guide-examples.htm).

### Linux Penguin
* Autore: `Alan Davide Bovo`[`@AlBovo`](https://github.com/AlBovo)

TODO

### Curve Ball
* Autore: `Alan Davide Bovo`[`@AlBovo`](https://github.com/AlBovo)

TODO

### wordy
* Autore: `Alessandro Bombarda`[`@ale18V`](https://github.com/ale18V)

TODO

## Binary Exploitation 💻

## Reverse Engineering ⚙️

## Miscellaneous 🧭

## Intelligenza Artificiale 🤖

### Tea Guardian
TODO

### Selfish AI
TODO

### 🤓 AI
TODO

### My ai lover
TODO

### Geoguesser Revenge
TODO

## Conclusioni
Nonostante le diverse problematiche incontrate durante l'organizzazione e lo svolgimento della competizione, siamo estremamente soddisfatti del risultato finale e della partecipazione ricevuta. Vorremmo però anche scusarci con tutti i partecipanti per eventuali disagi o problemi tecnici verificatisi durante la competizione, e assicurarvi che faremo del nostro meglio per evitare che si ripetano in futuro.

Vogliamo inoltre riflettere sull'utilizzo degli **LLM** e dell'**AI** in generale all'interno delle competizioni CTF. Se da un lato queste tecnologie possono essere strumenti estremamente potenti per risolvere le challenge, dall'altro rischiano di rendere alcune sfide troppo *semplici* o addirittura *banali*. Per questo motivo, stiamo valutando l'idea di introdurre delle **limitazioni** all'utilizzo di questi strumenti nelle future edizioni della PascalCTF, così da mantenere un certo livello di difficoltà e stimolare la creatività e l'ingegno dei partecipanti.

Il nostro scopo rimarrà infatti, oggi come in futuro, quello di offrire una competizione *divertente*, *educativa* e *stimolante* per tutti i partecipanti, indipendentemente dal loro livello di esperienza o dalle tecnologie che decidono di utilizzare.

Speriamo che questa competizione abbia offerto un'opportunità di apprendimento e divertimento a tutti i partecipanti, e non vediamo l'ora di organizzare la prossima edizione della PascalCTF 🔜