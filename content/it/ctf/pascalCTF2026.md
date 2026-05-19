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

La PascalCTF 2026 è stata una competizione di Capture The Flag (CTF) organizzata dal nostro team [Paolo](https://pascalctf.github.io/). La competizione si è svolta dal `31 gennaio 2026` al `1 febbraio 2026` e ha visto la partecipazione di numerosi team provenienti da tutto il mondo.

Buona parte delle challenge è stata creata per l'edizione **Beginner** tenutasi nello stesso mese presso l'[ITT Pascal](https://www.ispascalcomandini.it/pagine/pascal-ctf). Le challenge erano suddivise in diverse categorie, tra cui *Web Security*, *Cryptography*, *Binary Exploitation*, *Reverse Engineering*, *Miscellaneous* e *Intelligenza Artificiale*. Ogni categoria presentava sfide di difficoltà variabile, adatte sia a principianti che a esperti.

![pascalCTF 2026](/images/pascalctf2026.jpeg)

Ci teniamo inoltre a ringraziare tutti i **partecipanti** per il loro entusiasmo e la loro dedizione, nonché i nostri [**sponsors**](/it/sponsors#2026) per il loro supporto.

## Web 🌐

### JSHit
* Autore: `Alan Davide Bovo`[`@AlBovo`](https://github.com/AlBovo)

Come si può intuire dal nome, questa challenge era basata su un semplice script JSFuck il quale poteva essere "deoffuscato" mediante un semplice `toString()`:

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

Ciò nonostante il metodo più veloce per risolvere una challenge del genere era semplicemente utilizzare un qualsiasi LLM disponibile (ad esempio ChatGPT) e chiedergli di deoffuscare il codice, ottenendo così la flag in pochi secondi.

### ZazaStore
* Autore: `Enea Maroncelli`[`@ZazaMan`](https://github.com/Eneamaroncelli27)
* Autore: `Alan Davide Bovo`[`@AlBovo`](https://github.com/AlBovo)

TODO

```javascript
const content = {
    "RealZa": process.env.FLAG,
    "FakeZa": "pascalCTF{this_is_a_fake_flag_like_the_fake_za}",
    "ElectricZa": "<img src='images/ElectricZa.jpeg' alt='Electric Za'>",
    "CartoonZa": "<img src='images/CartoonZa.png' alt='Cartoon Za'>"
};
const prices = { "FakeZa": 1, "ElectricZa": 65, "CartoonZa": 35, "RealZa": 1000 };
```



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

## Cryptography 🔒

### XorD
* Autore: `Filippo Boschi`[`@pllossi`](https://github.com/pllossi)

La challenge forniva un semplice script Python che implementava una cifratura XOR mediante un One-Time Pad (OTP) inizializzato con un seed fisso:

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

Questa challenge come si può intuire dal nome si basava interamente sulla risoluzione di un normalissimo sistema di equazioni lineari le cui incognite altro non erano che i singoli byte della flag. Il sistema veniva generato in maniera casuale, ma con la garanzia che avesse una soluzione unica, e veniva fornito al giocatore sotto forma di stringa:

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

Per risolvere il sistema, era sufficiente utilizzare un qualsiasi software di algebra computazionale (ad esempio Wolfram Alpha) o scrivere una semplice solve mediante l'utilizzo di librerie come [`z3`](https://ericpony.github.io/z3py-tutorial/guide-examples.htm).

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
Nonostante le diverse problematiche incontrate durante l'organizzazione e lo svolgimento della competizione, siamo estremamente soddisfatti del risultato finale e della partecipazione che abbiamo ricevuto. Vorremmo però anche scusarci con tutti i partecipanti per eventuali disagi o problemi tecnici che si sono verificati durante la competizione, e assicurarvi che faremo del nostro meglio per evitare che si ripetano in futuro.

Ci teniamo inoltre a riflettere sull'utilizzo degli **LLM** e dell'**AI** in generale all'interno delle competizioni CTF. Se da un lato queste tecnologie possono essere strumenti estremamente potenti per risolvere le challenge, dall'altro rischiano di rendere alcune sfide troppo *semplici* o addirittura *banali*. Per questo motivo, stiamo valutando l'idea di introdurre delle **limitazioni** all'utilizzo di questi strumenti nelle future edizioni della PascalCTF, al fine di mantenere un certo livello di difficoltà e di stimolare la creatività e l'ingegno dei partecipanti.

Il nostro scopo rimarrà infatti, oggi come in futuro, quello di offrire una competizione *divertente*, *educativa* e *stimolante* per tutti i partecipanti, indipendentemente dal loro livello di esperienza o dalle tecnologie che decidono di utilizzare.

Speriamo che questa competizione abbia offerto un'opportunità di apprendimento e divertimento a tutti i partecipanti, e non vediamo l'ora di organizzare la prossima edizione della PascalCTF 🔜