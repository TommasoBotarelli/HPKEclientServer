# HPKEclientServer

Questa repo ha come obiettivo l'implementazione del framework per la comunicazione sicura chiamato HPKE (Hybrid Public Key Encryption).

L'implementazione si basa sull'utilizzo della libreria python `pyhpke` ([repo](https://github.com/dajiaji/pyhpke)).
L'implementazione dell'encryption e la decryption è stata testata sui test vectors forniti direttamente dalla documentazione ufficiale di HPKE reperibili al seguente [link](https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json).
Per la parte di client-server si possono introdurre varie impostazioni per la cifratura (reperibili anche queste dai test vectors linkati sopra).

La repo è divisa in 3 cartelle:

- `encryption/` cartella contenente l'eseguibile Python che permette di effettuare l'encryption di un messaggio.
  Le configurazioni per effettuare l'encryption devono essere introdotte nel file `encryption_info.json`.
  Questo file permette di contenere varie impostazioni che possono essere ricavate dai test vectors. L'eseguibile andrà a scegliere una configurazione casuale e effettuerà l'encryption utilizzando tale modalità di cifratura.
  L'eseguibile poi permetterà di richiedere da tastiera un messaggio di cui fare encryption e salvare in un json le informazioni necessarie per effettuare la decryption (cioè le impostazioni di cifratura) ed il messaggio cifrato.
  Il file JSON in uscita ha template simile ai test vectors che si sono utilizzati per testare l'implementazione, quindi è aggiunto al file anche il testo in chiaro che ci si aspetta riuscire a recuperare con la parte di decryption;
- `decryption/` cartella contenente l'eseguibile Python che permette di effettuare la decryption di un messagggio cifrato. Come per l'encryption, anche in questo caso l'eseguibile selezionerà casualmente un test vector per mostrare la decifratura del plaintext presente al suo interno, andando ad usare le informazioni necessarie fornite appunto nel test vector;
- `client-server/` cartella contenente i due eseguibili Python che simulano una comunicazione client server.
  Avviando i due eseguibili `receiver.py` e `sender.py` è possibile effettuare uno scambio di messaggi in modo sicuro utilizzando HPKE.
  Nei due file JSON `receiver_data.json` e `sender_data.json` si possono trovare le informazioni utili per la configurazione delle due entità.
  I messaggi da inviare sono richiesti tramite input da tastiera e la comunicazione può avvenire in entrambi i sensi in modo asincrono.

Oltre a queste 3 cartelle è presente un eseguibile chiamato `test_hpke` che seleziona casualmente un test vector e testa che la libreria pyhpke funzioni come ci si aspetta. In particolare, recupera tutte le informazioni presenti nel test vector (chiavi, info, aad, enc, ikm, ecc...) e:

- crea la CipherSuite usando gli id di KEM, KDF e AEAD presi dal test vector;
- estrae dal test vector, insieme ai corrispondenti ikm: le chiavi effimere, le chiavi del receiver e del sender (quest'ultime solo quando presenti, a seconda della modalità) che sono codificate e le decodifica. Poi con gli ikm prelevati genera le chiavi a partire da essi e verifica che quest'ultime siano uguali a quelle prelevate dal test vector, in questo modo verifichiamo che la generazione delle chiavi funzioni correttamente;
- crea il sender context e l'enc che dovrà passare al receiver, e controlla che questo enc sia uguale a quello presente nel test vector;
- esegue il seal del plaintext preso dal vector e produce un ciphertext, verifica che il ciphertext prodotto sia uguale a quello preso dal test vector;
- crea il recipient context ed esegue l'open del ciphertext e controlla che il plaintext ottenuto sia uguale a quello del test vector.

Tutti i test vector usati sono visibili nel file `test_data` che è in `decryption/`, esso contiene 4 test vector prelevati come detto dalla documentazione ufficiale, ogni vector ha una modalità diversa tra: Base (0), PSK (1), AUTH (2) e AUTH_PSK(3); ed ognuno usa anche un algoritmo diverso per KEM, KDF e AEAD in modo da poter testare più casistiche di funzionamento. In caso si vogliano aggiungere dei test vector nel file è necessario fare qualche piccolo cambio negli eseguibili nelle parti dove si prelevano casualmente i test vector da questo file. 


