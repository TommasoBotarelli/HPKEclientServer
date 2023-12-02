# HPKEclientServer

Questa repo ha come obiettivo l'implementazione del metodo di cifratura dei messaggi chiamato HPKE.

L'implementazione si basa sull'utilizzo della libreria `pyhpke` ([repo](https://github.com/dajiaji/pyhpke)).
L'implementazione dell'encryption e la decryption è stata testata sui test vectors forniti direttamente dalla documentazione ufficiale di HPKE reperibili al seguente [link](https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json).
Per la parte di client-server si possono introdurre varie impostazioni per la cifratura (reperibili anche queste dai test vectors linkati sopra).

La repo è divisa in 3 cartelle:

- `encryption/` cartella contenente l'eseguibile Python che permette di effettuare l'encryption di un messaggio.
  Le configurazioni per effettuare l'encryption devono essere introdotte nel file `encryption_info.json`.
  Questo file permette di contenere varie impostazioni che possono essere ricavate dai test vectors. L'eseguibile andrà a scegliere una configurazione casuale e effettuerà l'encryption utilizzando tale modalità di cifratura.
  L'eseguibile poi permetterà di richiedere da tastiera un messaggio di cui fare encryption e salvare in un json le informazioni necessarie per effettuare la decryption (cioè le impostazioni di cifratura) e il messaggio cifrato.
  Il file JSON in uscita ha template simile ai test vectors che si sono utilizzati per testare l'implementazione, quindi è aggiunto al file anche il testo in chiaro che ci si aspetta riuscire a recuperare con la parte di decryption;
- `decryption/` cartella contenente l'eseguibile Python che permette di effettuare la decryption di un messagggio cifrato. TODO
- `client-server/` cartella contenente i due eseguibili Python che simulano una comunicazione client server.
  Avviando i due eseguibili `receiver.py` e `sender.py` è possibile effettuare uno scambio di messaggi in modo sicuro utilizzando HPKE.
  Nei due file JSON `receiver_data.json` e `sender_data.json` si possono trovare le informazioni utili per la configurazione delle due entità.
  I messaggi da inviare sono richiesti tramite input da tastiera e la comunicazione può avvenire in entrambi i sensi in modo asincrono.


