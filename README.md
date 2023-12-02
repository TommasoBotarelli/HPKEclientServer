# HPKEclientServer

La repo è divisa in 3 cartelle:

- `encryption/` cartella contenente l'eseguibile Python che permette di effettuare l'encryption di un messaggio.
  Le configurazioni per effettuare l'encryption devono essere introdotte nel file `encryption_info.json`.
  Questo eseguibile permette di richiedere da tastiera un messaggio di cui fare encryption e salvare in un json le informazioni necessarie per effettuare la decryption e il messaggio cifrato;
- `decryption/` cartella contenente l'eseguibile Python che permette di effettuare la decryption di un messagggio cifrato. TODO
- `client-server/` cartella contenente i due eseguibili Python che simulano una comunicazione client server.
  Avviando i due eseguibili `receiver.py` e `sender.py` è possibile effettuare uno scambio di messaggi in modo cifrato utilizzando HPKE.
  Nei due file JSON `receiver_data.json` e `sender_data.json` si possono trovare le informazioni utili per la configurazione delle due entità.
  I messaggi da inviare sono richiesti tramite input da tastiera.
