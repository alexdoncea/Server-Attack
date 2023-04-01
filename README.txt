Tema Introducere in Criptologie - Doncea Ilie-Alexandru 341C4

Task-uri realizate: task 1

Mod rulare: pentru Linux -> python3 skel.py
			pentru Windows -> python3 ./skel.py

Inainte de a ma apuca sa rezolv tema a fost nevoie sa ma ocup de probleme
legate de Python si de pachete, intrucat interpretorul nu vedea pachetele
pycryptodome si pwntools desi acestea erau instalate. Aceasta problema am
rezolvat-o prin utilizarea unui Virtual Enviroment pe WSL, insa aici am avut
parte de alte erori, si anume dupa apelul functiei sendline() din get_token()
si login() codul devenea unreachable (eroare pe care am rezolvat o ulterior
prin cateva update-uri de pachete) si primirea EOFError la rulare la apelul
functiei readuntil() din read_options(). Cea din urma eroare a fost mai dificil
de rezolvat, deoarece nimic din ce scria pe internet nu functiona. Am trecut de
aceasta eroare prin a crea un enviroment nou, curat, cu reinstalarea tuturor
lucrurilor necesare, inclusiv Python.

Am inceput lucrul efectiv la tema prin a analiza fisierul server.py. Prin
rularea sevrerului am observat ca se pot face doar doua operatii pe server:
cererea de token guest si introducerea unui token pentru logare. Urmarind codul
sursa am vazut ca tokenul primit de la server este pentru user-ul Anonymous
si este creat in functia encrypt(). In aceasta functie se poate observa ca
token-ul este format din 3 siruri concatenate: numele utilizatorului criptat
prin operatia xor cu o cheie random dar care ramane constanta pe toata durata
rularii serverului, SERVER_PUBLIC_BANNER care este un sir constant si
integritatea, care si ea este random. Deci token-ul este format din doua
siruri randomizate si un sir constant. Imediat dupa am inceput sa cer in mod
repetat token-uri de la server:

low9S2PcyR6wAXN1p+X5/Q==
dCHcaJzNboZDAXN1p+X57A==
/NKiDl6XudatAXN1p+X5lQ==
WdSr9LSad2vKAXN1p+X5Ug==
l8HtxkaIT31MAXN1p+X5eA==
UjcuOXFFSMyPAXN1p+X5bA==
zXJ4luNlyvxtAXN1p+X5xg==
xCLPGeiMr346AXN1p+X50w==
wH7UWUiomwTWAXN1p+X5tg==
6c+EMTE3565xAXN1p+X5Tg==

Analizand mai atent aceste token-uri am observat ca bucata AXN1p+X5 apare in
fiecare token in exact aceeasi pozitie, iar de aici am dedus ca acesta ar fi
SERVER_PUBLIC_BANNER. Tot in codul sursa al serverului am putut observa ca se
cere tokenul utilizatorului Ephvuln pentru a putea accesa flag-ul. Astfel,
pentru a putea ajunge la flag trebuie sa introducem un token de forma:
	Ephvuln XOR k + SERVER_PUBLIC_BANNER + integrity
unde: k este o cheie random pentru operatia xor, dar ramane constanta in
		timpul rularii serverului
	  SERVER_PUBLIC_BANNER este o constanta pe care o stim: AXN1p+X5
	  integrity este o valoare random pe care nu o stim

Pentru a afla cipher-ul utilizatorului Ephvuln este indeajuns sa facem de doua
ori operatia XOR: Anonymous XOR token-ul primit de la server pentru a afla k
					(chiar daca in mod normal pentru XOR este necesar ca ambii
					termeni sa aiba aceeasi lungime, cu ajutorul functiei zip()
					token-ul este trunchiat la len(Anonymous) = 9 bytes)
				  Ephvuln XOR k pentru a afla cipher-ul care trebuie bagat in
					token-ul de atac.
Dupa ce am aplicat operatia XOR de doua ori am aflat cipher-ul pentru Ephvuln,
caruia i se adauga SERVER_PUBLIC_BANNER. Tot ce mai lipseste din token-ul de
atac este integritatea, despre care nu stim nimic, doar ca este random.
					
Intrucat AXN1p+X5 are 8 caractere in b64, scris in biti va avea lungimea 16,
deoarece pentru 4 caractere in b64 corespund 3 bytes => len(b'AXN1p+X5') = 6.
Astfel, lungimea cumulata a tot ce cunoastem pana acum, si anume cipher-ul
pentru Anonymous si SERVER_PUBLIC_BANNER este de 9 + 6 = 15 bytes, iar daca ne
uitam in codul sursa al serverului se poate gasi in functia login() un if in
care se verifica daca lungimea token-ului primit este mai mare de 16 bytes,
ceea ce inseamna ca un token nu are voie sa fie mai lung de 16 bytes. Iar cum
token-ul primit de la server are deja 15 bytes => lungimea integrity-ului este
de 1 byte, adica 8 biti. Drept urmare, integrity poate lua 2^8 = 256 de valori.

Pentru ca len(integrity) = 1 si nu mai stim nimic altceva, putem sa iteram prin
fiecare valoare pentru a gasi token-ul potrivit. Astfel, vom folosi un atac de
tip bruteforce pentru a captura flag-ul: la sirul format din cipher-ul pentru
Ephvuln si SERVER_PUBLIC_BANNER vom alipi fiecare valoare posibila, de la 0 la
255 pentru integrity pana cand token-ul nostru este acceptat de server si va
afisa flag-ul: Secret: CTF{Ez_T4g_Cr4ftyng}. Am folosit functia to_bytes pentru
a transforma integer in bytes pentru daca as fi transformat in caractere care
apoi erau codificate as fi trecut si prin valori de 2 bytes, astfel programul
negasind flag-ul de fiecare data. 

Am pus si comentarii care sa detalieze mai bine modul de lucru al algoritmului
in fisierul skel.py. Nu am comentat si functiile care erau deja date in schelet
din motive evidente.
