# Metamorphose - HackMyVM (Hard)

![Metamorphose.png](Metamorphose.png)

## Übersicht

*   **VM:** Metamorphose
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Metamorphose)
*   **Schwierigkeit:** Hard
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 05. August 2024
*   **Original-Writeup:** https://alientec1908.github.io/Metamorphose_HackMyVM_Hard/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Metamorphose" zu erlangen. Der initiale Zugriff erfolgte durch Ausnutzung des Erlang Port Mapper Daemon (EPMD) und des Erlang Distribution Protocols. Durch Analyse des Netzwerkverkehrs wurde das Erlang-Cookie extrahiert, was Remote Code Execution (RCE) als Benutzer `melbourne` ermöglichte. Die erste Rechteausweitung zum Benutzer `coralie` gelang durch das Auslesen und Knacken eines SHA256-Passwort-Hashes für `coralie`, der in einem Kafka-Topic (`users.properties`) gefunden wurde. Die finale Eskalation zu Root erfolgte ebenfalls durch das Knacken des SHA256-Passwort-Hashes für den `root`-Benutzer, der im selben Kafka-Topic gefunden wurde, und anschließender Verwendung des Passworts mit `su`.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `vi` / `nano`
*   `nmap`
*   `nc` (netcat)
*   `git`
*   Wireshark
*   `python2` (für Erlang Exploit)
*   `stty`
*   `find`
*   `sudo` (versucht)
*   `getcap`
*   `whereis`
*   `grep`
*   `kafka-topics.sh`
*   `kafka-console-consumer.sh`
*   `echo`
*   `john`
*   `ssh`
*   `cp`
*   `debugfs` (versucht, nicht erfolgreich)
*   Standard Linux-Befehle (`id`, `ls`, `cat`, `cd`, `pwd`, `su`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Metamorphose" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Erlang Enumeration:**
    *   IP-Adresse des Ziels (192.168.2.113) mit `arp-scan` identifiziert. Hostname `metamorphose.hmv` in `/etc/hosts` eingetragen.
    *   `nmap`-Scan offenbarte Port 22 (SSH, OpenSSH 9.2p1), Port 4369 (EPMD, Erlang Port Mapper Daemon) und einen dynamischen Port (z.B. 38639, später 40155) für einen Erlang-Knoten namens `network`.
    *   Manuelle Abfrage an EPMD (`echo -n -e "\x00\x01\x6e" | nc ... 4369`) bestätigte den Knotennamen und aktuellen Port.

2.  **Erlang EPMD Exploitation & Initial Access (als `melbourne`):**
    *   Mittels Wireshark wurde der Netzwerkverkehr während der Interaktion mit dem Erlang-Knoten mitgeschnitten.
    *   Im TCP-Stream wurde das Erlang-Cookie `SAPUKI@nowhere` und der vollständige Knotenname `network@metamorphose` identifiziert. Es wurde auch sichtbar, dass Befehle wie `os:cmd('id')` erfolgreich als Benutzer `melbourne` ausgeführt wurden.
    *   Mit einem Python2-Skript (z.B. `shell-erldp.py` aus `erl-matter`) und den gefundenen Informationen (IP, Knotenport, Cookie "batman" - *Abweichung vom Wireshark-Fund, aber funktionierend laut Log*) wurde eine Reverse Shell als Benutzer `melbourne` zu einem Netcat-Listener aufgebaut.

3.  **Privilege Escalation (von `melbourne` zu `coralie` via Kafka Leak):**
    *   Als `melbourne` wurde im Verzeichnis `/opt/kafka/bin/` das Kafka-Topic `users.properties` entdeckt.
    *   Mittels `./kafka-console-consumer.sh --bootstrap-server localhost:9092 --topic users.properties --from-beginning` wurde der Inhalt des Topics ausgelesen.
    *   Das Topic enthielt JSON-Objekte mit Benutzernamen und SHA256-Passwort-Hashes, u.a. für `coralie` (`9bf4...`) und `root` (`e2f7...`).
    *   Der SHA256-Hash für `coralie` wurde (implizit im Log) geknackt.
    *   Erfolgreicher SSH-Login als `coralie` mit dem geknackten Passwort.
    *   Die User-Flag (`aab176494645050f3e8a7b081d443d3b`) wurde in `/home/coralie/user.txt` gefunden.

4.  **Privilege Escalation (von `coralie` zu `root` via Kafka Leak & `su`):**
    *   Der zuvor aus dem Kafka-Topic extrahierte SHA256-Passwort-Hash für `root` (`e2f7a3617512ed81aa68c7be9c435609cfb513b021ce07ee9d2759f08f4d9054`) wurde mit `john` und `rockyou.txt` geknackt. Das Passwort war `my2monkeys`.
    *   Als `coralie` wurde `su root` ausgeführt und das Passwort `my2monkeys` eingegeben.
    *   Erfolgreicher Wechsel zu Root.
    *   Die Root-Flag (`ac7f9ad56c6a07f55cdfd71aec2e04d5`) wurde in `/root/root.txt` gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Erlang EPMD / Distribution Protocol RCE:** Ein exponierter EPMD und ein Erlang-Knoten mit einem bekannten oder leicht zu erratenden/extrahierenden Cookie ermöglichten Remote Code Execution durch Missbrauch der `os:cmd`-Funktionalität.
*   **Informationsleck in Kafka:** Sensible Benutzerdaten, einschließlich Passwort-Hashes (SHA256), wurden ungeschützt in einem Kafka-Topic (`users.properties`) gespeichert und waren für einen Benutzer mit lokalen Zugriffsrechten lesbar.
*   **Schwache Passwörter / Passwort-Cracking:** Die SHA256-Hashes für `coralie` (implizit) und `root` (`my2monkeys`) konnten mit Wörterbuchangriffen geknackt werden.
*   **Netzwerkanalyse (Wireshark):** Extraktion des Erlang-Cookies durch Analyse des Netzwerkverkehrs.

## Flags

*   **User Flag (`/home/coralie/user.txt`):** `aab176494645050f3e8a7b081d443d3b`
*   **Root Flag (`/root/root.txt`):** `ac7f9ad56c6a07f55cdfd71aec2e04d5`

## Tags

`HackMyVM`, `Metamorphose`, `Hard`, `Erlang EPMD Exploit`, `Erlang Cookie`, `RCE`, `Kafka`, `Information Disclosure`, `Password Cracking`, `SHA256`, `Linux`, `Privilege Escalation`, `Wireshark`
