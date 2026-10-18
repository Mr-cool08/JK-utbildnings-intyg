# SSH-skydd med Fail2ban

Imagen läser egna jails från `/data/jail.d/*.local`. `fail2ban.local`
monteras i `/etc/fail2ban/`, där Fail2ban läser serverinställningarna.
Databasen ligger kvar i volymen på `/data/db`.

Jailen `sshd` läser `/var/log/host/auth.log` med filbaserad polling och
blockerar SSH med `iptables-multiport` i värdens `INPUT`-kedja.
Fem matchande fel inom 600 sekunder ger 3600 sekunders blockering.
`mode = normal` undviker de extra anslutningsfel som aggressive räknar.
`/var/log/secure` behövs inte på denna server. Att filen saknas är inte
i sig en förklaring till noll jails när en annan giltig loggfil finns.

## Automatisk driftsättning med update_app.py

`scripts/update_app.py` skapar eller kompletterar åtkomstfilen automatiskt.
Klientadressen hämtas från `SSH_CONNECTION`; redan sparade undantag och portar
behålls. Första gången hämtas även SSH-porten från sessionen. Vid ändrad
SSH-port anges `FAIL2BAN_SSH_PORTS` uttryckligen. Kontrollera att loggens
tidszon stämmer med `TZ` och att värdens SSH-loggning fungerar.

Kör från projektets rot, med projektets Python-miljö. Exempel med `.venv`:

```bash
sudo --preserve-env=SSH_CONNECTION .venv/bin/python scripts/update_app.py --fail2ban-only
```

Detta läge kör inga Git-, paket-, test-, cron- eller prune-steg och påverkar
endast Fail2ban. Det använder befintlig lokal image. Vid behov måste imagen
först hämtas med `sudo docker compose pull fail2ban`.

Den vanliga uppdateringen inkluderar också Fail2ban-steget:

```bash
sudo --preserve-env=SSH_CONNECTION .venv/bin/python scripts/update_app.py
```

Den vanliga uppdateringen behåller sitt befintliga flöde för hela appen,
inklusive stopp/start av övriga tjänster och Docker-rensning. Fail2bans
förkontroll sker efter imagehämtning men innan tjänsterna stoppas.
Fail2ban startas separat och verifieras efter appens start.

Om `SSH_CONNECTION` saknas kan en tidigare skapad åtkomstfil återanvändas.
För första obevakade körningen anges egna riktiga adresser och portar med
`FAIL2BAN_ADMIN_IPS` (mellanslagsseparerade IP-adresser eller CIDR-nät) och
`FAIL2BAN_SSH_PORTS` (kommaseparerade portnummer). De kan anges i projektets
`.env`. Använd smala undantag; undanta inte hela internet. Ett nytt SSH-IP
läggs till utan att gamla undantag raderas; rensa gamla adresser manuellt.

Skriptet avbryter om giltiga åtkomstuppgifter saknas, om `auth.log` är tom
eller saknas, eller om konfigurationstestet misslyckas. Efter start väntar
det högst 180 sekunder på healthcheck och kontrollerar 5/600/3600 samt att
alla IP-undantag finns i den körande jailen. Vid fel försöker det stoppa
endast Fail2ban och avslutar med felstatus. Om även stoppet misslyckas
meddelas detta uttryckligen. En krasch kan lämna brandväggsregler kvar.

Behåll SSH-sessionen och tillgången till leverantörens konsol tills en andra
inloggning har lyckats. Skriptet gör inga avsiktliga felinloggningar och kan
inte bevisa extern åtkomst eller faktisk trafikblockering. Loggarnas aktualitet,
tidszon och serverns brandvägg behöver fortfarande vara korrekta.

När själva uppdateringsskriptet ändrats behöver den nya versionen finnas
på disk innan det startas. Ett redan körande Python-skript laddas inte om
bara för att dess interna `git pull` hämtar en ny version.

## Manuell driftsättning på servern

Kommandona nedan är avsedda för Bash på Linux, från projektets rot och
med samma Compose-projektnamn som den befintliga installationen.
De har inte körts mot servern. Ingen absolut garanti mot utelåsning kan
ges utan att verifiera serverns nät och brandvägg. Behåll den nuvarande
SSH-sessionen och ha leverantörens konsol tillgänglig innan aktivering.

1. För över kodändringarna. Skapa sedan den lokala åtkomstfilen från din
   vanliga SSH-session, innan du byter till ett root-skal. `SSH_CONNECTION`
   ger klientadressen som servern faktiskt ser och serverporten för sessionen.
   Python 3 används för att validera värdena. Filen ignoreras av Git.
   Följande avbryter om den redan finns; granska då filen manuellt.

```bash
(
set -eu
: "${SSH_CONNECTION:?Kör från din vanliga SSH-session}"
read -r admin_ip client_port server_ip ssh_port <<< "$SSH_CONNECTION"
python3 -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1]); assert 1 <= int(sys.argv[2]) <= 65535' "$admin_ip" "$ssh_port"
test ! -e deploy/fail2ban/ssh-access.local
umask 077
printf '[sshd]\nignoreip = 127.0.0.1/8 ::1 %s\nport = %s\n\n# Copyright (c) Liam Suorsa and Mika Suorsa\n' "$admin_ip" "$ssh_port" > deploy/fail2ban/ssh-access.local
cat deploy/fail2ban/ssh-access.local
sudo test -s /var/log/auth.log
sudo tail -n 20 /var/log/auth.log
sudo sshd -T | grep '^port '
)
```

Kontrollera att `ignoreip` innehåller rätt administrationsadress och att
`port` stämmer med SSH. Lägg till andra fasta administrationsadresser,
VPN-adresser eller IPv6-adresser på samma `ignoreip`-rad om de används.
Vid flera SSH-portar anges de kommaseparerade. Om NAT översätter porten
ska den lokala port som sshd lyssnar på skyddas. Loggen måste innehålla
aktuella SSH-händelser; om den är gammal behöver värdens loggning åtgärdas
före driftsättning. `TZ` måste motsvara tidszonen i loggar utan tidszon.
Standard är `Europe/Stockholm`.

2. Kontrollera konfigurationen utan att starta en ny Fail2ban-daemon.
   Fortsätt bara om båda kommandona lyckas. Använd befintlig lokal image
   för att inte samtidigt introducera en imageuppgradering.

```bash
sudo docker compose config --quiet
sudo docker compose run --rm --no-deps --pull never fail2ban fail2ban-client -t
```

3. Återskapa endast Fail2ban. Kör inte `docker compose down`.

```bash
sudo docker compose up -d --no-deps --pull never --force-recreate fail2ban
sudo docker compose logs --tail=100 fail2ban
```

## Verifiering

```bash
sudo docker compose exec -T fail2ban fail2ban-client status
sudo docker compose exec -T fail2ban fail2ban-client status sshd
sudo docker compose exec -T fail2ban fail2ban-client get sshd maxretry
sudo docker compose exec -T fail2ban fail2ban-client get sshd findtime
sudo docker compose exec -T fail2ban fail2ban-client get sshd bantime
sudo docker compose exec -T fail2ban fail2ban-client get sshd ignoreip
sudo docker compose exec -T fail2ban fail2ban-client get sshd actions
sudo docker compose exec -T fail2ban fail2ban-client get sshd action iptables-multiport actionban
sudo docker inspect --format '{{json .State.Health}}' "$(sudo docker compose ps -q fail2ban)"
```

Förväntat: en aktiv jail, `sshd`, med rätt loggfil, värdena `5`, `600`,
`3600` och din administrationsadress i `ignoreip`. Åtgärden ska använda
rätt SSH-port. Healthcheck ska bli `healthy` efter uppstart. Den verifierar
att jailen svarar, men bevisar inte att brandväggen faktiskt stoppar trafik.

Kontrollera filtermatchningen utan att orsaka misslyckade inloggningar:

```bash
sudo docker compose exec -T fail2ban fail2ban-regex /var/log/host/auth.log 'sshd[mode=normal]'
sudo docker compose exec -T fail2ban iptables -S INPUT
sudo docker compose exec -T fail2ban iptables -S f2b-sshd
```

Noll matchningar kan vara normalt om loggen saknar misslyckade inloggningar.
Brandväggskedjan kan saknas tills första blockeringen sker. Efter en faktisk
blockering ska `INPUT` referera till `f2b-sshd` för SSH-porten. För IPv6
kontrolleras även motsvarande `ip6tables`-regler. Gör inga avsiktliga
felinloggningar eller manuella blockeringar från administrationsadressen.
Öppna en andra vanlig SSH-session och verifiera lyckad inloggning innan
du stänger den första.

## Resurser och felsökning

Gränserna för endast Fail2ban har höjts från 96 till 192 MiB minne,
0,10 till 0,20 CPU och 100 till 200 processer/trådar. Swaputrymmet utöver
minnesgränsen är fortfarande noll. Detta ger marginal men garanterar inte
att värden har tillräckliga resurser. Healthcheck kör `status sshd` var
30:e sekund, med 10 sekunders timeout, tre försök och 60 sekunders startperiod.
Imagens standardkontroll kör enbart `ping` och upptäcker inte noll jails.

`procReady not received` kommer från containerruntimen och är inte bevis
för ett jail-fel. Kontrollera följande om problemet återkommer:

```bash
sudo docker inspect --format 'State={{json .State}} Memory={{.HostConfig.Memory}} MemorySwap={{.HostConfig.MemorySwap}} NanoCpus={{.HostConfig.NanoCpus}} PidsLimit={{.HostConfig.PidsLimit}}' "$(sudo docker compose ps -q fail2ban)"
sudo docker stats --no-stream "$(sudo docker compose ps -q fail2ban)"
sudo journalctl -u docker --since '30 minutes ago' --no-pager
sudo journalctl -k --since '30 minutes ago' --no-pager
```

Leta efter OOM, PID-gränser och runtimefel; mer minne i Compose hjälper
inte om själva värden saknar minne. Starta inte om Docker som felsökningssteg
eftersom det kan påverka andra tjänster.

## Stoppa skyddet vid problem

Från den kvarvarande SSH-sessionen eller leverantörens konsol:

```bash
sudo docker compose stop -t 30 fail2ban
```

Vid normal nedstängning tar Fail2ban bort sina regler. Om processen kraschat
kan regler ligga kvar: kontrollera `iptables -S INPUT` och eventuell
`ip6tables -S INPUT` via konsolen. Rensa aldrig hela brandväggen. En tidigare
image/konfiguration kan också återställa gamla blockeringar från databasen;
behåll därför åtkomstundantagen vid fortsatt felsökning och omstart.

## Källor

- [Imagens dokumentation](https://github.com/crazy-max/docker-fail2ban/blob/master/README.md)
- [Imagens startskript](https://github.com/crazy-max/docker-fail2ban/blob/master/rootfs/entrypoint.sh)
- [Imagens healthcheck](https://github.com/crazy-max/docker-fail2ban/blob/master/Dockerfile)
- [SSH-exemplet](https://github.com/crazy-max/docker-fail2ban/blob/master/examples/jails/sshd/jail.d/sshd.conf)

<!-- # Copyright (c) Liam Suorsa and Mika Suorsa -->
