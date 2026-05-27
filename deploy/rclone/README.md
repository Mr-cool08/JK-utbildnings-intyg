<!-- # Copyright (c) Liam Suorsa and Mika Suorsa -->
# Rclone och molnbackup

`backup_cloud_sync` genererar sin `rclone.conf` automatiskt inne i containern från `.env`.

Du behöver därför normalt inte lägga någon separat konfigurationsfil i den här katalogen.

## Aktuell användning

1. Fyll i lämpliga `RCLONE_*`-variabler i `.env`.
2. Välj remote med `RCLONE_REMOTE`.
3. Starta den valfria tjänsten:

```bash
docker compose --profile backup-cloud up -d backup_cloud_sync
```

## Vanliga variabler

- `RCLONE_REMOTE`
- `RCLONE_BACKUP_PATH`
- `RCLONE_SYNC_INTERVAL_SECONDS`
- `RCLONE_PRUNE_REMOTE`
- `RCLONE_ONEDRIVE_*`
- `RCLONE_DROPBOX_*`

Det här används tillsammans med `postgres_backup`, som fortsätter skapa lokala `.sql.gz`-filer i backupvolymen.

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
