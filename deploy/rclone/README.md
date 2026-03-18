<!-- # Copyright (c) Liam Suorsa and Mika Suorsa -->
# Rclone-konfiguration

`backup_cloud_sync` genererar nu sin `rclone.conf` automatiskt inne i containern från `.env`.

Du behöver därför normalt inte lägga någon separat konfigurationsfil i den här katalogen.

Lägg i stället OAuth-token och eventuella klientuppgifter i `.env` med variablerna `RCLONE_ONEDRIVE_*` eller `RCLONE_DROPBOX_*`, och välj aktiv remote via `RCLONE_REMOTE`.

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
