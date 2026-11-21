# scripts-server

Scripts d'installation et d'administration de serveurs **Ubuntu**, utilisés sur un homelab Proxmox et des VPS.

> Toutes les adresses IP, noms d'hôte, e-mails et identifiants de ce dépôt sont des exemples (plages de documentation RFC 5737 / RFC 3849, `example.com`). Aucun script ne contient de valeur propre à un serveur : elles sont lues dans un fichier de configuration séparé.

## Utilisation

Chaque script configurable est accompagné d'un modèle `<script>.conf.example` :

```bash
cp install/install-semaphore.conf.example install/install-semaphore.conf
nano install/install-semaphore.conf
sudo ./install/install-semaphore.sh
```

Le script lit `<script>.conf` à côté de lui (ou le chemin passé en premier argument) et **refuse de démarrer** si une valeur obligatoire manque, contient `CHANGE_ME` ou est encore une IP d'exemple. Les fichiers `*.conf` remplis sont exclus par le `.gitignore` : ne les versionnez jamais.

## Organisation

Les scripts sont rangés par **domaine fonctionnel**, et non par machine :

| Dossier | Rôle |
|---|---|
| `install/` | Installation complète d'un serveur ou d'un service |
| `firewall/` | Règles de pare-feu (UFW), mise à jour d'IP dynamiques |
| `backup/` | Sauvegardes (backup-manager, rclone, object storage) |
| `network/` | Réseau, VPN (WireGuard), routage |
| `audit/` | Contrôles de sécurité en lecture seule et rapports |

Un dossier n'est créé que lorsqu'il contient au moins un script. Un script qui a des fichiers compagnons (unités systemd, exemple de configuration, README) a son propre sous-dossier, par exemple `firewall/ufw-ddns/`.

Conventions :
- noms de fichiers en kebab-case (`install-semaphore.sh`) ;
- en-tête en commentaire : nom, description, cible, usage, prérequis ;
- valeurs à personnaliser dans un fichier `<script>.conf.example` à côté du script, chargé au démarrage et vérifié.

## Index des scripts

| Script | Description | Cible |
|---|---|---|
| [`install/install-lamp-virtualmin.sh`](install/install-lamp-virtualmin.sh) | Serveur LAMP + Virtualmin, Docker, backups (backup-manager + rclone vers OVH Object Storage), UFW | VPS Ubuntu 24.04 |
| [`install/install-semaphore.sh`](install/install-semaphore.sh) | Semaphore UI + Ansible, service systemd dédié, base SQLite, script rejouable | LXC Ubuntu 26.04 |
| [`firewall/ufw-cloudflare-sync/`](firewall/ufw-cloudflare-sync/) | Restreint 80/443 aux plages IP officielles Cloudflare (IPv4 et IPv6) dans UFW, sans toucher aux autres ports ; procédure complète et timer systemd quotidien dans le README du dossier | Ubuntu + UFW |
| [`audit/audit-securite.sh`](audit/audit-securite.sh) | Audit de sécurité en lecture seule (ports et pare-feu, SSH, comptes et sudo, permissions, services, sysctl, Apache/PHP/MySQL, Docker) avec rapport Markdown et plan d'action. Configuration facultative (`audit-securite.conf.example`). Code de sortie 0/1/2 selon la gravité | Ubuntu 24.04 / 26.04 |

## Licence

[MIT](LICENSE)
