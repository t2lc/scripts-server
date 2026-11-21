# Restreindre UFW aux adresses Cloudflare (IPv4 et IPv6)

**Serveur :** Ubuntu (testé sur un VPS OVH)  
**Objectif :** n'autoriser les connexions entrantes sur **80/tcp et 443/tcp** que depuis les plages officielles de Cloudflare, en IPv4 et IPv6, sans modifier les règles d'administration sur les autres ports.  
**Validation réalisée :** 21 novembre 2026 — **15 plages IPv4**, **7 plages IPv6**, **44 autorisations** (22 plages × 2 ports). Ces nombres peuvent évoluer.

## 1. État initial et prérequis

Vérifier :

```bash
sudo ufw status verbose
grep '^IPV6=' /etc/default/ufw
```

Préconditions :

- UFW doit être **actif**.
- La politique entrante doit être **`deny (incoming)`**.
- `/etc/default/ufw` doit contenir **`IPV6=yes`**.
- Tous les noms de domaine devant rester accessibles sur 80/443 doivent passer par le proxy Cloudflare (DNS en mode **Proxied**, nuage orange). Les services accessibles directement à l'IP d'origine sur ces ports ne fonctionneront plus pour les IP externes non autorisées.
- Conserver une session SSH et, idéalement, un accès console de secours pendant les opérations.

**Autres ports existants :** la procédure ne modifie pas les règles des autres ports (par exemple SSH, Webmin 10000/tcp et Usermin 20000/tcp).

**Sources officielles des plages Cloudflare :**

- IPv4 : https://www.cloudflare.com/ips-v4
- IPv6 : https://www.cloudflare.com/ips-v6

## 2. Script de synchronisation

Créer ou éditer **`/usr/local/sbin/ufw-cloudflare-sync.sh`** et y placer le contenu suivant (identique à [`ufw-cloudflare-sync.sh`](ufw-cloudflare-sync.sh)). **Le shebang doit être à la toute première ligne du fichier, sans ligne vide avant.**

```bash
#!/usr/bin/env bash
# Nom        : ufw-cloudflare-sync.sh
# Description: Restreint 80/tcp et 443/tcp aux plages IP officielles
#              Cloudflare (IPv4 et IPv6) dans UFW, sans toucher aux autres ports
# Cible      : Ubuntu, UFW actif avec IPV6=yes et politique entrante deny
# Usage      : sudo /usr/local/sbin/ufw-cloudflare-sync.sh
#              (procédure complète et timer systemd : README.md)
# Prérequis  : root, ufw, python3, sites proxifiés par Cloudflare
set -euo pipefail

# Synchronisation UFW avec les plages officielles Cloudflare
# Ports concernés : 80/tcp et 443/tcp
# IPv4 et IPv6
# Autres ports : inchangés

if [[ $EUID -ne 0 ]]; then
    echo "ERREUR : exécuter en root"
    exit 1
fi

if ! grep -q '^IPV6=yes' /etc/default/ufw; then
    echo "ERREUR : IPv6 non activé dans UFW"
    exit 1
fi

if ! ufw status verbose | grep -q 'Status: active'; then
    echo "ERREUR : UFW inactif"
    exit 1
fi

if ! ufw status verbose | grep -q 'Default: deny (incoming)'; then
    echo "ERREUR : politique entrante différente de deny"
    exit 1
fi

python3 - <<'PY'
import ipaddress
import re
import shutil
import subprocess
import sys
import urllib.request
from collections import Counter
from datetime import datetime
from pathlib import Path

PORTS = (80, 443)
CF_URL_V4 = "https://www.cloudflare.com/ips-v4"
CF_URL_V6 = "https://www.cloudflare.com/ips-v6"


def run(*args):
    return subprocess.run(
        args,
        check=True,
        text=True,
        capture_output=True
    ).stdout


def fetch(url, version):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "ufw-cloudflare-sync/1.0"}
    )

    with urllib.request.urlopen(request, timeout=20) as response:
        content = response.read().decode("utf-8")

    networks = set()

    # splitlines() gère également une dernière ligne sans \n.
    for line in content.splitlines():
        line = line.strip()

        if not line:
            continue

        net = ipaddress.ip_network(line, strict=True)

        if net.version != version:
            raise ValueError(f"IPv{version} invalide : {line}")

        networks.add(str(net))

    minimum = 10 if version == 4 else 5

    if len(networks) < minimum:
        raise ValueError(
            f"Liste IPv{version} suspecte : {len(networks)} plages"
        )

    return networks


def rules():
    output = run("ufw", "status")
    result = []

    for line in output.splitlines():
        match = re.match(
            r"^\s*(80|443)/tcp\s+ALLOW(?: IN)?\s+(\S+)(.*)$",
            line
        )

        if not match:
            continue

        port = int(match.group(1))
        source = match.group(2)
        suffix = match.group(3)

        if source.startswith("Anywhere"):
            network = "public"
        else:
            network = str(
                ipaddress.ip_network(source, strict=False)
            )

        result.append({
            "port": port,
            "network": network,
            "managed": (
                "Cloudflare HTTP" in suffix
                or "Cloudflare HTTPS" in suffix
            ),
        })

    return result


def allow(network, port):
    comment = (
        "Cloudflare HTTP"
        if port == 80
        else "Cloudflare HTTPS"
    )

    run(
        "ufw", "allow",
        "from", network,
        "to", "any",
        "port", str(port),
        "proto", "tcp",
        "comment", comment
    )


def delete(network, port):
    run(
        "ufw", "--force", "delete", "allow",
        "from", network,
        "to", "any",
        "port", str(port),
        "proto", "tcp"
    )


try:
    print("Téléchargement des plages Cloudflare...")

    ipv4 = fetch(CF_URL_V4, 4)
    ipv6 = fetch(CF_URL_V6, 6)
    desired = ipv4 | ipv6

    print(f"IPv4 : {len(ipv4)} plages")
    print(f"IPv6 : {len(ipv6)} plages")

    expected = {
        (network, port)
        for network in desired
        for port in PORTS
    }

    current = rules()

    existing = {
        (r["network"], r["port"])
        for r in current
    }

    # Refuser les règles inconnues afin de ne pas
    # supprimer des autorisations non gérées.
    unknown = [
        r for r in current
        if r["network"] != "public"
        and not r["managed"]
        and (r["network"], r["port"]) not in expected
    ]

    if unknown:
        raise RuntimeError(
            f"Règles 80/443 inconnues : {unknown}. "
            "Aucune modification effectuée."
        )

    # Préparer les modifications avant toute écriture.
    missing = expected - existing
    obsolete = {
        (r["network"], r["port"])
        for r in current
        if r["managed"]
        and r["network"] != "public"
        and (r["network"], r["port"]) not in expected
    }
    public = [
        r for r in current if r["network"] == "public"
    ]

    # Sauvegarder seulement si des règles doivent changer.
    if missing or obsolete or public:
        backup = (
            Path("/root") /
            (
                "ufw-backup-"
                + datetime.now().strftime("%Y%m%d-%H%M%S-%f")
            )
        )
        shutil.copytree("/etc/ufw", backup)
        print(f"Sauvegarde avant modification : {backup}")
    else:
        print("Aucune modification nécessaire : pas de sauvegarde")

    # 1. Ajouter les règles manquantes

    for network, port in sorted(missing):
        print(f"AJOUT : {network} -> {port}")
        allow(network, port)

    # 2. Vérifier les ajouts avant suppression
    after_add = {
        (r["network"], r["port"])
        for r in rules()
    }

    if not expected.issubset(after_add):
        raise RuntimeError(
            "Certaines règles Cloudflare n'ont pas été ajoutées. "
            "Arrêt sans suppression."
        )

    # 3. Supprimer les anciennes plages gérées
    for network, port in sorted(obsolete):
        print(f"SUPPRESSION OBSOLÈTE : {network} -> {port}")
        delete(network, port)

    # 4. Supprimer les accès publics 80/443
    for port in PORTS:
        while any(
            r["port"] == port
            and r["network"] == "public"
            for r in rules()
        ):
            print(f"SUPPRESSION ACCÈS PUBLIC : {port}/tcp")

            run(
                "ufw", "--force", "delete",
                "allow", f"{port}/tcp"
            )

    # 5. Validation finale
    final = rules()

    actual = Counter(
        (r["network"], r["port"])
        for r in final
    )

    missing_final = expected - set(actual)
    extra_final = set(actual) - expected

    duplicates = {
        key: count
        for key, count in actual.items()
        if count != 1
    }

    if missing_final or extra_final or duplicates:
        raise RuntimeError(
            "ÉCHEC VALIDATION FINALE\n"
            f"Manquantes : {missing_final}\n"
            f"Superflues : {extra_final}\n"
            f"Doublons : {duplicates}"
        )

    print()
    print("================================")
    print("SYNCHRONISATION RÉUSSIE")
    print("================================")
    print(f"Plages IPv4 : {len(ipv4)}")
    print(f"Plages IPv6 : {len(ipv6)}")
    print(f"Règles validées : {len(expected)}")
    print("Accès publics 80/443 : aucun")
    print("Autres ports UFW : non modifiés")

except Exception as exc:
    print(f"\nERREUR : {exc}", file=sys.stderr)
    sys.exit(1)
PY
```

> **Version améliorée :** la version initiale a été exécutée avec succès sur le VPS. Cette variante ne crée une **sauvegarde que si une règle doit être ajoutée ou supprimée**. Elle effectue toujours la validation finale, y compris en l’absence de changement. Elle ne réalise pas de rollback automatique. Les anciens répertoires de sauvegarde ne sont pas supprimés automatiquement.

### Installer, vérifier et exécuter

```bash
sudo chmod 750 /usr/local/sbin/ufw-cloudflare-sync.sh
sudo bash -n /usr/local/sbin/ufw-cloudflare-sync.sh
sudo /usr/local/sbin/ufw-cloudflare-sync.sh
sudo ufw status
```

En cas de message `set: Illegal option -o pipefail`, vérifier que **la première ligne du fichier** est bien `#!/usr/bin/env bash` (aucune ligne vide avant) :

```bash
head -n 3 /usr/local/sbin/ufw-cloudflare-sync.sh
```

## 3. Automatisation avec systemd

### Service `/etc/systemd/system/ufw-cloudflare-sync.service`

```ini
[Unit]
Description=Synchronisation UFW avec les IP Cloudflare
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/ufw-cloudflare-sync.sh
User=root
```

### Timer `/etc/systemd/system/ufw-cloudflare-sync.timer`

```ini
[Unit]
Description=Synchronisation quotidienne des IP Cloudflare

[Timer]
OnCalendar=*-*-* 03:00:00
Persistent=true
RandomizedDelaySec=5min
Unit=ufw-cloudflare-sync.service

[Install]
WantedBy=timers.target
```

Le timer déclenche une synchronisation chaque jour **vers 03:00, avec jusqu'à 5 minutes de délai aléatoire**. `Persistent=true` rattrape une exécution manquée lorsque le serveur était arrêté.

### Activer le timer

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ufw-cloudflare-sync.timer
systemctl list-timers --all ufw-cloudflare-sync.timer
```

### Tester le service immédiatement

```bash
sudo systemctl start ufw-cloudflare-sync.service
sudo systemctl status ufw-cloudflare-sync.service
sudo journalctl -u ufw-cloudflare-sync.service -n 50 --no-pager
```

Le statut **`inactive (dead)`** est normal une fois l'exécution terminée pour ce service `Type=oneshot`, dès lors que le résultat est **`status=0/SUCCESS`**.

### Rechercher les erreurs

```bash
sudo journalctl -u ufw-cloudflare-sync.service -p err --since '7 days ago'
```

## 4. Résultat observé le 21 novembre 2026

Le lancement manuel puis le test du service systemd ont affiché :

```text
Téléchargement des plages Cloudflare...
IPv4 : 15 plages
IPv6 : 7 plages

================================
SYNCHRONISATION RÉUSSIE
================================
Plages IPv4 : 15
Plages IPv6 : 7
Règles validées : 44
Accès publics 80/443 : aucun
Autres ports UFW : non modifiés
```

Exécution systemd observée le **21/11/2026**, avec **`status=0/SUCCESS`**. Exemple de sauvegarde créée : `/root/ufw-backup-AAAAMMJJ-HHMMSS-ffffff`.

## 5. Contrôles de sécurité après déploiement

1. Vérifier que les domaines proxifiés sont toujours accessibles en HTTP/HTTPS via Cloudflare.
2. Depuis une connexion extérieure ne provenant pas de Cloudflare, tester la connexion directe aux **IP publiques IPv4 et IPv6 de l'origine** sur les ports 80 et 443. Elle doit être refusée ou expirer. Éviter d'exposer publiquement les IP de l'origine dans un compte-rendu.
3. Vérifier le fonctionnement des renouvellements de certificats TLS (notamment challenge ACME HTTP-01 s'il est utilisé).
4. Vérifier que les accès d'administration (SSH, Webmin…) restent utilisables depuis leurs IP autorisées.
5. Contrôler les règles affichées :

   ```bash
   sudo ufw status numbered
   ```

**Limites :**

- Le script vérifie les autorisations affichées par UFW, **pas** la totalité du chemin réseau ni les règles d'autres pare-feu.
- Il cible les règles UFW `ALLOW` explicites sur `80/tcp` et `443/tcp`. Des règles non standard, des règles `before.rules`, des règles par interface ou des autorisations couvrant plusieurs ports peuvent nécessiter un audit manuel.
- Les plages Cloudflare sont partagées entre clients : les autoriser ne prouve pas qu'une requête vient de **votre** zone Cloudflare. Pour une authentification de l'accès à l'origine, envisager **Authenticated Origin Pulls** avec vérification du certificat côté serveur.
- Si une étape échoue après des changements, le script s'arrête, mais **n'annule pas automatiquement** les modifications déjà appliquées.
- Les sauvegardes `/root/ufw-backup-*` ne sont créées qu’en cas de changement. Prévoir si besoin une politique de rétention séparée.

## 6. Maintenance et diagnostic

Consulter l'horaire du prochain lancement :

```bash
systemctl list-timers --all ufw-cloudflare-sync.timer
```

Exécuter une synchronisation manuelle :

```bash
sudo systemctl start ufw-cloudflare-sync.service
```

Consulter les journaux :

```bash
sudo journalctl -u ufw-cloudflare-sync.service --since today --no-pager
```

Désactiver l'exécution automatique sans modifier les règles déjà appliquées :

```bash
sudo systemctl disable --now ufw-cloudflare-sync.timer
```

**Important :** désactiver le timer ne rouvre pas les ports 80/443 au public ; les règles UFW existantes restent en place.
