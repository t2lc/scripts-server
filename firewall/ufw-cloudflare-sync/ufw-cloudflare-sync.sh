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


# A faire pour le faire fonctionner
#sudo chmod 750 /usr/local/sbin/ufw-cloudflare-sync.sh
#sudo bash -n /usr/local/sbin/ufw-cloudflare-sync.sh
#sudo /usr/local/sbin/ufw-cloudflare-sync.sh
