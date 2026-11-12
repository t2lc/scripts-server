#!/bin/bash

# ========================================
# Nom        : install-semaphore.sh
# Description: Installation de Semaphore UI + Ansible
# Cible      : LXC Ubuntu 26.04
# Usage      : cp install-semaphore.conf.example install-semaphore.conf
#              nano install-semaphore.conf            # renseigner les valeurs
#              sudo ./install-semaphore.sh [chemin/vers/fichier.conf]
# Prérequis  : accès root, accès Internet (API GitHub)
#
# - Semaphore installé depuis le .deb officiel (version au choix)
# - Service lancé par un utilisateur dédié "semaphore" (pas root)
# - Base SQLite, config dans /etc/semaphore, données dans /var/lib/semaphore
# - Ansible depuis les dépôts Ubuntu (ansible-core 2.20 sur 26.04)
# Le script est rejouable : il ne régénère jamais les secrets existants.
# ========================================

set -euo pipefail

# ========================================
# Configuration
# ========================================

# Valeurs propres à l'installation : lues dans install-semaphore.conf
# (à côté du script, ou chemin passé en argument).
# Modèle : install-semaphore.conf.example
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
CONF_FILE="${1:-$SCRIPT_DIR/install-semaphore.conf}"

if [ ! -f "$CONF_FILE" ]; then
    echo "ERREUR : fichier de configuration introuvable : $CONF_FILE" >&2
    echo "Copiez install-semaphore.conf.example en install-semaphore.conf et renseignez-le." >&2
    exit 1
fi

# shellcheck source-path=SCRIPTDIR source=install-semaphore.conf.example
. "$CONF_FILE"

for v in SEMAPHORE_VERSION ADMIN_LOGIN ADMIN_NAME ADMIN_EMAIL TIMEZONE; do
    if [ -z "${!v:-}" ] || [[ "${!v}" == *CHANGE_ME* ]]; then
        echo "ERREUR : $v est vide ou contient encore CHANGE_ME dans $CONF_FILE" >&2
        exit 1
    fi
done
if [[ "$ADMIN_EMAIL" == *@example.com ]]; then
    echo "ERREUR : ADMIN_EMAIL est encore l'adresse d'exemple ($ADMIN_EMAIL)" >&2
    exit 1
fi

# Valeurs internes
SEM_USER="semaphore"
SEM_HOME="/var/lib/semaphore"
SEM_CONF_DIR="/etc/semaphore"
SEM_CONF="$SEM_CONF_DIR/config.json"
SEM_DB="$SEM_HOME/database.sqlite"
SEM_TMP="$SEM_HOME/tmp"

# Collections installées au niveau système (utiles pour tester en CLI).
# Les playbooks déclarent aussi les leurs dans collections/requirements.yml.
COLLECTIONS=(community.general community.proxmox ansible.posix community.crypto)
COLLECTIONS_PATH="/usr/share/ansible/collections"

# ========================================
# Logging
# ========================================
LOGFILE="/var/log/semaphore-installation-$(date +%Y%m%d-%H%M%S).log"
exec 1> >(tee -a "$LOGFILE")
exec 2>&1

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

fail() {
    log "ERREUR : $*"
    exit 1
}

log "===== Début de l'installation Semaphore UI ====="

# ========================================
# Vérifications préalables
# ========================================
[ "$(id -u)" -eq 0 ] || fail "ce script doit être exécuté en root"

. /etc/os-release
log "Distribution détectée : $PRETTY_NAME"
[ "$ID" = "ubuntu" ] || fail "distribution non Ubuntu ($ID)"
[ "$VERSION_ID" = "26.04" ] || log "ATTENTION : script prévu pour 26.04, détecté $VERSION_ID"

case "$(dpkg --print-architecture)" in
    amd64) ARCH="amd64" ;;
    arm64) ARCH="arm64" ;;
    *) fail "architecture non prise en charge : $(dpkg --print-architecture)" ;;
esac

# ========================================
# Système
# ========================================
log "Mise à jour du système..."
timedatectl set-timezone "$TIMEZONE" 2>/dev/null || ln -sf "/usr/share/zoneinfo/$TIMEZONE" /etc/localtime

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get dist-upgrade -y
apt-get install -y \
    curl ca-certificates jq git openssl sqlite3 \
    ansible-core python3-paramiko python3-proxmoxer python3-requests \
    sshpass
log "✓ Dépendances installées"
log "Ansible : $(ansible --version | head -n1)"

# ========================================
# Collections Ansible (niveau système)
# ========================================
log "Installation des collections Ansible..."
mkdir -p "$COLLECTIONS_PATH"
ansible-galaxy collection install --upgrade -p "$COLLECTIONS_PATH" "${COLLECTIONS[@]}"
log "✓ Collections installées dans $COLLECTIONS_PATH"

# ========================================
# Téléchargement de Semaphore
# ========================================
if [ "$SEMAPHORE_VERSION" = "latest" ]; then
    API_URL="https://api.github.com/repos/semaphoreui/semaphore/releases/latest"
else
    API_URL="https://api.github.com/repos/semaphoreui/semaphore/releases/tags/v${SEMAPHORE_VERSION}"
fi

log "Récupération des informations de release ($SEMAPHORE_VERSION)..."
RELEASE_JSON="$(curl -fsSL "$API_URL")" || fail "impossible de joindre l'API GitHub"

TAG="$(jq -r '.tag_name' <<<"$RELEASE_JSON")"
DEB_URL="$(jq -r --arg a "linux_${ARCH}.deb" \
    '.assets[] | select(.name | endswith($a)) | .browser_download_url' <<<"$RELEASE_JSON" | head -n1)"
SUM_URL="$(jq -r \
    '.assets[] | select(.name | endswith("checksums.txt")) | .browser_download_url' <<<"$RELEASE_JSON" | head -n1)"

[ -n "$DEB_URL" ] && [ "$DEB_URL" != "null" ] || fail "paquet .deb introuvable pour $TAG ($ARCH)"

DEB_NAME="$(basename "$DEB_URL")"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

INSTALLED_VERSION="$(dpkg-query -W -f='${Version}' semaphore 2>/dev/null || true)"
if [ -n "$INSTALLED_VERSION" ] && [ "v${INSTALLED_VERSION}" = "$TAG" ]; then
    log "Semaphore $TAG déjà installé, pas de réinstallation"
else
    log "Téléchargement de $DEB_NAME..."
    curl -fsSL -o "$WORKDIR/$DEB_NAME" "$DEB_URL"

    if [ -n "$SUM_URL" ] && [ "$SUM_URL" != "null" ]; then
        curl -fsSL -o "$WORKDIR/checksums.txt" "$SUM_URL"
        (cd "$WORKDIR" && grep " ${DEB_NAME}\$" checksums.txt | sha256sum -c -) \
            || fail "somme de contrôle invalide pour $DEB_NAME"
        log "✓ Somme de contrôle SHA-256 vérifiée"
    else
        log "ATTENTION : pas de fichier checksums dans la release, vérification impossible"
    fi

    # Arrêt du service pendant la mise à jour éventuelle
    systemctl stop semaphore 2>/dev/null || true
    apt-get install -y "$WORKDIR/$DEB_NAME"
    log "✓ Semaphore $TAG installé"
fi

# ========================================
# Utilisateur et répertoires
# ========================================
if ! id -u "$SEM_USER" >/dev/null 2>&1; then
    useradd --system --home-dir "$SEM_HOME" --create-home --shell /usr/sbin/nologin "$SEM_USER"
    log "✓ Utilisateur système $SEM_USER créé"
else
    log "Utilisateur $SEM_USER déjà existant"
fi

mkdir -p "$SEM_TMP" "$SEM_HOME/.ssh" "$SEM_CONF_DIR"
chown -R "$SEM_USER:$SEM_USER" "$SEM_HOME"
chmod 750 "$SEM_HOME"
chmod 700 "$SEM_HOME/.ssh"

# ========================================
# Configuration (secrets générés UNE SEULE FOIS)
# ========================================
NEW_INSTALL=0

if [ -f "$SEM_CONF" ]; then
    log "Configuration existante conservée : $SEM_CONF (secrets inchangés)"
else
    NEW_INSTALL=1
    log "Génération de la configuration et des secrets..."
    SEM_HASH="$(openssl rand -base64 32)"
    SEM_ENCRYPTION="$(openssl rand -base64 32)"
    SEM_KEY="$(openssl rand -base64 32)"

    cat > "$SEM_CONF" <<EOF
{
  "sqlite": {
    "host": "$SEM_DB"
  },
  "dialect": "sqlite",
  "tmp_path": "$SEM_TMP",
  "cookie_hash": "$SEM_HASH",
  "cookie_encryption": "$SEM_ENCRYPTION",
  "access_key_encryption": "$SEM_KEY"
}
EOF
    log "✓ Configuration créée : $SEM_CONF"
fi

chown root:"$SEM_USER" "$SEM_CONF_DIR" "$SEM_CONF"
chmod 750 "$SEM_CONF_DIR"
chmod 640 "$SEM_CONF"

# ========================================
# Compte administrateur
# ========================================
CREDENTIALS_FILE=""

admin_exists() {
    [ -f "$SEM_DB" ] && \
        sqlite3 "$SEM_DB" "SELECT 1 FROM user WHERE login='$ADMIN_LOGIN' LIMIT 1;" 2>/dev/null | grep -q 1
}

if admin_exists; then
    log "Compte $ADMIN_LOGIN déjà existant, mot de passe inchangé"
else
    ADMIN_PASSWORD="$(openssl rand -base64 32 | tr -d '=+/' | cut -c1-24)"

    runuser -u "$SEM_USER" -- semaphore user add --admin \
        --login "$ADMIN_LOGIN" \
        --name "$ADMIN_NAME" \
        --email "$ADMIN_EMAIL" \
        --password "$ADMIN_PASSWORD" \
        --config "$SEM_CONF"
    log "✓ Compte administrateur $ADMIN_LOGIN créé"

    CREDENTIALS_FILE="/root/semaphore-credentials-$(hostname)-$(date +%Y%m%d-%H%M%S).txt"
    cat > "$CREDENTIALS_FILE" <<EOF
===========================================
SEMAPHORE UI - $(hostname)
===========================================
Date : $(date)
URL  : http://$(hostname -I | awk '{print $1}'):3000

Login        : $ADMIN_LOGIN
Mot de passe : $ADMIN_PASSWORD

Configuration (contient access_key_encryption) :
  $SEM_CONF
À sauvegarder dans le gestionnaire de mots de passe :
sans cette clé, les secrets stockés dans Semaphore
sont illisibles, même après restauration de la base.

Supprimer ce fichier après sauvegarde :
  shred -u $CREDENTIALS_FILE
===========================================
EOF
    chmod 600 "$CREDENTIALS_FILE"
fi

# ========================================
# Service systemd
# ========================================
log "Création du service systemd..."

cat > /etc/systemd/system/semaphore.service <<EOF
[Unit]
Description=Semaphore UI
Documentation=https://docs.semaphoreui.com/
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=$SEM_USER
Group=$SEM_USER
WorkingDirectory=$SEM_HOME
Environment=HOME=$SEM_HOME
Environment=ANSIBLE_COLLECTIONS_PATH=$SEM_HOME/.ansible/collections:$COLLECTIONS_PATH
ExecStart=/usr/bin/semaphore server --config $SEM_CONF
Restart=always
RestartSec=10s

# Durcissement
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable semaphore
systemctl restart semaphore
log "✓ Service semaphore activé et démarré"

# ========================================
# Vérification
# ========================================
log "Vérification du démarrage..."
for i in $(seq 1 15); do
    if curl -fsS http://127.0.0.1:3000/api/ping >/dev/null 2>&1; then
        log "✓ Semaphore répond sur le port 3000"
        break
    fi
    sleep 2
    if [ "$i" -eq 15 ]; then
        log "ATTENTION : Semaphore ne répond pas, voir : journalctl -u semaphore -n 50"
    fi
done

# ========================================
# Fin
# ========================================
log "===== Installation terminée ====="
echo ""
echo "=========================================="
echo "Semaphore $TAG"
echo "Ansible   : $(ansible --version | head -n1)"
echo "URL       : http://$(hostname -I | awk '{print $1}'):3000"
echo "Config    : $SEM_CONF"
echo "Base      : $SEM_DB"
echo "Logs      : journalctl -u semaphore -f"
if [ -n "$CREDENTIALS_FILE" ]; then
    echo ""
    echo "Identifiants : $CREDENTIALS_FILE"
    echo "  -> sauvegarder le mot de passe ET $SEM_CONF,"
    echo "     puis : shred -u $CREDENTIALS_FILE"
fi
if [ "$NEW_INSTALL" -eq 0 ]; then
    echo ""
    echo "Configuration existante conservée (aucun secret régénéré)."
fi
echo "=========================================="
echo ""
log "Log complet : $LOGFILE"
