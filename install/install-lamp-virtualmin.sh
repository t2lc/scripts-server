#!/bin/bash

# ========================================
# Nom        : install-lamp-virtualmin.sh
# Description: Installation d'un serveur LAMP + Virtualmin (VPS OVH),
#              avec génération automatique des mots de passe
# Cible      : Ubuntu 24.04
# Usage      : cp install-lamp-virtualmin.conf.example install-lamp-virtualmin.conf
#              nano install-lamp-virtualmin.conf      # renseigner toutes les valeurs
#              sudo ./install-lamp-virtualmin.sh [chemin/vers/fichier.conf]
# Prérequis  : accès root, terminal interactif (étapes d'édition manuelles)
#
# Toutes les valeurs propres au serveur (IP, port SSH, clés S3, clé publique…)
# sont lues dans le fichier de configuration. Par défaut : le fichier
# install-lamp-virtualmin.conf placé à côté du script.
# Le script refuse de démarrer si une valeur manque ou si une IP d'exemple
# (plages de documentation RFC 5737 / RFC 3849) est encore présente :
# sans cela, UFW fermerait le SSH à tout le monde sauf à ces IP fictives.
# ========================================

# Gestion des erreurs stricte
set -e  # Arrêter en cas d'erreur
set -u  # Erreur si variable non définie
set -o pipefail  # Détecter les erreurs dans les pipes

# Réglage du fuseau horaire sur Paris
sudo timedatectl set-timezone Europe/Paris

# ========================================
# Configuration du logging
# ========================================
LOGFILE="/var/log/vps-installation-$(date +%Y%m%d-%H%M%S).log"
exec 1> >(tee -a "$LOGFILE")
exec 2>&1

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

log "===== Début de l'installation LAMP + Virtualmin ====="

# ========================================
# Vérifications préalables
# ========================================
log "Vérification des prérequis..."

# Vérifier les privilèges root
if [ "$(id -u)" -ne 0 ]; then
    echo "ERREUR: Ce script doit être exécuté en tant que root" >&2
    exit 1
fi

# Vérifier la distribution
if [ -f /etc/lsb-release ]; then
    . /etc/lsb-release
    log "Distribution détectée: $DISTRIB_ID $DISTRIB_RELEASE"
else
    log "ATTENTION: Impossible de détecter la distribution"
fi

# ========================================
# Chargement de la configuration
# ========================================
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
CONF_FILE="${1:-$SCRIPT_DIR/install-lamp-virtualmin.conf}"

if [ ! -f "$CONF_FILE" ]; then
    echo "ERREUR: fichier de configuration introuvable : $CONF_FILE" >&2
    echo "Copiez install-lamp-virtualmin.conf.example en install-lamp-virtualmin.conf et renseignez-le." >&2
    exit 1
fi

# shellcheck source-path=SCRIPTDIR source=install-lamp-virtualmin.conf.example
. "$CONF_FILE"
log "Configuration chargée : $CONF_FILE"

# ========================================
# Vérification de la configuration
# ========================================
CONF_ERRORS=0

conf_error() {
    echo "ERREUR config: $*" >&2
    CONF_ERRORS=$((CONF_ERRORS + 1))
}

# Valeur obligatoire, non vide, sans CHANGE_ME
require_value() {
    local name="$1"
    local value="${!name:-}"
    if [ -z "$value" ]; then
        conf_error "$name est vide ou absent"
    elif [[ "$value" == *CHANGE_ME* ]]; then
        conf_error "$name contient encore CHANGE_ME"
    fi
}

# Refuse les plages réservées à la documentation (IP d'exemple)
is_example_ip() {
    case "$1" in
        192.0.2.*|198.51.100.*|203.0.113.*|2001:db8:*|2001:DB8:*) return 0 ;;
        *) return 1 ;;
    esac
}

require_ip() {
    local name="$1"
    require_value "$name"
    if is_example_ip "${!name:-}"; then
        conf_error "$name=${!name} est une IP d'exemple (plage de documentation)"
    fi
}

for v in varIp varIpv6 varGateway adminIpBackup adminIpMain; do
    require_ip "$v"
done

for v in pmaSymlink publicKeyPath publicKeyName sshKeyComment sshPort \
         rcloneObjectName rcloneBucket rcloneAccessKeyId rcloneSecretAccessKey \
         rcloneRegion rcloneLocationConstraint rcloneEndpoint backupManagerPublicKey; do
    require_value "$v"
done

if ! [[ "${sshPort:-}" =~ ^[0-9]+$ ]] || [ "${sshPort:-0}" -lt 1 ] || [ "${sshPort:-0}" -gt 65535 ]; then
    conf_error "sshPort=${sshPort:-} n'est pas un port valide"
fi

if [[ "${backupManagerPublicKey:-}" != ssh-* ]] || [[ "${backupManagerPublicKey:-}" == *"AAAA..."* ]]; then
    conf_error "backupManagerPublicKey n'est pas une clé publique SSH réelle"
fi

# bannedIps peut être vide, mais pas contenir d'IP d'exemple
declare -p bannedIps >/dev/null 2>&1 || bannedIps=()
for ip in "${bannedIps[@]}"; do
    if is_example_ip "$ip"; then
        conf_error "bannedIps contient une IP d'exemple : $ip"
    fi
done

if [ "$CONF_ERRORS" -gt 0 ]; then
    echo "ERREUR: $CONF_ERRORS problème(s) dans $CONF_FILE, installation annulée." >&2
    exit 1
fi
log "✓ Configuration vérifiée"

# ========================================
# Valeurs internes (non configurables)
# ========================================
rcloneFolderConfig="/home/rclone/.config"
rcloneFolder="/home/rclone/.config/rclone"
rcloneFile="$rcloneFolder/rclone.conf"
backupGRP="backupGRP"

# ========================================
# Génération automatique des mots de passe et username
# ========================================
log "Génération des mots de passe et username sécurisés..."

# Désactiver temporairement pipefail pour éviter les erreurs SIGPIPE avec head
set +o pipefail

# Webmin username: root-xxxxxxxx (8 caractères aléatoires)
webminUsername="root-$(tr -dc 'a-z0-9' < /dev/urandom | head -c 8)"

# Webmin: SANS caractères spéciaux (uniquement alphanumériques)
webminPassword=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 20)

# Réactiver pipefail
set -o pipefail

# Autres mots de passe: avec caractères spéciaux
rclonePassword=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
backupManagerPassword=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)

# ========================================
# Génération de la clé SSH (AVANT credentials)
# ========================================
log "Génération de la clé SSH..."

if [ -f "$publicKeyPath/$publicKeyName" ]; then
    log "Suppression de l'ancienne clé..."
    rm -f "$publicKeyPath/$publicKeyName"
    rm -f "$publicKeyPath/$publicKeyName.pub"
fi

ssh-keygen -t ed25519 -C "$sshKeyComment" -N "" -f "$publicKeyPath/$publicKeyName"
publicKey=$(cat "$publicKeyPath/$publicKeyName.pub")
privateKey=$(cat "$publicKeyPath/$publicKeyName")

if [ -n "$publicKey" ]; then
    echo "$publicKey" >> "$publicKeyPath/authorized_keys"
    log "✓ Clé SSH générée et ajoutée à authorized_keys"
else
    log "ATTENTION: Impossible de générer la clé SSH"
fi

# ========================================
# Sauvegarde des credentials
# ========================================
CREDENTIALS_FILE="/root/server-credentials-$(hostname)-$(date +%Y%m%d-%H%M%S).txt"

cat > "$CREDENTIALS_FILE" <<EOF
===========================================
CREDENTIALS DU SERVEUR
===========================================
Serveur: $(hostname)
Date de génération: $(date)
IP: $varIp

-------------------------------------------
CREDENTIALS GÉNÉRÉS
-------------------------------------------
Webmin Username:         $webminUsername
Webmin Password:         $webminPassword
Rclone user:             $rclonePassword
Backup Manager:          $backupManagerPassword

-------------------------------------------
ACCÈS AUX SERVICES
-------------------------------------------
Webmin/Virtualmin:       https://$varIp:10000
  Utilisateur: $webminUsername
  Mot de passe: $webminPassword

PhpMyAdmin:              http://$varIp/$pmaSymlink

-------------------------------------------
CLÉ SSH PRIVÉE (pour connexion au serveur)
-------------------------------------------
ATTENTION: Cette clé est SENSIBLE, gardez-la en sécurité!

Chemin de la clé sur le serveur: $publicKeyPath/$publicKeyName
Clé publique: $publicKeyPath/$publicKeyName.pub

Pour vous connecter au serveur avec cette clé:
1. Copiez le contenu de la clé privée ci-dessous dans un fichier local (ex: ~/.ssh/server-key)
2. Changez les permissions: chmod 600 ~/.ssh/server-key
3. Connectez-vous: ssh -i ~/.ssh/server-key -p $sshPort ubuntu@$varIp

CLÉ PRIVÉE:
$privateKey

CLÉ PUBLIQUE:
$publicKey

-------------------------------------------
DOCKER
-------------------------------------------
Docker sera installé pendant le processus
Pour utiliser Docker sans sudo après installation:
  - Déconnectez-vous et reconnectez-vous
  - ou utilisez: newgrp docker

-------------------------------------------
CONFIGURATION RCLONE
-------------------------------------------
Object Storage: $rcloneObjectName
Region: $rcloneRegion
Endpoint: $rcloneEndpoint

===========================================
IMPORTANT: Téléchargez ce fichier et
supprimez-le du serveur après installation!
===========================================
EOF

chmod 600 "$CREDENTIALS_FILE"

log "✓ Credentials générés et sauvegardés dans: $CREDENTIALS_FILE"
echo ""
echo "=========================================="
echo "MOTS DE PASSE GÉNÉRÉS - NOTEZ-LES !"
echo "=========================================="
cat "$CREDENTIALS_FILE"
echo ""
echo "Fichier sauvegardé: $CREDENTIALS_FILE"
echo "=========================================="
echo ""
echo "L'installation va démarrer dans 10 secondes..."
echo "Appuyez sur Ctrl+C pour annuler"
sleep 10

# ========================================
# Modification du port SSH
# ========================================
log "Configuration du port SSH..."

echo ""
echo "=========================================="
echo "CONFIGURATION MANUELLE REQUISE - PORT SSH"
echo "=========================================="
echo "Vous allez modifier le port SSH (Ubuntu 24.04 utilise systemd socket)."
echo ""
echo "Instructions:"
echo "1. Ajoutez ces lignes dans l'éditeur qui va s'ouvrir:"
echo ""
echo "[Socket]"
echo "ListenStream="
echo "ListenStream=0.0.0.0:$sshPort"
echo ""
echo "2. Sauvegardez et quittez (Ctrl+O, Entrée, Ctrl+X pour nano)"
echo ""
echo "Note: Changez $sshPort par le port que vous souhaitez utiliser"
echo ""
echo "Appuyez sur Entrée pour ouvrir l'éditeur systemctl..."
read -r </dev/tty

# Utiliser systemctl edit pour créer l'override
EDITOR=nano systemctl edit ssh.socket </dev/tty >/dev/tty 2>&1

# Recharger systemd et redémarrer le socket SSH
systemctl daemon-reload
systemctl restart ssh.socket

log "✓ Configuration SSH socket modifiée et redémarrée"

# ========================================
# Mise à jour du système
# ========================================
log "Mise à jour du système et ajout des repositories..."

apt-get install -y language-pack-en-base
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8
apt-get install -y software-properties-common
apt-add-repository -y ppa:ondrej/php
apt-add-repository -y ppa:ondrej/apache2
apt-get update
apt-get dist-upgrade -y

log "✓ Système mis à jour"

# ========================================
# Installation des extensions PHP (AVANT Virtualmin)
# ========================================
log "Installation des extensions PHP..."
apt-get install -y php-common php-mysql php-xml php-xmlrpc php-curl php-gd php-imagick php-cli php-dev php-mbstring php-soap php-zip php-intl php8.4-imap

# ========================================
# Installation de Git et ImageMagick (AVANT Virtualmin)
# ========================================
log "Installation de Git et ImageMagick..."
apt-get install -y git imagemagick

# ========================================
# Installation Webmin & Virtualmin
# ========================================
log "Installation de Webmin & Virtualmin..."

# Télécharger le script d'installation
cd /tmp
wget -O install.sh https://software.virtualmin.com/gpl/scripts/install.sh

# Lancer l'installation
/bin/sh ./install.sh

log "✓ Virtualmin installé"

# Créer un nouvel utilisateur Webmin avec le username généré
log "Création de l'utilisateur Webmin personnalisé..."

# ÉTAPE 1 : Changer le mot de passe de root (qui existe déjà)
/usr/share/webmin/changepass.pl /etc/webmin root "$webminPassword"
log "✓ Mot de passe root changé"

# ÉTAPE 2 : Renommer root vers le nouveau username dans miniserv.users
if [ -f /etc/webmin/miniserv.users ]; then
    sed -i "s/^root:/$webminUsername:/" /etc/webmin/miniserv.users
    log "✓ Utilisateur root renommé en $webminUsername dans miniserv.users"
fi

# ÉTAPE 3 : Configurer les permissions dans webmin.acl
if [ -f /etc/webmin/webmin.acl ]; then
    # Copier la ligne root et la renommer (au lieu de juste renommer)
    if grep -q "^root:" /etc/webmin/webmin.acl; then
        # Ajouter la nouvelle ligne avec le nouveau username
        grep "^root:" /etc/webmin/webmin.acl | sed "s/^root:/$webminUsername:/" >> /etc/webmin/webmin.acl
        log "✓ Permissions copiées pour $webminUsername dans webmin.acl"
    fi
    # Désactiver l'ancien utilisateur root (commenter ou renommer)
    sed -i "s/^root:/_root_disabled:/" /etc/webmin/webmin.acl
    log "✓ Utilisateur root désactivé dans webmin.acl"
fi

# ÉTAPE 4 : Vérifier les autres fichiers de configuration Webmin
# Certains modules peuvent avoir des restrictions spécifiques
for module_acl in /etc/webmin/*/module.acl; do
    if [ -f "$module_acl" ] && grep -q "^root:" "$module_acl" 2>/dev/null; then
        # Copier les permissions root pour le nouveau user
        grep "^root:" "$module_acl" | sed "s/^root:/$webminUsername:/" >> "$module_acl"
        # Désactiver root
        sed -i "s/^root:/_root_disabled:/" "$module_acl"
    fi
done
log "✓ Permissions des modules Webmin mises à jour"

# Vérifier que l'utilisateur a été créé
if grep -q "^$webminUsername:" /etc/webmin/miniserv.users; then
    log "✓ Utilisateur Webmin $webminUsername créé et configuré avec succès"
else
    log "ERREUR: L'utilisateur $webminUsername n'existe pas dans miniserv.users"
fi

# Redémarrer webmin
systemctl restart webmin

log "✓ Webmin redémarré"

# ========================================
# Installation des dépendances Python et autres
# ========================================
log "Installation des dépendances..."

# Python related
log "Installation de python-swiftclient..."
apt-get install -y python3-swiftclient

# Certbot related
log "Installation de certbot..."
apt-get install -y python3-certbot-apache

# Show system info on ssh connection
log "Installation de landscape-common..."
apt-get install -y landscape-common

log "✓ Dépendances installées"

# ========================================
# Installation PhpMyAdmin
# ========================================
log "Installation de PhpMyAdmin..."

apt-get install -y phpmyadmin

# Créer le symlink
if [ ! -e "/var/www/html/$pmaSymlink" ]; then
    ln -s /usr/share/phpmyadmin/ "/var/www/html/$pmaSymlink"
    log "✓ Symlink PhpMyAdmin créé: /var/www/html/$pmaSymlink"
else
    log "Symlink PhpMyAdmin déjà existant"
fi

# ========================================
# Installation Docker & Docker Compose
# ========================================
log "Installation de Docker..."

# Vérifier si Docker est déjà installé
if command -v docker > /dev/null 2>&1; then
    log "Docker déjà installé: $(docker --version)"
else
    log "Installation de Docker Engine..."

    # Mise à jour et installation des prérequis
    apt-get update
    apt-get install -y ca-certificates curl

    # Créer le répertoire pour les clés
    install -m 0755 -d /etc/apt/keyrings

    # Ajouter la clé GPG officielle de Docker
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc

    # Ajouter le repository Docker
    tee /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Signed-By: /etc/apt/keyrings/docker.asc
EOF

    # Installer Docker
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

    log "✓ Docker installé: $(docker --version)"
    log "✓ Docker Compose installé: $(docker compose version)"

    # Ajouter l'utilisateur ubuntu au groupe docker
    if id -u ubuntu > /dev/null 2>&1; then
        usermod -aG docker ubuntu
        log "✓ Utilisateur 'ubuntu' ajouté au groupe docker"
    fi

    log "✓ Installation Docker terminée"
fi

# ========================================
# Configuration Apache
# ========================================
log "Configuration Apache et activation des modules..."

# Liste des modules Apache à activer
APACHE_MODULES="core so watchdog http log_config logio version unixd \
access_compat actions alias auth_basic authn_core authn_file authz_core \
authz_groupfile authz_host authz_user autoindex cgi deflate dir env expires \
filter headers mime mpm_prefork negotiation php proxy proxy_ajp \
proxy_balancer proxy_connect proxy_express proxy_fcgi proxy_fdpass proxy_ftp \
proxy_html proxy_http proxy_scgi proxy_wstunnel reqtimeout rewrite session \
session_cookie setenvif slotmem_shm socache_shmcb ssl status suexec xml2enc"

# Activer les modules avec boucle
for module in $APACHE_MODULES; do
    if a2query -m "$module" > /dev/null 2>&1; then
        log "Module $module déjà activé"
    else
        if a2enmod "$module" 2>/dev/null; then
            log "✓ Module $module activé"
        else
            log "ATTENTION: Impossible d'activer le module $module"
        fi
    fi
done

# Créer le symlink Apache pour le site par défaut si nécessaire
if [ ! -e /etc/apache2/sites-enabled/000-default.conf ] && [ -f /etc/apache2/sites-available/000-default.conf ]; then
    ln -s /etc/apache2/sites-available/000-default.conf /etc/apache2/sites-enabled/000-default.conf
    log "✓ Symlink Apache 000-default.conf créé"
fi

# Redémarrer Apache
systemctl restart apache2.service
log "✓ Apache redémarré"

# ========================================
# Configuration Bind (DNS)
# ========================================
log "Configuration Bind/DNS pour utiliser le serveur local..."

# Ubuntu 24.04 utilise systemd-resolved au lieu de dhclient
# Configurer systemd-resolved pour utiliser 127.0.0.1 comme DNS

# Backup du fichier resolved.conf
if [ -f /etc/systemd/resolved.conf ]; then
    cp /etc/systemd/resolved.conf /etc/systemd/resolved.conf.backup-$(date +%Y%m%d)
    log "✓ Backup de resolved.conf créé"
fi

# Modifier resolved.conf pour utiliser 127.0.0.1 comme DNS
if ! grep -q "^DNS=127.0.0.1" /etc/systemd/resolved.conf; then
    sed -i 's/^#DNS=/DNS=127.0.0.1/' /etc/systemd/resolved.conf
    # Si la ligne n'existait pas du tout, l'ajouter
    if ! grep -q "^DNS=127.0.0.1" /etc/systemd/resolved.conf; then
        echo "DNS=127.0.0.1" >> /etc/systemd/resolved.conf
    fi
    log "✓ Configuration DNS locale ajoutée dans resolved.conf"
else
    log "Configuration DNS locale déjà présente dans resolved.conf"
fi

# Redémarrer systemd-resolved
systemctl restart systemd-resolved
log "✓ systemd-resolved redémarré"

# Redémarrer Bind9
if systemctl is-active --quiet bind9; then
    systemctl restart bind9
    log "✓ Bind9 redémarré"
else
    log "ATTENTION: Bind9 n'est pas actif"
fi

# ========================================
# Configuration réseau IPv6
# ========================================
log "Configuration réseau IPv6..."

# Sauvegarder le fichier original
if [ -f /etc/network/interfaces ]; then
    mv /etc/network/interfaces /etc/network/interfaces.old
    log "✓ Backup de /etc/network/interfaces créé"
fi

# Créer le nouveau fichier de configuration réseau
cat > /etc/network/interfaces <<EOF
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

# The loopback network interface
auto lo
iface lo inet loopback

auto ens3
iface ens3 inet dhcp
iface ens3 inet6 static
  address $varIpv6
  netmask 128
  post-up /sbin/ip -f inet6 route add $varGateway dev ens3
  post-up /sbin/ip -f inet6 route add default via $varGateway
  pre-down /sbin/ip -f inet6 route del default via $varGateway
  pre-down /sbin/ip -f inet6 route del $varGateway dev ens3

# Source interfaces
# Please check /etc/network/interfaces.d before changing this file
# as interfaces may have been defined in /etc/network/interfaces.d
# See LP: #1262951
source /etc/network/interfaces.d/*.cfg
EOF

log "✓ Configuration réseau IPv6 créée"

# Désactiver la configuration réseau cloud-init
echo "network: {config: disabled}" > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
log "✓ Cloud-init réseau désactivé"

# ========================================
# Ajout de la clé publique pour MBP
# ========================================
if [ -n "$publicKey" ]; then
    if ! grep -q "$publicKey" /home/ubuntu/.ssh/authorized_keys 2>/dev/null; then
        echo "$publicKey" >> /home/ubuntu/.ssh/authorized_keys
        log "✓ Clé SSH MBP ajoutée"
    else
        log "Clé SSH MBP déjà présente"
    fi
else
    log "ATTENTION: Pas de clé SSH MBP à ajouter"
fi

# ========================================
# Installation DAR
# ========================================
log "Installation de DAR..."
apt-get install -y dar
log "✓ DAR installé"

# ========================================
# Préparation du système de backup
# ========================================
log "Préparation du système de backup..."

# Créer le groupe backup s'il n'existe pas
if ! getent group "$backupGRP" > /dev/null 2>&1; then
    groupadd -g 2000 "$backupGRP"
    log "✓ Groupe $backupGRP créé"
else
    log "Groupe $backupGRP déjà existant"
fi

# ========================================
# Configuration Rclone
# ========================================
log "Configuration de Rclone..."

# Créer l'utilisateur rclone s'il n'existe pas
if ! id -u rclone > /dev/null 2>&1; then
    useradd -u 2001 -m -G "$backupGRP" rclone
    echo "rclone:$rclonePassword" | chpasswd
    log "✓ Utilisateur rclone créé"
else
    log "Utilisateur rclone déjà existant"
    echo "rclone:$rclonePassword" | chpasswd
    log "✓ Mot de passe rclone mis à jour"
fi

# Installer rclone
apt-get install -y rclone

# Créer les dossiers de configuration
mkdir -p "$rcloneFolderConfig"
mkdir -p "$rcloneFolder"
chown -R rclone:"$backupGRP" "$rcloneFolderConfig"

# Créer le fichier de configuration rclone
cat > "$rcloneFile" <<EOF
# Copy the config entry below in your rclone configuration file.
[$rcloneObjectName]
type = s3
provider = Other
env_auth = false
access_key_id = $rcloneAccessKeyId
secret_access_key = $rcloneSecretAccessKey
acl = private
region = $rcloneRegion
location_constraint = $rcloneLocationConstraint
# API endpoint
# S3 standard endpoint
endpoint = $rcloneEndpoint
EOF

chown rclone:"$backupGRP" "$rcloneFile"
chmod 600 "$rcloneFile"

log "✓ Rclone configuré"

# ========================================
# Configuration Backup Manager
# ========================================
log "Configuration de Backup Manager..."

# Créer l'utilisateur backup-manager s'il n'existe pas
if ! id -u backup-manager > /dev/null 2>&1; then
    useradd -u 2002 -M -G "$backupGRP" backup-manager
    echo "backup-manager:$backupManagerPassword" | chpasswd
    log "✓ Utilisateur backup-manager créé"
else
    log "Utilisateur backup-manager déjà existant"
    echo "backup-manager:$backupManagerPassword" | chpasswd
    log "✓ Mot de passe backup-manager mis à jour"
fi

# Créer la structure de répertoires
mkdir -p /home/backup-manager/.ssh
chown -R backup-manager:backup-manager /home/backup-manager
chmod 700 /home/backup-manager/.ssh

# Ajouter la clé publique pour backup-manager
echo "$backupManagerPublicKey" >> /home/backup-manager/.ssh/authorized_keys
chmod 600 /home/backup-manager/.ssh/authorized_keys
chown backup-manager:backup-manager /home/backup-manager/.ssh/authorized_keys
log "✓ Clé SSH ajoutée pour backup-manager"

# Créer le dossier de backup avec les bonnes permissions
mkdir -p /home/backup
chown -R backup-manager:"$backupGRP" /home/backup
chmod -R 770 /home/backup

log "✓ Structure backup-manager créée"

# Installer backup-manager
apt-get install -y backup-manager

log "✓ Backup-manager installé"

# Configuration de backup-manager
log "Configuration du fichier backup-manager.conf..."

echo ""
echo "=========================================="
echo "CONFIGURATION MANUELLE REQUISE"
echo "=========================================="
echo "Vous allez configurer backup-manager."
echo ""
echo "Paramètres à configurer:"
echo "  - BM_REPOSITORY_ROOT (ex: /home/backup)"
echo "  - BM_REPOSITORY_USER (backup-manager)"
echo "  - BM_REPOSITORY_GROUP (backupGRP)"
echo "  - BM_ARCHIVE_TTL (ex: 7)"
echo "  - BM_REPOSITORY_RECURSIVEPURGE (true)"
echo "  - BM_ARCHIVE_PURGEDUPS (false)"
echo "  - BM_ARCHIVE_METHOD (tarball mysql)"
echo "  - BM_TARBALL_FILETYPE (dar)"
echo "  - BM_TARBALL_DIRECTORIES (vos dossiers à sauvegarder)"
echo "  - BM_TARBALL_SLICESIZE (4500M)"
echo "  - BM_UPLOAD_METHOD (none)"
echo "  - BM_MYSQL_DATABASES (__ALL__)"
echo "  - BM_MYSQL_SAFEDUMPS (true)"
echo "  - BM_MYSQL_ADMINLOGIN (root)"
echo "  - BM_MYSQL_ADMINPASS (votre mot de passe MySQL root)"
echo "  - BM_BURNING_METHOD (none)"
echo ""
echo "Appuyez sur Entrée pour ouvrir vi..."
read -r </dev/tty

# Backup du fichier original
if [ -f /etc/backup-manager.conf ]; then
    cp /etc/backup-manager.conf /etc/backup-manager.conf.backup-$(date +%Y%m%d)
    log "✓ Backup de backup-manager.conf créé"
fi

# Ouvrir l'éditeur avec accès direct au terminal
vi /etc/backup-manager.conf </dev/tty >/dev/tty 2>&1

log "✓ Configuration backup-manager modifiée"

# ========================================
# Création des scripts de backup
# ========================================
log "Création des scripts de backup..."

dirScript="/usr/share/scripts-perso"
fileScript="backup-manager.sh"

mkdir -p "$dirScript"

# Créer le script de backup
# rcloneObjectName et rcloneBucket sont injectés à la génération ;
# les \$ sont évalués à l'exécution du backup.
cat > "$dirScript/$fileScript" <<EOF
#!/bin/sh
test -x /usr/sbin/backup-manager || exit 0
/usr/sbin/backup-manager

now=\$(date +"%Y-%m-%d")
rclone sync -v --progress /home/backup/ $rcloneObjectName:$rcloneBucket/\$now
suppressionDate=\$(date +%Y-%m-%d -d "7 days ago")
rclone purge $rcloneObjectName:$rcloneBucket/\$suppressionDate
EOF

chmod +x "$dirScript/$fileScript"
log "✓ Script de backup créé: $dirScript/$fileScript"

# Créer la tâche cron
cat > /etc/cron.d/backup-manager <<'EOF'
# Cron for backup
40 1 * * * root sh /usr/share/scripts-perso/backup-manager.sh > /dev/null 2>&1
EOF

log "✓ Tâche cron backup configurée (1h40 quotidien)"

# ========================================
# Configuration locale
# ========================================
log "Génération de la locale française..."
locale-gen fr_FR.UTF-8
log "✓ Locale fr_FR générée"

# ========================================
# Configuration du socket SSH (port personnalisé)
# ========================================
log "Configuration du socket SSH sur port personnalisé..."

# Note: La configuration du socket SSH nécessite systemd
# Décommenter et adapter si nécessaire:
# mkdir -p /etc/systemd/system/ssh.socket.d/
# cat > /etc/systemd/system/ssh.socket.d/listen.conf <<EOF
# [Socket]
# ListenStream=
# ListenStream=$sshPort
# EOF
# systemctl daemon-reload
# systemctl restart ssh.socket

log "ATTENTION: Configuration socket SSH à faire manuellement si nécessaire"

# ========================================
# Configuration du Firewall (UFW)
# ========================================
log "Configuration du firewall UFW..."

# Désactiver firewalld s'il est présent (conflit avec ufw)
if systemctl is-active --quiet firewalld; then
    systemctl stop firewalld
    systemctl disable firewalld
    log "✓ Firewalld arrêté et désactivé"
fi

# UFW est installé par défaut sur Ubuntu mais désactivé
# Installation si nécessaire
if ! command -v ufw > /dev/null 2>&1; then
    apt-get install -y ufw
fi

# Configuration de base UFW
log "Configuration des règles UFW..."

# Politique par défaut (n'ajoute aucune règle, n'influe pas sur la numérotation)
ufw --force default deny incoming
ufw --force default allow outgoing

# L'ordre des commandes ci-dessous = l'ordre d'évaluation dans `ufw status numbered`
# Les règles sans IP source génèrent automatiquement leur équivalent (v6)

# Accès admin : VPS de secours (IP fixe)
ufw allow from "$adminIpBackup" to any port 10000 proto tcp comment 'VPS secours'  # Webmin
ufw allow from "$adminIpBackup" to any port "$sshPort" proto tcp comment 'VPS secours'   # SSH

# Accès admin : IP fixe principale
ufw allow from "$adminIpMain" to any port "$sshPort" proto tcp    # SSH
ufw allow from "$adminIpMain" to any port 10000 proto tcp   # Webmin

# SSH fermé au reste du monde
ufw deny "$sshPort/tcp"

# Web public
ufw allow 80/tcp
ufw allow 443/tcp

# Webmin et Usermin fermés au reste du monde
ufw deny 10000/tcp
ufw deny 20000/tcp

# IP bannies
for bannedIp in "${bannedIps[@]}"; do
    ufw deny from "$bannedIp"
done

log "✓ Services non sécurisés bloqués"

# Activer UFW
echo "y" | ufw enable

log "✓ Firewall UFW activé et configuré"
log ""
log "Configuration UFW finale:"
ufw status verbose

# ========================================
# Nettoyage et finalisation
# ========================================
log "Nettoyage..."

# Nettoyer l'historique bash (pour supprimer les mots de passe)
history -c
history -w

log "===== Installation terminée ====="
echo ""
echo "=========================================="
echo "INSTALLATION TERMINÉE"
echo "=========================================="
echo ""
echo "Fichier de credentials: $CREDENTIALS_FILE"
echo ""
echo "IMPORTANT:"
echo "1. Téléchargez le fichier de credentials immédiatement"
echo "2. Redémarrez le serveur: reboot"
echo "3. Après redémarrage, accédez à Webmin:"
echo "   https://$varIp:10000"
echo "   Utilisateur: $webminUsername"
echo "   Mot de passe: (voir fichier credentials)"
echo ""
echo "4. PhpMyAdmin accessible à:"
echo "   http://$varIp/$pmaSymlink"
echo ""
echo "5. Docker - Commandes utiles:"
echo "   Vérifier l'installation: docker --version"
echo "   Tester Docker: docker run hello-world"
echo "   Utiliser Docker Compose: docker compose up -d"
echo "   Note: Reconnectez-vous pour utiliser Docker sans sudo"
echo ""
echo "6. Supprimez ce script et le fichier credentials:"
echo "   rm -f /tmp/install-lamp-virtualmin.sh"
echo "   shred -u $CREDENTIALS_FILE"
echo ""
echo "=========================================="
echo ""

log "Log complet disponible dans: $LOGFILE"
