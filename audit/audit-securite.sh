#!/bin/bash

# ========================================
# Nom        : audit-securite.sh
# Description: Audit de sécurité d'un serveur Ubuntu, en lecture seule :
#              ports exposés, pare-feu, SSH, utilisateurs et sudo,
#              permissions, services, durcissement noyau, Apache/PHP/MySQL,
#              Docker, journalisation. Génère un rapport Markdown détaillé
#              avec un plan d'action priorisé.
# Cible      : Ubuntu 24.04 / 26.04 (serveur, VM ou LXC)
# Usage      : sudo ./audit-securite.sh [-o dossier] [-c fichier.conf] [-q]
#                -o  dossier du rapport (défaut : /var/log/audit-securite)
#                -c  fichier de configuration (défaut : audit-securite.conf
#                    à côté du script, s'il existe ; sinon valeurs par défaut)
#                -q  mode silencieux (n'affiche que le chemin du rapport)
# Prérequis  : root ; paquets iproute2 (ss) et openssh-server pour les
#              contrôles réseau et SSH
#
# Le script NE MODIFIE RIEN : il lit la configuration et propose les
# corrections. Le rapport contient des informations sensibles (comptes,
# ports, chemins) : il est créé en 600 dans un dossier en 700.
#
# Code de sortie : 0 = rien d'important, 1 = au moins un point MOYEN,
#                  2 = au moins un point ÉLEVÉ ou CRITIQUE, 3 = erreur
# (utilisable depuis cron, Ansible ou Semaphore)
# ========================================

set -uo pipefail
export LC_ALL=C.UTF-8

SCRIPT_VERSION="1.0"

# ========================================
# Valeurs par défaut (surchargées par le fichier de configuration)
# ========================================
# Ports qui peuvent être ouverts à tout Internet
ALLOWED_PUBLIC_PORTS="80 443"
# Ports d'administration : doivent être restreints à des IP précises
# (le ou les ports SSH détectés sont ajoutés automatiquement)
ADMIN_PORTS="10000 20000 8006 9090"
# Nombre de jours sans connexion au-delà duquel un compte est signalé
MAX_INACTIVE_DAYS=90
# Racines web à inspecter (motifs glob acceptés)
WEB_ROOTS="/var/www /srv/www /home/*/public_html"
# Durée maximale (secondes) de chaque recherche dans le système de fichiers
FIND_TIMEOUT=300

OUTPUT_DIR="/var/log/audit-securite"
CONF_FILE=""
QUIET=0

usage() {
    sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'
    exit 3
}

while getopts "o:c:qh" opt; do
    case "$opt" in
        o) OUTPUT_DIR="$OPTARG" ;;
        c) CONF_FILE="$OPTARG" ;;
        q) QUIET=1 ;;
        *) usage ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "ERREUR : ce script doit être exécuté en root (sudo)." >&2
    exit 3
fi

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
if [ -z "$CONF_FILE" ] && [ -f "$SCRIPT_DIR/audit-securite.conf" ]; then
    CONF_FILE="$SCRIPT_DIR/audit-securite.conf"
fi
if [ -n "$CONF_FILE" ]; then
    if [ ! -f "$CONF_FILE" ]; then
        echo "ERREUR : fichier de configuration introuvable : $CONF_FILE" >&2
        exit 3
    fi
    # shellcheck source-path=SCRIPTDIR source=audit-securite.conf.example
    . "$CONF_FILE"
fi

HOST="$(hostname -s 2>/dev/null || hostname)"
START_TS="$(date +%s)"
STAMP="$(date +%Y%m%d-%H%M%S)"

mkdir -p "$OUTPUT_DIR" || { echo "ERREUR : impossible de créer $OUTPUT_DIR" >&2; exit 3; }
chmod 700 "$OUTPUT_DIR"
REPORT="$OUTPUT_DIR/audit-$HOST-$STAMP.md"
: > "$REPORT" || { echo "ERREUR : impossible d'écrire $REPORT" >&2; exit 3; }
chmod 600 "$REPORT"

# ========================================
# Outils
# ========================================
has() { command -v "$1" >/dev/null 2>&1; }

say() { [ "$QUIET" -eq 1 ] || echo "$*"; }

# Recherche bornée dans le temps et en nombre de résultats
bounded() {
    local max="$1"; shift
    timeout "$FIND_TIMEOUT" "$@" 2>/dev/null | head -n "$max"
}

# Liste à puces Markdown à partir de lignes (avec limite d'affichage)
bullets() {
    local max="${2:-30}" n=0 total
    total=$(printf '%s\n' "$1" | grep -c . || true)
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        n=$((n + 1))
        [ "$n" -gt "$max" ] && break
        printf -- '- `%s`\n' "$line"
    done <<< "$1"
    if [ "$total" -gt "$max" ]; then
        printf -- '- … et %s autre(s)\n' "$((total - max))"
    fi
}

# ========================================
# Collecte des constats
# ========================================
SEVERITIES=("CRITIQUE" "ÉLEVÉ" "MOYEN" "FAIBLE" "INFO")
CATEGORIES=("Système et mises à jour" "Réseau et pare-feu" "SSH" "Utilisateurs et sudo" \
            "Fichiers et permissions" "Services" "Noyau (sysctl)" \
            "Web (Apache, PHP, MySQL)" "Docker" "Journalisation")

F_SEV=(); F_CAT=(); F_TITLE=(); F_DETAIL=(); F_ACTION=(); F_CMD=()
OK_CAT=(); OK_TXT=()
declare -A INVENTORY=()

# finding SÉVÉRITÉ CATÉGORIE TITRE CONSTAT ACTION [COMMANDES]
finding() {
    F_SEV+=("$1"); F_CAT+=("$2"); F_TITLE+=("$3")
    F_DETAIL+=("$4"); F_ACTION+=("$5"); F_CMD+=("${6:-}")
}

# ok CATÉGORIE TEXTE : contrôle conforme
ok() { OK_CAT+=("$1"); OK_TXT+=("$2"); }

# inventory CATÉGORIE TEXTE_MARKDOWN
inventory() { INVENTORY["$1"]+="$2"$'\n'; }

# ========================================
# 1. Système et mises à jour
# ========================================
check_system() {
    local cat="Système et mises à jour"
    say "→ $cat"

    . /etc/os-release
    OS_NAME="$PRETTY_NAME"
    KERNEL="$(uname -r)"
    VIRT="$(systemd-detect-virt 2>/dev/null || echo inconnu)"
    UPTIME="$(uptime -p 2>/dev/null || true)"

    if [ "${ID:-}" != "ubuntu" ]; then
        finding "INFO" "$cat" "Distribution non Ubuntu ($ID)" \
            "Ce script est écrit pour Ubuntu ; certains contrôles peuvent être imprécis." \
            "Vérifier manuellement les points signalés."
    fi

    if [ -f /var/run/reboot-required ]; then
        local pkgs=""
        [ -f /var/run/reboot-required.pkgs ] && pkgs="$(sort -u /var/run/reboot-required.pkgs | tr '\n' ' ')"
        finding "MOYEN" "$cat" "Redémarrage requis" \
            "Des mises à jour (noyau, bibliothèques) ne sont pas actives tant que la machine n'a pas redémarré. Paquets concernés : ${pkgs:-non précisés}." \
            "Planifier un redémarrage." \
            "sudo reboot"
    else
        ok "$cat" "Aucun redémarrage en attente"
    fi

    # Fraîcheur des listes de paquets
    local stamp=/var/lib/apt/periodic/update-success-stamp age_days=""
    [ -f "$stamp" ] || stamp=/var/lib/apt/lists
    if [ -e "$stamp" ]; then
        age_days=$(( ( $(date +%s) - $(stat -c %Y "$stamp") ) / 86400 ))
        if [ "$age_days" -gt 7 ]; then
            finding "FAIBLE" "$cat" "Listes de paquets anciennes ($age_days jours)" \
                "Le décompte des mises à jour ci-dessous peut être incomplet : les listes APT n'ont pas été rafraîchies depuis $age_days jours." \
                "Rafraîchir les listes puis relancer l'audit." \
                "sudo apt-get update"
        fi
    fi

    # Mises à jour en attente (simulation, sans rien installer)
    if has apt-get; then
        local sim total sec
        sim="$(apt-get -s -o Debug::NoLocking=1 dist-upgrade 2>/dev/null | grep '^Inst ' || true)"
        total=$(printf '%s\n' "$sim" | grep -c '^Inst ' || true)
        sec=$(printf '%s\n' "$sim" | grep -ci 'security' || true)
        inventory "$cat" "- Mises à jour en attente : **$total** (dont **$sec** de sécurité)"
        if [ "$sec" -gt 0 ]; then
            local sec_pkgs
            sec_pkgs="$(printf '%s\n' "$sim" | grep -i security | awk '{print $2}' | sort -u)"
            finding "ÉLEVÉ" "$cat" "$sec mise(s) à jour de sécurité en attente" \
                "$(printf 'Paquets concernés :\n%s' "$(bullets "$sec_pkgs" 20)")" \
                "Installer les mises à jour de sécurité." \
                "sudo apt-get update && sudo apt-get dist-upgrade"
        elif [ "$total" -gt 0 ]; then
            finding "FAIBLE" "$cat" "$total mise(s) à jour en attente (hors sécurité)" \
                "Des mises à jour non liées à la sécurité sont disponibles." \
                "Les installer lors de la prochaine maintenance." \
                "sudo apt-get update && sudo apt-get dist-upgrade"
        else
            ok "$cat" "Aucune mise à jour en attente"
        fi
    fi

    # Mises à jour automatiques de sécurité
    if dpkg -s unattended-upgrades >/dev/null 2>&1 \
        && grep -qsE '^\s*APT::Periodic::Unattended-Upgrade\s+"1"' /etc/apt/apt.conf.d/*; then
        ok "$cat" "Mises à jour de sécurité automatiques actives (unattended-upgrades)"
    else
        finding "MOYEN" "$cat" "Mises à jour de sécurité automatiques désactivées" \
            "unattended-upgrades n'est pas installé ou n'est pas activé dans /etc/apt/apt.conf.d/20auto-upgrades : les correctifs de sécurité dépendent d'une action manuelle." \
            "Installer et activer unattended-upgrades." \
            "sudo apt-get install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades"
    fi

    # Synchronisation de l'heure (indispensable pour les journaux et TLS)
    if [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" = "yes" ]; then
        ok "$cat" "Horloge synchronisée (NTP)"
    elif [ "$VIRT" = "lxc" ]; then
        ok "$cat" "Conteneur LXC : l'horloge est celle de l'hôte"
    else
        finding "FAIBLE" "$cat" "Horloge non synchronisée" \
            "timedatectl n'indique pas de synchronisation NTP : les horodatages des journaux et la validation TLS peuvent être faussés." \
            "Activer la synchronisation NTP." \
            "sudo timedatectl set-ntp true
timedatectl status"
    fi

    # AppArmor
    if has aa-enabled && aa-enabled -q 2>/dev/null; then
        ok "$cat" "AppArmor actif"
    elif [ "$VIRT" = "lxc" ]; then
        inventory "$cat" "- AppArmor : non vérifiable depuis un conteneur LXC (géré par l'hôte)"
    else
        finding "MOYEN" "$cat" "AppArmor inactif" \
            "AppArmor confine les services (Apache, MySQL, snap…). Il est actif par défaut sur Ubuntu et semble désactivé ici." \
            "Réactiver AppArmor (vérifier aussi les paramètres noyau dans /etc/default/grub)." \
            "sudo systemctl enable --now apparmor
sudo aa-status"
    fi
}

# ========================================
# 2. Réseau et pare-feu
# ========================================
FW_TYPE="aucun"
FW_DEFAULT_DENY=0
UFW_STATUS=""
SSH_PORTS=""

is_loopback() {
    case "$1" in
        127.*|::1|\[::1\]) return 0 ;;
        *) return 1 ;;
    esac
}

detect_firewall() {
    if has ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then
        FW_TYPE="ufw"
        UFW_STATUS="$(ufw status 2>/dev/null)"
        ufw status verbose 2>/dev/null | grep -q 'deny (incoming)\|reject (incoming)' && FW_DEFAULT_DENY=1
    elif has nft && nft list ruleset 2>/dev/null | grep -qE 'hook input.*policy drop'; then
        FW_TYPE="nftables"
        FW_DEFAULT_DENY=1
    elif has iptables && iptables -S INPUT 2>/dev/null | grep -qE '^-P INPUT (DROP|REJECT)'; then
        FW_TYPE="iptables"
        FW_DEFAULT_DENY=1
    elif has nft && [ "$(nft list ruleset 2>/dev/null | grep -c 'hook input')" -gt 0 ]; then
        FW_TYPE="nftables (politique accept)"
    fi
}

# Exposition d'un port selon UFW : open | restricted | blocked | unknown
port_exposure() {
    local port="$1" proto="$2"
    case "$FW_TYPE" in
        aucun|"nftables (politique accept)") echo "open"; return ;;
        nftables|iptables) echo "unknown"; return ;;
    esac
    [ "$FW_DEFAULT_DENY" -eq 1 ] || { echo "open"; return; }

    local status="blocked" to action from
    while read -r to action from; do
        case "$to" in
            "$port"|"$port/$proto") ;;
            *) continue ;;
        esac
        [[ "$action" == ALLOW* || "$action" == DENY* || "$action" == REJECT* || "$action" == LIMIT* ]] || continue
        if [[ "$from" == Anywhere* ]]; then
            if [[ "$action" == ALLOW* || "$action" == LIMIT* ]]; then status="open"; fi
            break
        elif [[ "$action" == ALLOW* || "$action" == LIMIT* ]]; then
            status="restricted"
        fi
    done < <(printf '%s\n' "$UFW_STATUS" | sed -n '/^--/,$p' | tail -n +2 \
             | sed -E 's/ \(v6\)//g; s/ (IN|OUT)( |$)/_\1\2/; s/\s+#.*$//' \
             | awk '{to=$1; act=$2; $1=""; $2=""; sub(/^ +/,""); print to, act, $0}')
    echo "$status"
}

declare -A DANGEROUS_PORTS=(
    [21]="FTP (identifiants en clair)" [23]="Telnet (en clair)" [69]="TFTP"
    [111]="rpcbind" [135]="RPC Microsoft" [137]="NetBIOS" [138]="NetBIOS" [139]="NetBIOS/Samba"
    [161]="SNMP" [445]="SMB" [512]="rexec" [513]="rlogin" [514]="rsh/syslog" [873]="rsync daemon"
    [2049]="NFS" [2375]="API Docker sans TLS (prise de contrôle root)" [2376]="API Docker"
    [3306]="MySQL/MariaDB" [5432]="PostgreSQL" [5900]="VNC" [5984]="CouchDB"
    [6379]="Redis" [9200]="Elasticsearch" [9300]="Elasticsearch (cluster)"
    [11211]="Memcached" [27017]="MongoDB"
)

check_network() {
    local cat="Réseau et pare-feu"
    say "→ $cat"

    detect_firewall
    inventory "$cat" "- Pare-feu détecté : **$FW_TYPE**$([ "$FW_DEFAULT_DENY" -eq 1 ] && echo ' (politique entrante : refus par défaut)')"

    case "$FW_TYPE" in
        aucun)
            finding "ÉLEVÉ" "$cat" "Aucun pare-feu actif" \
                "Ni UFW, ni nftables, ni iptables ne filtrent le trafic entrant : chaque service qui écoute sur une interface publique est joignable depuis Internet." \
                "Activer UFW avec une politique de refus par défaut, en autorisant d'abord le SSH depuis vos IP d'administration (sinon vous perdez l'accès)." \
                "sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from <IP_ADMIN> to any port <PORT_SSH> proto tcp
sudo ufw allow 80/tcp && sudo ufw allow 443/tcp
sudo ufw enable && sudo ufw status numbered" ;;
        "nftables (politique accept)")
            finding "MOYEN" "$cat" "Pare-feu nftables sans politique de refus" \
                "Des règles nftables existent mais la chaîne input accepte par défaut : tout ce qui n'est pas explicitement refusé passe." \
                "Passer la chaîne input en « policy drop » dans /etc/nftables.conf, après avoir autorisé le SSH. Tester avec un filet de sécurité (vidage automatique des règles au bout de 2 minutes)." \
                "sudo nft -c -f /etc/nftables.conf
(sleep 120 && sudo nft flush ruleset) &
sudo nft -f /etc/nftables.conf" ;;
        ufw)
            if [ "$FW_DEFAULT_DENY" -eq 1 ]; then
                ok "$cat" "UFW actif avec refus par défaut des connexions entrantes"
            else
                finding "ÉLEVÉ" "$cat" "UFW actif mais politique entrante permissive" \
                    "UFW est actif mais accepte par défaut les connexions entrantes : il ne protège que ce qui est explicitement refusé." \
                    "Passer la politique entrante en refus, après avoir vérifié les règles ALLOW nécessaires (SSH en premier)." \
                    "sudo ufw status numbered
sudo ufw default deny incoming"
            fi ;;
        *) ok "$cat" "Pare-feu $FW_TYPE actif avec refus par défaut" ;;
    esac

    # Ports SSH (socket systemd sur Ubuntu 24.04+, sinon sshd -T)
    if systemctl is-active --quiet ssh.socket 2>/dev/null; then
        SSH_PORTS="$(systemctl show ssh.socket -p Listen --value 2>/dev/null | grep -oE ':[0-9]+ ' | tr -d ': ' | sort -u | tr '\n' ' ')"
    fi
    if [ -z "$SSH_PORTS" ] && [ -x /usr/sbin/sshd ]; then
        SSH_PORTS="$(/usr/sbin/sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | sort -u | tr '\n' ' ')"
    fi
    local admin_ports="$ADMIN_PORTS $SSH_PORTS"

    if ! has ss; then
        finding "INFO" "$cat" "Commande ss absente : ports non analysés" \
            "Le paquet iproute2 n'est pas installé, l'inventaire des ports en écoute n'a pas pu être fait." \
            "Installer iproute2 puis relancer l'audit." \
            "sudo apt-get install iproute2"
        return
    fi

    local table="| Proto | Adresse | Port | Processus | Exposition |"$'\n'"|---|---|---|---|---|"
    local seen="" public_count=0
    local netid local_addr proc addr port pname key expo expo_txt

    while read -r netid _ _ _ local_addr _ proc; do
        port="${local_addr##*:}"
        addr="${local_addr%:*}"
        addr="${addr%%%*}"
        pname="$(sed -nE 's/.*\(\("([^"]+)".*/\1/p' <<< "${proc:-}")"
        pname="${pname:-?}"
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        key="$netid:$port:$(is_loopback "$addr" && echo lo || echo pub)"
        [[ " $seen " == *" $key "* ]] && continue
        seen="$seen $key"

        if is_loopback "$addr"; then
            table+=$'\n'"| $netid | \`$addr\` | $port | $pname | locale uniquement |"
            continue
        fi
        # Résolveur local systemd-resolved
        [[ "$addr" == 127.0.0.53 || "$addr" == 127.0.0.54 ]] && continue

        public_count=$((public_count + 1))
        expo="$(port_exposure "$port" "$netid")"
        case "$expo" in
            open) expo_txt="**ouvert à Internet**" ;;
            restricted) expo_txt="restreint à certaines IP" ;;
            blocked) expo_txt="bloqué par le pare-feu" ;;
            *) expo_txt="filtré par $FW_TYPE (non vérifié)" ;;
        esac
        table+=$'\n'"| $netid | \`$addr\` | $port | $pname | $expo_txt |"

        local label="${DANGEROUS_PORTS[$port]:-}"
        if [ "$port" = "2375" ]; then
            finding "CRITIQUE" "$cat" "API Docker non chiffrée exposée ($netid/$port)" \
                "Le démon Docker écoute en TCP sans TLS sur \`$addr:$port\`. Quiconque peut joindre ce port obtient l'équivalent d'un accès root sur la machine." \
                "Retirer l'écoute TCP (option -H tcp://… dans /etc/docker/daemon.json ou dans l'override systemd de docker.service) et utiliser le socket local ou SSH (docker -H ssh://…)." \
                "sudo grep -Rn 'tcp://' /etc/docker/daemon.json /etc/systemd/system/docker.service.d/ 2>/dev/null
sudo systemctl daemon-reload && sudo systemctl restart docker"
        elif [ -n "$label" ]; then
            case "$expo" in
                open)
                    finding "ÉLEVÉ" "$cat" "$label joignable depuis Internet ($netid/$port)" \
                        "Le service \`$pname\` écoute sur \`$addr:$port\` et le pare-feu ne le bloque pas. Ce type de service ne doit jamais être exposé publiquement." \
                        "Le faire écouter sur 127.0.0.1 (ou le désactiver s'il est inutile) et bloquer le port au pare-feu. Si un accès distant est nécessaire, passer par un tunnel SSH ou WireGuard." \
                        "sudo ufw deny $port/$netid
sudo ss -tulpn | grep ':$port '" ;;
                restricted|blocked|unknown)
                    finding "FAIBLE" "$cat" "$label écoute sur une interface publique ($netid/$port)" \
                        "Le service \`$pname\` écoute sur \`$addr:$port\`. Le pare-feu le protège ($expo_txt), mais une erreur de règle suffirait à l'exposer." \
                        "Le faire écouter sur 127.0.0.1 si aucun accès distant n'est nécessaire (défense en profondeur)." ;;
            esac
        elif [[ " $admin_ports " == *" $port "* ]]; then
            case "$expo" in
                open)
                    finding "ÉLEVÉ" "$cat" "Port d'administration ouvert à tout Internet ($netid/$port, $pname)" \
                        "Le port \`$port\` (\`$pname\`) est accessible depuis n'importe quelle IP. Les ports d'administration (SSH, Webmin, Proxmox…) doivent être restreints à vos IP fixes ou à un tunnel." \
                        "Autoriser uniquement vos IP d'administration en tête de liste, puis refuser le reste. Ajouter d'abord la règle ALLOW pour ne pas perdre l'accès." \
                        "sudo ufw prepend allow proto $netid from <IP_ADMIN> to any port $port
sudo ufw status numbered      # repérer puis supprimer la règle ALLOW Anywhere
sudo ufw delete <NUMERO>
sudo ufw deny $port/$netid" ;;
                *) ok "$cat" "Port d'administration $port ($pname) non ouvert à tout Internet ($expo_txt)" ;;
            esac
        elif [[ " $ALLOWED_PUBLIC_PORTS " == *" $port "* ]]; then
            ok "$cat" "Port public autorisé $netid/$port ($pname)"
        elif [ "$expo" = "open" ]; then
            finding "MOYEN" "$cat" "Port non prévu ouvert à Internet ($netid/$port, $pname)" \
                "Le service \`$pname\` écoute sur \`$addr:$port\` et ce port n'est ni dans ALLOWED_PUBLIC_PORTS ni bloqué par le pare-feu." \
                "Vérifier que ce service doit être public. Sinon : le faire écouter sur 127.0.0.1, le désactiver, ou bloquer le port. S'il est légitime, l'ajouter à ALLOWED_PUBLIC_PORTS dans audit-securite.conf." \
                "sudo ss -tulpn | grep ':$port '
sudo ufw deny $port/$netid"
        fi
    done < <(ss -H -tulpn 2>/dev/null | awk '$2=="LISTEN" || $1=="udp"')

    inventory "$cat" "$(printf '\n**Ports en écoute** (%s sur une interface non locale) :\n\n%s' "$public_count" "$table")"
    [ -n "$SSH_PORTS" ] && inventory "$cat" $'\n'"- Port(s) SSH détecté(s) : \`${SSH_PORTS% }\`"

    # Docker publie ses ports en contournant UFW
    if [ "$FW_TYPE" = "ufw" ] && has docker && docker ps -q 2>/dev/null | grep -q .; then
        local published
        published="$(docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null | grep -E '0\.0\.0\.0:|:::' || true)"
        if [ -n "$published" ]; then
            finding "ÉLEVÉ" "$cat" "Ports Docker publiés en contournant UFW" \
                "$(printf 'Docker insère ses propres règles iptables : un port publié avec -p 8080:80 est joignable depuis Internet même si UFW le refuse.\n\n%s' "$(bullets "$published")")" \
                "Publier les ports sur 127.0.0.1 (-p 127.0.0.1:8080:80) derrière un reverse proxy, ou filtrer dans la chaîne DOCKER-USER." \
                "docker ps --format '{{.Names}} {{.Ports}}'
sudo iptables -L DOCKER-USER -n -v"
        fi
    fi

    # Routage IP
    if [ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" = "1" ]; then
        if has docker || has wg || has lxc-ls || [ -d /etc/pve ]; then
            inventory "$cat" "- Routage IPv4 activé (attendu : Docker, WireGuard, LXC ou Proxmox présent)"
        else
            finding "FAIBLE" "$cat" "Routage IPv4 activé sans raison apparente" \
                "net.ipv4.ip_forward=1 alors qu'aucun Docker, WireGuard, LXC ni Proxmox n'a été détecté : la machine peut relayer du trafic entre interfaces." \
                "Désactiver le routage s'il n'est pas utilisé." \
                "echo 'net.ipv4.ip_forward = 0' | sudo tee /etc/sysctl.d/60-no-forward.conf
sudo sysctl --system"
        fi
    fi
}

# ========================================
# 3. SSH
# ========================================
check_ssh() {
    local cat="SSH"
    say "→ $cat"

    if [ ! -x /usr/sbin/sshd ]; then
        ok "$cat" "Serveur SSH non installé"
        return
    fi

    local cfg
    cfg="$(/usr/sbin/sshd -T 2>/dev/null)"
    if [ -z "$cfg" ]; then
        finding "MOYEN" "$cat" "Configuration SSH illisible" \
            "\`sshd -T\` a échoué : la configuration contient peut-être une erreur, ce qui empêcherait sshd de redémarrer." \
            "Tester la configuration et corriger l'erreur affichée." \
            "sudo sshd -t"
        return
    fi
    sshv() { awk -v k="$1" '$1==k{ $1=""; sub(/^ /,""); print; exit }' <<< "$cfg"; }

    local hardening="/etc/ssh/sshd_config.d/00-hardening.conf"
    local note="Les fichiers de /etc/ssh/sshd_config.d/ sont lus par ordre alphabétique et la première valeur lue l'emporte : le préfixe 00- garantit que votre réglage passe avant un éventuel 50-cloud-init.conf."
    local reload="sudo sshd -t && sudo systemctl reload ssh"

    case "$(sshv permitrootlogin)" in
        yes)
            finding "ÉLEVÉ" "$cat" "Connexion root autorisée (PermitRootLogin yes)" \
                "Le compte root peut se connecter directement en SSH, y compris par mot de passe si celui-ci est autorisé." \
                "Interdire la connexion root (passer par un utilisateur sudo). $note" \
                "echo 'PermitRootLogin no' | sudo tee -a $hardening
$reload" ;;
        prohibit-password|without-password)
            finding "FAIBLE" "$cat" "Connexion root par clé autorisée" \
                "root peut se connecter avec une clé SSH. C'est moins risqué qu'un mot de passe, mais une clé volée donne directement root, sans trace de l'utilisateur." \
                "Si un utilisateur sudo existe, interdire root complètement." \
                "echo 'PermitRootLogin no' | sudo tee -a $hardening
$reload" ;;
        *) ok "$cat" "Connexion root interdite" ;;
    esac

    if [ "$(sshv passwordauthentication)" = "yes" ]; then
        finding "ÉLEVÉ" "$cat" "Authentification par mot de passe autorisée" \
            "sshd accepte les mots de passe : la machine est exposée aux attaques par force brute. Vérifiez d'abord que votre clé fonctionne dans une autre session." \
            "Désactiver les mots de passe. $note" \
            "printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\n' | sudo tee -a $hardening
$reload
sudo sshd -T | grep -E 'passwordauthentication|kbdinteractive'"
    else
        ok "$cat" "Authentification par mot de passe désactivée"
        if [ "$(sshv kbdinteractiveauthentication)" = "yes" ] && [ "$(sshv usepam)" = "yes" ]; then
            finding "MOYEN" "$cat" "Authentification « keyboard-interactive » active" \
                "Avec UsePAM yes, KbdInteractiveAuthentication yes permet encore de saisir un mot de passe Unix, même si PasswordAuthentication vaut no." \
                "Désactiver KbdInteractiveAuthentication (sauf usage d'une double authentification TOTP via PAM)." \
                "echo 'KbdInteractiveAuthentication no' | sudo tee -a $hardening
$reload"
        fi
    fi

    if [ "$(sshv permitemptypasswords)" = "yes" ]; then
        finding "CRITIQUE" "$cat" "Mots de passe vides autorisés (PermitEmptyPasswords yes)" \
            "Un compte sans mot de passe peut ouvrir une session SSH sans aucune authentification." \
            "Interdire les mots de passe vides." \
            "echo 'PermitEmptyPasswords no' | sudo tee -a $hardening
$reload"
    fi

    if [ "$(sshv x11forwarding)" = "yes" ]; then
        finding "FAIBLE" "$cat" "Redirection X11 activée" \
            "X11Forwarding yes est inutile sur un serveur sans interface graphique et élargit la surface d'attaque côté client." \
            "Désactiver X11Forwarding." \
            "echo 'X11Forwarding no' | sudo tee -a $hardening
$reload"
    else
        ok "$cat" "Redirection X11 désactivée"
    fi

    local tries
    tries="$(sshv maxauthtries)"
    if [ -n "$tries" ] && [ "$tries" -gt 4 ]; then
        finding "FAIBLE" "$cat" "MaxAuthTries élevé ($tries)" \
            "Chaque connexion peut tenter $tries authentifications avant d'être coupée." \
            "Réduire à 3." \
            "echo 'MaxAuthTries 3' | sudo tee -a $hardening
$reload"
    fi

    if [[ " $SSH_PORTS " == *" 22 "* ]]; then
        inventory "$cat" "- SSH écoute sur le port 22 (port par défaut : plus de bruit dans les journaux, sans gain de sécurité réel si les mots de passe sont désactivés)"
    fi

    # Protection contre la force brute
    if systemctl is-active --quiet fail2ban 2>/dev/null || systemctl is-active --quiet crowdsec 2>/dev/null; then
        ok "$cat" "Protection anti-force brute active (fail2ban ou CrowdSec)"
    elif [ "$(sshv passwordauthentication)" = "yes" ]; then
        finding "MOYEN" "$cat" "Aucune protection contre la force brute" \
            "Les mots de passe sont acceptés et ni fail2ban ni CrowdSec ne tournent : rien ne limite les tentatives." \
            "Désactiver les mots de passe (prioritaire), ou à défaut installer fail2ban." \
            "sudo apt-get install fail2ban
sudo systemctl enable --now fail2ban
sudo fail2ban-client status sshd"
    fi

    # Tentatives échouées récentes
    if has journalctl; then
        local fails
        fails=$(journalctl -u ssh -u sshd --since "7 days ago" --no-pager -q 2>/dev/null \
            | grep -cE 'Failed password|Invalid user|authentication failure' || true)
        inventory "$cat" "- Tentatives d'authentification SSH échouées sur 7 jours : **$fails**"
    fi

    # Clés autorisées : permissions et inventaire
    local keys_md="" user home dir f perm owner fps
    while IFS=: read -r user _ _ _ _ home _; do
        dir="$home/.ssh"
        [ -d "$dir" ] || continue
        perm="$(stat -c %a "$dir")"; owner="$(stat -c %U "$dir")"
        if [ "$owner" != "$user" ] || [ $((8#$perm & 8#077)) -ne 0 ]; then
            finding "MOYEN" "$cat" "Permissions trop larges sur $dir" \
                "Le dossier \`$dir\` est en $perm (propriétaire : $owner). sshd peut refuser les clés, et d'autres comptes peuvent lire ou modifier son contenu." \
                "Restreindre le dossier à son propriétaire." \
                "sudo chown -R $user: $dir && sudo chmod 700 $dir && sudo chmod 600 $dir/authorized_keys"
        fi
        for f in "$dir/authorized_keys" "$dir/authorized_keys2"; do
            [ -f "$f" ] || continue
            perm="$(stat -c %a "$f")"
            if [ $((8#$perm & 8#022)) -ne 0 ]; then
                finding "ÉLEVÉ" "$cat" "$f modifiable par d'autres comptes" \
                    "Le fichier \`$f\` est en $perm : un autre utilisateur peut y ajouter sa propre clé et se connecter en tant que $user." \
                    "Restreindre les permissions." \
                    "sudo chown $user: $f && sudo chmod 600 $f"
            fi
            fps="$(ssh-keygen -lf "$f" 2>/dev/null | awk '{ $2=""; print }' | sed 's/  / /')"
            keys_md+=$'\n'"**$user** (\`$f\`) :"$'\n'"$(bullets "$fps" 50)"$'\n'
        done
    done < /etc/passwd
    if [ -n "$keys_md" ]; then
        inventory "$cat" $'\n'"**Clés SSH autorisées** (vérifier que chacune est connue et toujours utile) :"$'\n'"$keys_md"
    fi
}

# ========================================
# 4. Utilisateurs et sudo
# ========================================
check_users() {
    local cat="Utilisateurs et sudo"
    say "→ $cat"

    local valid_shells
    valid_shells="$(grep -vE '^\s*#|nologin|/false' /etc/shells 2>/dev/null | sort -u)"
    is_login_shell() { grep -qxF "$1" <<< "$valid_shells"; }

    # UID 0 autres que root
    local uid0
    uid0="$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd)"
    if [ -n "$uid0" ]; then
        finding "CRITIQUE" "$cat" "Compte(s) avec UID 0 autre(s) que root" \
            "$(printf 'Ces comptes ont les droits root complets :\n%s' "$(bullets "$uid0")")" \
            "Vérifier leur origine (signe fréquent de compromission). Les supprimer ou leur attribuer un UID normal." \
            "sudo usermod -u <NOUVEL_UID> <compte>   # ou : sudo userdel <compte>"
    else
        ok "$cat" "Seul root a l'UID 0"
    fi

    # UID dupliqués
    local dup
    dup="$(cut -d: -f3 /etc/passwd | sort -n | uniq -d)"
    if [ -n "$dup" ]; then
        finding "ÉLEVÉ" "$cat" "UID dupliqués" \
            "$(printf 'Plusieurs comptes partagent le même UID, donc les mêmes droits sur les fichiers :\n%s' "$(bullets "$(for u in $dup; do awk -F: -v u="$u" '$3==u{printf "%s ", $1}' /etc/passwd; echo "(UID $u)"; done)")")" \
            "Attribuer un UID unique à chaque compte." \
            "sudo usermod -u <NOUVEL_UID> <compte>"
    fi

    # Mots de passe vides
    local empty
    empty="$(awk -F: '$2==""{print $1}' /etc/shadow 2>/dev/null)"
    if [ -n "$empty" ]; then
        finding "CRITIQUE" "$cat" "Compte(s) sans mot de passe" \
            "$(printf 'Ces comptes ont un mot de passe vide dans /etc/shadow :\n%s' "$(bullets "$empty")")" \
            "Verrouiller les comptes ou leur définir un mot de passe." \
            "sudo passwd -l <compte>"
    else
        ok "$cat" "Aucun compte avec mot de passe vide"
    fi

    # Comptes système avec un shell de connexion
    local sys_shell="" user uid shell
    while IFS=: read -r user _ uid _ _ _ shell; do
        [ "$uid" -lt 1000 ] && [ "$uid" -ne 0 ] || continue
        is_login_shell "$shell" && sys_shell+="$user ($shell)"$'\n'
    done < /etc/passwd
    if [ -n "$sys_shell" ]; then
        finding "MOYEN" "$cat" "Comptes système avec un shell de connexion" \
            "$(printf 'Ces comptes de service (UID < 1000) peuvent ouvrir une session interactive :\n%s' "$(bullets "$sys_shell")")" \
            "Leur attribuer /usr/sbin/nologin s'ils n'ont pas besoin de shell (vérifier avant : certains services, comme postgres, l'utilisent pour les tâches d'administration)." \
            "sudo usermod -s /usr/sbin/nologin <compte>"
    else
        ok "$cat" "Aucun compte système avec shell de connexion"
    fi

    # Comptes humains : inventaire, inactivité
    local humans="" inactive="" never="" ll=""
    has lastlog && ll="lastlog"
    [ -z "$ll" ] && has lastlog2 && ll="lastlog2"
    while IFS=: read -r user _ uid _ _ home shell; do
        [ "$uid" -ge 1000 ] && [ "$uid" -lt 60000 ] || continue
        is_login_shell "$shell" || continue
        local pw
        pw="$(awk -F: -v u="$user" '$1==u{ if ($2 ~ /^[!*]/) print "verrouillé"; else if ($2=="") print "VIDE"; else print "défini" }' /etc/shadow)"
        humans+="$user — UID $uid — $shell — mot de passe : $pw"$'\n'
        if [ -n "$ll" ]; then
            if $ll -u "$user" 2>/dev/null | grep -q 'Never logged in\|\*\*Never'; then
                never+="$user"$'\n'
            elif [ -n "$($ll -b "$MAX_INACTIVE_DAYS" -u "$user" 2>/dev/null | tail -n +2)" ]; then
                inactive+="$user"$'\n'
            fi
        fi
    done < /etc/passwd
    [ -n "$humans" ] && inventory "$cat" $'\n'"**Comptes avec shell de connexion :**"$'\n'"$(bullets "$humans" 100)"

    if [ -n "$inactive" ]; then
        finding "FAIBLE" "$cat" "Comptes inactifs depuis plus de $MAX_INACTIVE_DAYS jours" \
            "$(printf 'Ces comptes ne se sont pas connectés depuis plus de %s jours :\n%s' "$MAX_INACTIVE_DAYS" "$(bullets "$inactive")")" \
            "Verrouiller ou supprimer les comptes qui ne servent plus (et retirer leurs clés SSH)." \
            "sudo usermod -L -e 1 <compte>     # verrouille et fait expirer le compte"
    fi
    if [ -n "$never" ]; then
        finding "INFO" "$cat" "Comptes jamais connectés" \
            "$(printf 'Ces comptes ont un shell mais aucune connexion enregistrée :\n%s' "$(bullets "$never")")" \
            "Vérifier qu'ils sont utiles ; sinon leur retirer le shell ou les supprimer."
    fi

    # root : mot de passe
    if [ "$(passwd -S root 2>/dev/null | awk '{print $2}')" = "P" ]; then
        finding "FAIBLE" "$cat" "Le compte root a un mot de passe utilisable" \
            "root a un mot de passe défini. Si des utilisateurs sudo existent, ce mot de passe est une porte d'entrée de plus (console, su)." \
            "Verrouiller le mot de passe root (l'accès root reste possible via sudo). Garder un accès console de secours chez l'hébergeur." \
            "sudo passwd -l root"
    else
        ok "$cat" "Mot de passe root verrouillé"
    fi

    # Membres des groupes privilégiés
    local g members priv=""
    for g in sudo admin wheel lxd docker; do
        members="$(getent group "$g" | cut -d: -f4)"
        [ -n "$members" ] && priv+="$g : $members"$'\n'
    done
    [ -n "$priv" ] && inventory "$cat" $'\n'"**Groupes privilégiés** (sudo, et groupes équivalents à root : lxd, docker) :"$'\n'"$(bullets "$priv")"

    local lxdm
    lxdm="$(getent group lxd | cut -d: -f4)"
    if [ -n "$lxdm" ]; then
        finding "MOYEN" "$cat" "Membres du groupe lxd (équivalent root)" \
            "Les membres de lxd ($lxdm) peuvent créer un conteneur privilégié qui monte la racine de l'hôte : c'est un accès root sans mot de passe." \
            "Retirer du groupe les comptes qui n'administrent pas LXD." \
            "sudo gpasswd -d <compte> lxd"
    fi

    # sudoers : NOPASSWD et permissions
    local nopw
    nopw="$(grep -rHnE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null)"
    if [ -n "$nopw" ]; then
        finding "MOYEN" "$cat" "Règles sudo sans mot de passe (NOPASSWD)" \
            "$(printf 'Un compte compromis obtient root immédiatement, sans connaître de mot de passe :\n%s' "$(bullets "$nopw")")" \
            "Limiter NOPASSWD aux commandes précises nécessaires (comptes d'automatisation), jamais ALL pour un compte humain. Toujours éditer avec visudo." \
            "sudo visudo -f /etc/sudoers.d/<fichier>"
    else
        ok "$cat" "Aucune règle sudo NOPASSWD"
    fi

    local bad_perm=""
    for f in /etc/sudoers /etc/sudoers.d/*; do
        [ -f "$f" ] || continue
        local p o
        p="$(stat -c %a "$f")"; o="$(stat -c %U "$f")"
        { [ "$o" != "root" ] || [ $((8#$p & 8#022)) -ne 0 ]; } && bad_perm+="$f ($p, $o)"$'\n'
    done
    if [ -n "$bad_perm" ]; then
        finding "CRITIQUE" "$cat" "Fichiers sudoers modifiables par d'autres que root" \
            "$(printf 'Un utilisateur qui peut écrire dans ces fichiers peut se donner tous les droits :\n%s' "$(bullets "$bad_perm")")" \
            "Rétablir le propriétaire root et les permissions 440." \
            "sudo chown root:root /etc/sudoers /etc/sudoers.d/*
sudo chmod 440 /etc/sudoers /etc/sudoers.d/*
sudo visudo -c"
    fi

    # Dossiers personnels
    local open_homes="" ww_homes="" dir p
    while IFS=: read -r user _ uid _ _ dir _; do
        [ "$uid" -ge 1000 ] && [ "$uid" -lt 60000 ] && [ -d "$dir" ] || continue
        [[ "$dir" == /home/* ]] || continue
        p="$(stat -c %a "$dir")"
        if [ $((8#$p & 8#002)) -ne 0 ]; then ww_homes+="$dir ($p)"$'\n'
        elif [ $((8#$p & 8#005)) -ne 0 ]; then open_homes+="$dir ($p)"$'\n'
        fi
    done < /etc/passwd
    if [ -n "$ww_homes" ]; then
        finding "ÉLEVÉ" "$cat" "Dossiers personnels modifiables par tous" \
            "$(printf 'N'"'"'importe quel compte peut y écrire (par exemple remplacer .bashrc ou .ssh) :\n%s' "$(bullets "$ww_homes")")" \
            "Retirer l'écriture pour les autres." \
            "sudo chmod o-w <dossier>"
    fi
    if [ -n "$open_homes" ]; then
        finding "FAIBLE" "$cat" "Dossiers personnels lisibles par les autres comptes" \
            "$(printf 'Ces dossiers sont lisibles par tous les utilisateurs de la machine :\n%s' "$(bullets "$open_homes")")" \
            "Passer en 750 (attention aux sites web servis depuis /home/*/public_html : le groupe ou l'utilisateur d'Apache doit garder l'accès)." \
            "sudo chmod 750 <dossier>"
    fi
}

# ========================================
# 5. Fichiers et permissions
# ========================================
KNOWN_SUID="
/usr/bin/sudo /usr/bin/sudoedit /usr/bin/su /usr/bin/passwd /usr/bin/chsh /usr/bin/chfn
/usr/bin/newgrp /usr/bin/gpasswd /usr/bin/mount /usr/bin/umount /usr/bin/fusermount
/usr/bin/fusermount3 /usr/bin/pkexec /usr/bin/crontab /usr/bin/ssh-agent /usr/bin/chage
/usr/bin/expiry /usr/bin/wall /usr/bin/write.ul /usr/bin/bsd-write /usr/bin/dotlockfile
/usr/bin/at /usr/bin/plocate /usr/bin/mlocate /usr/bin/screen /usr/bin/procmail
/usr/bin/ntfs-3g /usr/bin/staprun /usr/lib/cargo/bin/sudo /usr/lib/cargo/bin/su
/usr/lib/openssh/ssh-keysign /usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1 /usr/lib/polkit-1/polkit-agent-helper-1
/usr/libexec/polkit-agent-helper-1 /usr/lib/snapd/snap-confine
/usr/lib/x86_64-linux-gnu/utempter/utempter /usr/lib/aarch64-linux-gnu/utempter/utempter
/usr/lib/eject/dmcrypt-get-device /usr/lib/xorg/Xorg.wrap
/usr/sbin/unix_chkpwd /usr/sbin/pam_extrausers_chkpwd /usr/sbin/pppd /usr/sbin/postdrop
/usr/sbin/postqueue /usr/sbin/exim4 /usr/sbin/mount.cifs /usr/sbin/mount.nfs
/usr/sbin/mount.ecryptfs_private /usr/sbin/sendmail
"

PRUNE=( \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /snap \
           -o -path /var/lib/docker -o -path /var/lib/containers -o -path /var/lib/lxcfs \
           -o -path /tmp -o -path /var/tmp \) -prune -o )

check_files() {
    local cat="Fichiers et permissions"
    say "→ $cat (recherches dans le système de fichiers, peut prendre quelques minutes)"

    # Fichiers système critiques
    local spec f maxperm owner p o g bad=""
    for spec in "/etc/passwd 644 root" "/etc/group 644 root" "/etc/shadow 640 root" \
                "/etc/gshadow 640 root" "/etc/ssh/sshd_config 644 root" "/etc/crontab 644 root"; do
        read -r f maxperm owner <<< "$spec"
        [ -e "$f" ] || continue
        p="$(stat -c %a "$f")"; o="$(stat -c %U "$f")"; g="$(stat -c %G "$f")"
        if [ "$o" != "$owner" ] || [ $((8#$p & ~8#$maxperm & 8#777)) -ne 0 ]; then
            bad+="$f : $p $o:$g (attendu au plus $maxperm, propriétaire $owner)"$'\n'
        fi
    done
    if [ -n "$bad" ]; then
        local sev="ÉLEVÉ"
        grep -q 'shadow' <<< "$bad" && sev="CRITIQUE"
        finding "$sev" "$cat" "Permissions incorrectes sur des fichiers système" \
            "$(printf 'Ces fichiers ont des permissions plus larges que la normale :\n%s' "$(bullets "$bad")")" \
            "Rétablir les permissions standard d'Ubuntu." \
            "sudo chown root:root /etc/passwd /etc/group /etc/crontab /etc/ssh/sshd_config
sudo chmod 644 /etc/passwd /etc/group /etc/crontab /etc/ssh/sshd_config
sudo chown root:shadow /etc/shadow /etc/gshadow && sudo chmod 640 /etc/shadow /etc/gshadow"
    else
        ok "$cat" "Permissions des fichiers système critiques conformes"
    fi

    # Fichiers modifiables par tous
    local ww ww_sys ww_other
    ww="$(bounded 500 find / -xdev "${PRUNE[@]}" -type f -perm -0002 -print)"
    ww_sys="$(grep -E '^/(etc|usr|bin|sbin|lib|boot|root|opt|var/www|srv)/' <<< "$ww" || true)"
    ww_other="$(grep -vE '^/(etc|usr|bin|sbin|lib|boot|root|opt|var/www|srv)/' <<< "$ww" || true)"
    if [ -n "$ww_sys" ]; then
        finding "ÉLEVÉ" "$cat" "Fichiers système modifiables par tous" \
            "$(printf 'N'"'"'importe quel compte peut modifier ces fichiers (scripts, configurations, pages web) :\n%s' "$(bullets "$ww_sys")")" \
            "Retirer le droit d'écriture pour les autres." \
            "sudo chmod o-w <fichier>
# en masse, après vérification de la liste :
sudo find /etc /usr /opt /var/www /srv -xdev -type f -perm -0002 -exec chmod o-w {} +"
    fi
    if [ -n "$ww_other" ]; then
        finding "MOYEN" "$cat" "Autres fichiers modifiables par tous" \
            "$(printf 'Fichiers hors dossiers système modifiables par tous les comptes :\n%s' "$(bullets "$ww_other")")" \
            "Vérifier et retirer le droit d'écriture pour les autres si ce n'est pas voulu." \
            "sudo chmod o-w <fichier>"
    fi
    [ -z "$ww" ] && ok "$cat" "Aucun fichier modifiable par tous (hors /tmp)"

    # Dossiers modifiables par tous sans sticky bit
    local wwd
    wwd="$(bounded 200 find / -xdev "${PRUNE[@]}" -type d -perm -0002 ! -perm -1000 -print)"
    if [ -n "$wwd" ]; then
        finding "MOYEN" "$cat" "Dossiers modifiables par tous sans sticky bit" \
            "$(printf 'Dans ces dossiers, chacun peut supprimer ou remplacer les fichiers des autres :\n%s' "$(bullets "$wwd")")" \
            "Retirer l'écriture pour les autres, ou ajouter le sticky bit s'il s'agit d'un dossier partagé." \
            "sudo chmod o-w <dossier>    # ou : sudo chmod +t <dossier>"
    fi

    # Fichiers sans propriétaire
    local unowned
    unowned="$(bounded 100 find / -xdev "${PRUNE[@]}" \( -nouser -o -nogroup \) -print)"
    if [ -n "$unowned" ]; then
        finding "FAIBLE" "$cat" "Fichiers sans propriétaire valide" \
            "$(printf 'Ces fichiers appartiennent à un UID ou GID qui n'"'"'existe plus. Un futur compte créé avec cet UID en hériterait :\n%s' "$(bullets "$unowned")")" \
            "Leur attribuer un propriétaire existant ou les supprimer." \
            "sudo chown root:root <fichier>"
    fi

    # Binaires SUID/SGID inhabituels
    local suid unknown="" orphan="" pkg
    suid="$(bounded 500 find / -xdev "${PRUNE[@]}" -type f \( -perm -4000 -o -perm -2000 \) -print)"
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        grep -qw -- "$f" <<< "$KNOWN_SUID" && continue
        pkg="$(dpkg -S "$f" 2>/dev/null | cut -d: -f1 | head -n1)"
        if [ -z "$pkg" ]; then
            orphan+="$f ($(stat -c '%A %U' "$f"))"$'\n'
        else
            unknown+="$f — paquet $pkg ($(stat -c '%A' "$f"))"$'\n'
        fi
    done <<< "$suid"
    if [ -n "$orphan" ]; then
        finding "ÉLEVÉ" "$cat" "Binaires SUID/SGID n'appartenant à aucun paquet" \
            "$(printf 'Ces exécutables s'"'"'exécutent avec les droits de leur propriétaire mais ne viennent d'"'"'aucun paquet Ubuntu. C'"'"'est un mécanisme classique de porte dérobée :\n%s' "$(bullets "$orphan")")" \
            "Identifier leur origine. S'ils ne sont pas légitimes, retirer le bit SUID/SGID et analyser la machine." \
            "sudo chmod u-s,g-s <fichier>"
    fi
    if [ -n "$unknown" ]; then
        finding "INFO" "$cat" "Binaires SUID/SGID hors liste de référence" \
            "$(printf 'Ces exécutables privilégiés viennent de paquets installés, mais ne font pas partie de la base Ubuntu habituelle :\n%s' "$(bullets "$unknown")")" \
            "Vérifier que chaque paquet est encore utile."
    fi
    [ -z "$orphan" ] && [ -z "$unknown" ] && ok "$cat" "Binaires SUID/SGID conformes à la liste de référence"

    # Fichiers sensibles laissés en place
    local creds
    creds="$(find /root /home -maxdepth 3 -type f \( -iname '*credential*' -o -iname '*password*' -o -iname '*.secret' \) 2>/dev/null | head -n 50)"
    if [ -n "$creds" ]; then
        finding "ÉLEVÉ" "$cat" "Fichiers d'identifiants laissés sur le disque" \
            "$(printf 'Ces fichiers semblent contenir des mots de passe ou des clés (par exemple les fichiers de credentials générés par un script d'"'"'installation) :\n%s' "$(bullets "$creds")")" \
            "Sauvegarder leur contenu dans un gestionnaire de mots de passe, puis les effacer de façon sécurisée." \
            "sudo shred -u <fichier>"
    fi

    local privkeys="" k
    while IFS= read -r k; do
        [ -z "$k" ] && continue
        grep -qs 'PRIVATE KEY' "$k" || continue
        p="$(stat -c %a "$k")"; g="$(stat -c %G "$k")"
        # lisible par tous : toujours anormal ; lisible par le groupe : toléré
        # pour root et ssl-cert (standard Ubuntu pour /etc/ssl/private)
        if [ $((8#$p & 8#007)) -ne 0 ] \
            || { [ $((8#$p & 8#070)) -ne 0 ] && [ "$g" != "root" ] && [ "$g" != "ssl-cert" ]; }; then
            privkeys+="$k ($p, $(stat -c %U "$k"):$g)"$'\n'
        fi
    done < <(find /root /home /etc/ssl/private /etc/ssh /etc/wireguard -maxdepth 4 -type f \
              \( -name 'id_*' ! -name '*.pub' -o -name '*.key' -o -name '*.pem' -o -name 'ssh_host_*_key' \) 2>/dev/null)
    if [ -n "$privkeys" ]; then
        finding "CRITIQUE" "$cat" "Clés privées lisibles par d'autres comptes" \
            "$(printf 'Ces clés privées sont lisibles au-delà de leur propriétaire :\n%s' "$(bullets "$privkeys")")" \
            "Restreindre les permissions à 600 (ou 640 avec le groupe ssl-cert pour les certificats TLS). Si la machine a d'autres utilisateurs, considérer ces clés comme compromises et les renouveler." \
            "sudo chmod 600 <fichier>"
    else
        ok "$cat" "Clés privées non lisibles par les autres comptes"
    fi
}

# ========================================
# 6. Services
# ========================================
declare -A RISKY_SERVICES=(
    [telnet]="Telnet (en clair)" [inetd]="inetd" [xinetd]="xinetd" [openbsd-inetd]="inetd"
    [vsftpd]="FTP (en clair)" [proftpd]="FTP (en clair)" [pure-ftpd]="FTP (en clair)"
    [rsh-server]="rsh" [rpcbind]="rpcbind" [nfs-server]="serveur NFS" [smbd]="Samba"
    [nmbd]="NetBIOS" [snmpd]="SNMP" [avahi-daemon]="Avahi (mDNS)" [cups]="impression CUPS"
    [cups-browsed]="impression CUPS" [bluetooth]="Bluetooth" [ModemManager]="ModemManager"
)

check_services() {
    local cat="Services"
    say "→ $cat"

    local running svc found=""
    running="$(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '{print $1}' | sed 's/\.service$//')"
    for svc in "${!RISKY_SERVICES[@]}"; do
        grep -qx "$svc" <<< "$running" && found+="$svc — ${RISKY_SERVICES[$svc]}"$'\n'
    done
    if [ -n "$found" ]; then
        local sev="MOYEN"
        grep -qE '^(telnet|vsftpd|proftpd|pure-ftpd|rsh-server|inetd|xinetd)' <<< "$found" && sev="ÉLEVÉ"
        finding "$sev" "$cat" "Services inutiles ou à risque en fonctionnement" \
            "$(printf 'Ces services sont rarement nécessaires sur un serveur, et certains transmettent les identifiants en clair :\n%s' "$(bullets "$found")")" \
            "Les arrêter et les désactiver s'ils ne servent pas. Pour transférer des fichiers, préférer SFTP (inclus dans SSH) à FTP." \
            "sudo systemctl disable --now <service>
# ou, pour supprimer le paquet : sudo apt-get purge <paquet>"
    else
        ok "$cat" "Aucun service à risque connu en fonctionnement"
    fi

    local failed
    failed="$(systemctl list-units --state=failed --no-legend --plain 2>/dev/null | awk '{print $1}')"
    if [ -n "$failed" ]; then
        finding "FAIBLE" "$cat" "Unités systemd en échec" \
            "$(printf 'Ces unités sont en échec. Une sauvegarde, un timer de sécurité ou une mise à jour automatique peut ne plus tourner :\n%s' "$(bullets "$failed")")" \
            "Consulter les journaux de chaque unité et corriger, ou la désactiver si elle est obsolète." \
            "systemctl status <unité>
journalctl -u <unité> -n 50"
    else
        ok "$cat" "Aucune unité systemd en échec"
    fi

    inventory "$cat" "**Services en fonctionnement :**"$'\n'"$(bullets "$running" 200)"
}

# ========================================
# 7. Noyau (sysctl)
# ========================================
check_kernel() {
    local cat="Noyau (sysctl)"
    say "→ $cat"

    if [ "$VIRT" = "lxc" ]; then
        inventory "$cat" "- Conteneur LXC : la plupart des paramètres noyau sont ceux de l'hôte Proxmox. Contrôles affichés à titre indicatif ; les corriger sur l'hôte."
    fi

    local forward
    forward="$(sysctl -n net.ipv4.ip_forward 2>/dev/null)"

    # clé valeur_attendue mode(eq|ge|in:a,b)
    local checks=(
        "kernel.randomize_va_space 2 eq"
        "kernel.kptr_restrict 1 ge"
        "kernel.dmesg_restrict 1 eq"
        "kernel.yama.ptrace_scope 1 ge"
        "fs.protected_hardlinks 1 eq"
        "fs.protected_symlinks 1 eq"
        "fs.suid_dumpable 0 eq"
        "net.ipv4.tcp_syncookies 1 eq"
        "net.ipv4.conf.all.accept_redirects 0 eq"
        "net.ipv4.conf.default.accept_redirects 0 eq"
        "net.ipv6.conf.all.accept_redirects 0 eq"
        "net.ipv4.conf.all.accept_source_route 0 eq"
        "net.ipv4.conf.all.rp_filter 1,2 in"
        "net.ipv4.icmp_echo_ignore_broadcasts 1 eq"
        "net.ipv4.conf.all.log_martians 1 eq"
    )
    [ "$forward" = "1" ] || checks+=("net.ipv4.conf.all.send_redirects 0 eq")

    local c key want mode cur bad="" fix=""
    for c in "${checks[@]}"; do
        read -r key want mode <<< "$c"
        cur="$(sysctl -n "$key" 2>/dev/null)" || continue
        [ -z "$cur" ] && continue
        case "$mode" in
            eq) [ "$cur" = "$want" ] && continue ;;
            ge) [ "$cur" -ge "$want" ] 2>/dev/null && continue ;;
            in) [[ ",$want," == *",$cur,"* ]] && continue ;;
        esac
        bad+="$key = $cur (recommandé : ${want%%,*})"$'\n'
        fix+="$key = ${want%%,*}"$'\n'
    done

    if [ -n "$bad" ]; then
        local sev="FAIBLE"
        grep -qE 'randomize_va_space|protected_(hard|sym)links' <<< "$bad" && sev="MOYEN"
        finding "$sev" "$cat" "Paramètres de durcissement du noyau absents" \
            "$(printf 'Ces paramètres sysctl diffèrent des valeurs recommandées :\n%s' "$(bullets "$bad")")" \
            "Les fixer dans un fichier dédié, puis recharger. Sur un conteneur LXC, appliquer sur l'hôte." \
            "sudo tee /etc/sysctl.d/60-hardening.conf <<'EOF'
${fix%$'\n'}
EOF
sudo sysctl --system"
    else
        ok "$cat" "Paramètres de durcissement du noyau conformes"
    fi
}

# ========================================
# 8. Web (Apache, PHP, MySQL)
# ========================================
check_web() {
    local cat="Web (Apache, PHP, MySQL)"
    say "→ $cat"
    local any=0

    # ---- Apache ----
    if [ -d /etc/apache2 ]; then
        any=1
        local conf_files val
        conf_files="/etc/apache2/apache2.conf /etc/apache2/conf-enabled/*.conf"
        apache_val() {
            # dernière valeur effective d'une directive dans la config activée
            # shellcheck disable=SC2086
            grep -hiE "^\s*$1\s+" $conf_files 2>/dev/null | tail -n1 | awk '{print $2}'
        }

        val="$(apache_val ServerTokens)"
        if [ "${val,,}" != "prod" ]; then
            finding "FAIBLE" "$cat" "Apache annonce sa version (ServerTokens ${val:-OS})" \
                "Les en-têtes HTTP et les pages d'erreur révèlent la version d'Apache et du système, ce qui aide à cibler les failles connues." \
                "Passer ServerTokens à Prod dans /etc/apache2/conf-available/security.conf." \
                "sudo sed -i 's/^\s*ServerTokens.*/ServerTokens Prod/' /etc/apache2/conf-available/security.conf
sudo a2enconf security && sudo apache2ctl configtest && sudo systemctl reload apache2"
        else
            ok "$cat" "Apache : ServerTokens Prod"
        fi

        val="$(apache_val ServerSignature)"
        if [ "${val,,}" != "off" ]; then
            finding "FAIBLE" "$cat" "Signature Apache affichée (ServerSignature ${val:-On})" \
                "Les pages d'erreur et les listings affichent la version d'Apache." \
                "Passer ServerSignature à Off dans /etc/apache2/conf-available/security.conf." \
                "sudo sed -i 's/^\s*ServerSignature.*/ServerSignature Off/' /etc/apache2/conf-available/security.conf
sudo apache2ctl configtest && sudo systemctl reload apache2"
        fi

        val="$(apache_val TraceEnable)"
        if [ "${val,,}" != "off" ]; then
            finding "FAIBLE" "$cat" "Méthode HTTP TRACE activée" \
                "TRACE renvoie la requête reçue et peut servir à contourner certaines protections des cookies." \
                "Passer TraceEnable à Off dans /etc/apache2/conf-available/security.conf." \
                "sudo sed -i 's/^\s*TraceEnable.*/TraceEnable Off/' /etc/apache2/conf-available/security.conf
sudo apache2ctl configtest && sudo systemctl reload apache2"
        fi

        local indexes
        indexes="$(grep -rHnE '^\s*Options\s+.*([^-+]|^|\s)Indexes' /etc/apache2/apache2.conf /etc/apache2/sites-enabled/ /etc/apache2/conf-enabled/ 2>/dev/null | grep -v -- '-Indexes' || true)"
        if [ -n "$indexes" ]; then
            finding "MOYEN" "$cat" "Listing des répertoires activé (Options Indexes)" \
                "$(printf 'Un dossier sans index.html ou index.php affiche la liste de ses fichiers (sauvegardes, fichiers de configuration…) :\n%s' "$(bullets "$indexes")")" \
                "Remplacer Indexes par -Indexes dans chaque fichier listé." \
                "sudo apache2ctl configtest && sudo systemctl reload apache2"
        else
            ok "$cat" "Apache : listing des répertoires désactivé"
        fi

        if apache2ctl -M 2>/dev/null | grep -q 'info_module'; then
            finding "MOYEN" "$cat" "Module Apache mod_info activé" \
                "mod_info publie la configuration complète d'Apache sur /server-info si l'URL est accessible." \
                "Désactiver le module s'il n'est pas utilisé." \
                "sudo a2dismod info && sudo systemctl reload apache2"
        fi
    fi

    # ---- PHP ----
    local ini ver versions=""
    for ini in /etc/php/*/apache2/php.ini /etc/php/*/fpm/php.ini; do
        [ -f "$ini" ] || continue
        any=1
        ver="$(cut -d/ -f4 <<< "$ini")"
        [[ " $versions " == *" $ver "* ]] || versions="$versions $ver"
        phpv() { grep -iE "^\s*$1\s*=" "$ini" | tail -n1 | cut -d= -f2 | tr -d ' "' | tr '[:upper:]' '[:lower:]'; }

        case "$(phpv allow_url_include)" in
            on|1)
                finding "ÉLEVÉ" "$cat" "PHP $ver : allow_url_include activé ($ini)" \
                    "PHP peut inclure du code depuis une URL distante : une faille d'inclusion devient une exécution de code à distance." \
                    "Passer allow_url_include = Off dans $ini." \
                    "sudo sed -i 's/^\s*allow_url_include.*/allow_url_include = Off/' $ini" ;;
        esac
        case "$(phpv display_errors)" in
            on|1|stdout|stderr)
                finding "MOYEN" "$cat" "PHP $ver : erreurs affichées aux visiteurs ($ini)" \
                    "display_errors est actif : les erreurs PHP affichent chemins, requêtes SQL et extraits de code aux visiteurs." \
                    "Passer display_errors = Off (les erreurs restent dans les journaux avec log_errors = On)." \
                    "sudo sed -i 's/^\s*display_errors.*/display_errors = Off/' $ini" ;;
        esac
        case "$(phpv expose_php)" in
            off|0) ;;
            *)
                finding "FAIBLE" "$cat" "PHP $ver : version annoncée (expose_php) ($ini)" \
                    "L'en-tête X-Powered-By révèle la version exacte de PHP." \
                    "Passer expose_php = Off dans $ini." \
                    "sudo sed -i 's/^\s*expose_php.*/expose_php = Off/' $ini" ;;
        esac
    done
    if [ -n "$versions" ]; then
        inventory "$cat" "- Versions PHP configurées :${versions}"
        for ver in $versions; do
            case "$ver" in
                5.*|7.*|8.0|8.1)
                    finding "ÉLEVÉ" "$cat" "PHP $ver n'est plus maintenu" \
                        "PHP $ver ne reçoit plus de correctifs de sécurité du projet PHP." \
                        "Migrer les sites vers une version maintenue (8.3 ou plus récente), puis désinstaller PHP $ver." \
                        "sudo apt-get install php8.3 php8.3-fpm   # adapter les extensions
sudo apt-get purge 'php$ver*'" ;;
                8.2)
                    finding "MOYEN" "$cat" "PHP 8.2 arrive en fin de support" \
                        "Le support de sécurité de PHP 8.2 par le projet PHP se termine le 31 décembre 2026." \
                        "Planifier la migration vers PHP 8.3 ou plus récent." ;;
            esac
        done
    fi

    # ---- Racines web : fichiers qui ne devraient pas y être ----
    local root roots="" leaks="" infos="" gits="" pma=""
    for root in $WEB_ROOTS; do
        [ -d "$root" ] && roots="$roots $root"
    done
    if [ -n "$roots" ]; then
        any=1
        # shellcheck disable=SC2086
        leaks="$(bounded 50 find $roots -maxdepth 6 -type f \( -name '.env' -o -name '.env.*' -o -iname '*.sql' -o -iname '*.sql.gz' -o -iname '*.dump' -o -iname '*.bak' -o -iname '*.old' -o -iname '*.orig' -o -iname '*.swp' -o -name '*~' -o -iname '*.tar.gz' -o -iname '*.zip' \) -print)"
        # shellcheck disable=SC2086
        infos="$(bounded 30 find $roots -maxdepth 6 -type f \( -iname 'phpinfo.php' -o -iname 'info.php' -o -iname 'test.php' \) -print)"
        # shellcheck disable=SC2086
        gits="$(bounded 30 find $roots -maxdepth 6 -type d -name '.git' -print)"
        # shellcheck disable=SC2086
        pma="$(find $roots -maxdepth 3 -type l -lname '*phpmyadmin*' -print 2>/dev/null)"

        if [ -n "$leaks" ]; then
            finding "ÉLEVÉ" "$cat" "Fichiers sensibles dans les racines web" \
                "$(printf 'Ces fichiers (secrets .env, dumps SQL, sauvegardes, archives) peuvent être téléchargeables par n'"'"'importe qui si leur dossier est servi :\n%s' "$(bullets "$leaks")")" \
                "Les déplacer hors des dossiers servis par Apache, ou les supprimer. Pour un .env nécessaire, vérifier qu'il est hors du DocumentRoot ou bloqué par la configuration." \
                "curl -sI https://<site>/<chemin>    # 200 = fichier exposé
sudo mv <fichier> /root/    # ou : sudo rm <fichier>"
        fi
        if [ -n "$gits" ]; then
            finding "MOYEN" "$cat" "Dépôts .git dans les racines web" \
                "$(printf 'Un dossier .git servi par Apache permet de reconstruire tout le code source, historique et identifiants compris :\n%s' "$(bullets "$gits")")" \
                "Vérifier qu'ils sont hors du DocumentRoot, ou bloquer l'accès aux fichiers cachés dans Apache." \
                "printf '<DirectoryMatch \"/\\\\.git\">\n    Require all denied\n</DirectoryMatch>\n' | sudo tee /etc/apache2/conf-available/deny-git.conf
sudo a2enconf deny-git && sudo apache2ctl configtest && sudo systemctl reload apache2"
        fi
        if [ -n "$infos" ]; then
            finding "MOYEN" "$cat" "Pages de diagnostic PHP accessibles" \
                "$(printf 'Ces fichiers affichent généralement phpinfo() : configuration complète, chemins et variables d'"'"'environnement :\n%s' "$(bullets "$infos")")" \
                "Les supprimer après usage." \
                "sudo rm <fichier>"
        fi
        if [ -n "$pma" ] || [ -f /etc/apache2/conf-enabled/phpmyadmin.conf ]; then
            finding "MOYEN" "$cat" "phpMyAdmin accessible par le web" \
                "$(printf 'phpMyAdmin est publié par Apache%s. Interface très ciblée par les robots :\n%s' "$([ -f /etc/apache2/conf-enabled/phpmyadmin.conf ] && echo ' (alias /phpmyadmin)')" "$(bullets "$pma")")" \
                "Restreindre l'accès à vos IP d'administration (directive Require ip), ou y accéder uniquement par un tunnel SSH." \
                "# dans /etc/apache2/conf-available/phpmyadmin.conf, bloc <Directory /usr/share/phpmyadmin> :
#     Require ip <IP_ADMIN>
sudo apache2ctl configtest && sudo systemctl reload apache2"
        fi
        [ -z "$leaks$gits$infos$pma" ] && ok "$cat" "Aucun fichier sensible repéré dans les racines web"
    fi

    # ---- MySQL / MariaDB ----
    if has mysql && { systemctl is-active --quiet mysql 2>/dev/null || systemctl is-active --quiet mariadb 2>/dev/null; }; then
        any=1
        local anon remote_root testdb
        q() { timeout 10 mysql --protocol=socket -NBe "$1" 2>/dev/null; }
        if q "SELECT 1" >/dev/null; then
            anon="$(q "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE user=''")"
            remote_root="$(q "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE user='root' AND host NOT IN ('localhost','127.0.0.1','::1')")"
            testdb="$(q "SHOW DATABASES LIKE 'test'")"
            if [ -n "$anon" ]; then
                finding "ÉLEVÉ" "$cat" "MySQL : comptes anonymes" \
                    "$(printf 'N'"'"'importe qui peut se connecter sans identifiant :\n%s' "$(bullets "$anon")")" \
                    "Supprimer les comptes anonymes (mysql_secure_installation le fait)." \
                    "sudo mysql -e \"DROP USER ''@'localhost'; FLUSH PRIVILEGES;\""
            fi
            if [ -n "$remote_root" ]; then
                finding "ÉLEVÉ" "$cat" "MySQL : root autorisé à distance" \
                    "$(printf 'Le compte root MySQL accepte des connexions depuis d'"'"'autres machines :\n%s' "$(bullets "$remote_root")")" \
                    "Supprimer ces comptes et créer, si besoin, un compte dédié limité à une base et à une IP." \
                    "sudo mysql -e \"DROP USER 'root'@'<hôte>'; FLUSH PRIVILEGES;\""
            fi
            if [ -n "$testdb" ]; then
                finding "FAIBLE" "$cat" "MySQL : base « test » présente" \
                    "La base de test, accessible par défaut à tous les comptes, existe encore." \
                    "La supprimer." \
                    "sudo mysql -e 'DROP DATABASE test;'"
            fi
            [ -z "$anon$remote_root$testdb" ] && ok "$cat" "MySQL : pas de compte anonyme, pas de root distant, pas de base test"
        else
            inventory "$cat" "- MySQL/MariaDB : comptes non vérifiés (connexion root par socket impossible)"
        fi
    fi

    [ "$any" -eq 0 ] && ok "$cat" "Aucun Apache, PHP ou MySQL détecté"
}

# ========================================
# 9. Docker
# ========================================
check_docker() {
    local cat="Docker"
    say "→ $cat"

    if ! has docker; then
        ok "$cat" "Docker non installé"
        return
    fi

    local members
    members="$(getent group docker | cut -d: -f4)"
    if [ -n "$members" ]; then
        finding "MOYEN" "$cat" "Membres du groupe docker (équivalent root)" \
            "Les membres du groupe docker ($members) peuvent lancer un conteneur qui monte / et devenir root sur l'hôte sans mot de passe." \
            "Ne laisser dans ce groupe que les comptes d'administration ; sinon passer par sudo docker, ou utiliser Docker en mode rootless." \
            "sudo gpasswd -d <compte> docker"
    fi

    if [ -S /var/run/docker.sock ]; then
        local p
        p="$(stat -c %a /var/run/docker.sock)"
        if [ $((8#$p & 8#006)) -ne 0 ]; then
            finding "CRITIQUE" "$cat" "Socket Docker accessible à tous ($p)" \
                "Tout compte de la machine peut piloter Docker, donc devenir root." \
                "Rétablir les permissions 660 (root:docker)." \
                "sudo chmod 660 /var/run/docker.sock && sudo chown root:docker /var/run/docker.sock"
        fi
    fi

    local ids
    ids="$(docker ps -q 2>/dev/null)"
    [ -z "$ids" ] && { ok "$cat" "Aucun conteneur en fonctionnement"; return; }

    local priv sock hostnet
    # shellcheck disable=SC2086
    priv="$(docker inspect --format '{{.Name}} {{.HostConfig.Privileged}}' $ids 2>/dev/null | awk '$2=="true"{print substr($1,2)}')"
    # shellcheck disable=SC2086
    sock="$(docker inspect --format '{{.Name}}{{range .Mounts}} {{.Source}}{{end}}' $ids 2>/dev/null | grep 'docker.sock' | awk '{print substr($1,2)}')"
    # shellcheck disable=SC2086
    hostnet="$(docker inspect --format '{{.Name}} {{.HostConfig.NetworkMode}}' $ids 2>/dev/null | awk '$2=="host"{print substr($1,2)}')"

    if [ -n "$priv" ]; then
        finding "ÉLEVÉ" "$cat" "Conteneurs privilégiés" \
            "$(printf 'Un conteneur --privileged a accès à tous les périphériques de l'"'"'hôte : une faille dans l'"'"'application donne l'"'"'hôte entier :\n%s' "$(bullets "$priv")")" \
            "Retirer --privileged (ou privileged: true dans le compose) et n'ajouter que les capacités nécessaires (--cap-add)."
    fi
    if [ -n "$sock" ]; then
        finding "ÉLEVÉ" "$cat" "Conteneurs ayant accès au socket Docker" \
            "$(printf 'Ces conteneurs montent /var/run/docker.sock et peuvent donc contrôler Docker, et devenir root sur l'"'"'hôte :\n%s' "$(bullets "$sock")")" \
            "Ne le garder que pour les outils qui en ont réellement besoin (Portainer, Traefik…), si possible en lecture seule ou derrière un proxy de socket filtrant."
    fi
    if [ -n "$hostnet" ]; then
        finding "INFO" "$cat" "Conteneurs en réseau hôte" \
            "$(printf 'Ces conteneurs partagent la pile réseau de l'"'"'hôte : leurs ports apparaissent directement dans la section Réseau :\n%s' "$(bullets "$hostnet")")" \
            "Vérifier que c'est nécessaire."
    fi
    [ -z "$priv$sock" ] && ok "$cat" "Aucun conteneur privilégié ni monté sur le socket Docker"

    inventory "$cat" "**Conteneurs :**"$'\n'"$(bullets "$(docker ps --format '{{.Names}} — {{.Image}} — {{.Ports}}' 2>/dev/null)" 100)"
}

# ========================================
# 10. Journalisation
# ========================================
check_logging() {
    local cat="Journalisation"
    say "→ $cat"

    if [ -d /var/log/journal ] || grep -qsE '^\s*Storage\s*=\s*persistent' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf; then
        ok "$cat" "Journal systemd persistant (conservé après redémarrage)"
    else
        finding "FAIBLE" "$cat" "Journal systemd non persistant" \
            "Le journal est stocké en mémoire : après un redémarrage (ou un incident), les traces sont perdues." \
            "Rendre le journal persistant." \
            "sudo mkdir -p /var/log/journal
sudo systemd-tmpfiles --create --prefix /var/log/journal
sudo systemctl restart systemd-journald"
    fi

    if systemctl is-active --quiet rsyslog 2>/dev/null; then
        ok "$cat" "rsyslog actif"
    fi

    if systemctl is-active --quiet auditd 2>/dev/null; then
        ok "$cat" "auditd actif"
    else
        finding "INFO" "$cat" "auditd non installé" \
            "auditd trace les accès aux fichiers sensibles et les commandes privilégiées. Il est utile pour enquêter après un incident." \
            "Facultatif : l'installer sur les serveurs exposés." \
            "sudo apt-get install auditd && sudo systemctl enable --now auditd"
    fi

    local usage
    usage="$(df -P /var/log 2>/dev/null | awk 'NR==2{gsub("%","",$5); print $5}')"
    if [ -n "$usage" ] && [ "$usage" -ge 90 ]; then
        finding "MOYEN" "$cat" "Partition des journaux presque pleine (${usage} %)" \
            "Quand la partition est pleine, les journaux ne sont plus écrits et certains services s'arrêtent." \
            "Libérer de la place et limiter la taille du journal." \
            "sudo journalctl --vacuum-size=500M
sudo du -xh /var/log | sort -h | tail -n 20"
    fi
}

# ========================================
# Exécution des contrôles
# ========================================
say "Audit de sécurité de $HOST — rapport : $REPORT"
check_system
check_network
check_ssh
check_users
check_files
check_services
check_kernel
check_web
check_docker
check_logging

# ========================================
# Génération du rapport
# ========================================
say "→ Génération du rapport"

declare -A COUNT=()
for s in "${SEVERITIES[@]}"; do COUNT[$s]=0; done
for s in "${F_SEV[@]}"; do COUNT[$s]=$(( COUNT[$s] + 1 )); done

# Ordre global : sévérité, puis catégorie
ORDER=()
for s in "${SEVERITIES[@]}"; do
    for c in "${CATEGORIES[@]}"; do
        for i in "${!F_SEV[@]}"; do
            [ "${F_SEV[$i]}" = "$s" ] && [ "${F_CAT[$i]}" = "$c" ] && ORDER+=("$i")
        done
    done
done
declare -A FID=()
n=0
for i in "${ORDER[@]}"; do
    n=$((n + 1))
    FID[$i]="$(printf 'F%02d' "$n")"
done

if [ $((COUNT[CRITIQUE] + COUNT[ÉLEVÉ])) -gt 0 ]; then
    VERDICT="🔴 **Action requise** : au moins un point critique ou élevé."
    EXIT_CODE=2
elif [ "${COUNT[MOYEN]}" -gt 0 ]; then
    VERDICT="🟠 **À améliorer** : aucun point critique, mais des points moyens à traiter."
    EXIT_CODE=1
else
    VERDICT="🟢 **Correct** : aucun point important."
    EXIT_CODE=0
fi

sev_icon() {
    case "$1" in
        CRITIQUE) echo "🔴" ;; ÉLEVÉ) echo "🟠" ;; MOYEN) echo "🟡" ;; FAIBLE) echo "🔵" ;; *) echo "⚪" ;;
    esac
}

DURATION=$(( $(date +%s) - START_TS ))

{
    echo "# Rapport d'audit de sécurité — $HOST"
    echo
    echo "| | |"
    echo "|---|---|"
    echo "| Date | $(date '+%d/%m/%Y %H:%M') |"
    echo "| Machine | \`$HOST\` ($(hostname -f 2>/dev/null || echo "$HOST")) |"
    echo "| Système | $OS_NAME — noyau $KERNEL |"
    echo "| Virtualisation | $VIRT |"
    echo "| Uptime | ${UPTIME:-inconnu} |"
    echo "| Durée de l'audit | ${DURATION} s |"
    echo "| Script | audit-securite.sh v$SCRIPT_VERSION$([ -n "$CONF_FILE" ] && echo " — config \`$CONF_FILE\`") |"
    echo
    echo "> Audit en lecture seule : aucune modification n'a été faite. Les commandes proposées sont à relire et à adapter avant exécution, en particulier celles qui touchent au pare-feu ou à SSH (gardez une session ouverte pendant les tests)."
    echo
    echo "## Synthèse"
    echo
    echo "$VERDICT"
    echo
    echo "| Sévérité | Nombre |"
    echo "|---|---|"
    for s in "${SEVERITIES[@]}"; do
        echo "| $(sev_icon "$s") $s | ${COUNT[$s]} |"
    done
    echo "| ✅ Contrôles conformes | ${#OK_TXT[@]} |"
    echo
    echo "## Plan d'action"
    echo
    if [ "${#ORDER[@]}" -eq 0 ]; then
        echo "Rien à faire."
    else
        echo "Par ordre de priorité. Le détail de chaque point (constat, action, commandes) est dans la section de sa catégorie."
        echo
        echo "| # | Sévérité | Catégorie | Point |"
        echo "|---|---|---|---|"
        for i in "${ORDER[@]}"; do
            echo "| ${FID[$i]} | $(sev_icon "${F_SEV[$i]}") ${F_SEV[$i]} | ${F_CAT[$i]} | ${F_TITLE[$i]//|/\\|} |"
        done
    fi
    echo
    echo "## Détail par catégorie"

    for c in "${CATEGORIES[@]}"; do
        echo
        echo "### $c"
        has_content=0
        for i in "${ORDER[@]}"; do
            [ "${F_CAT[$i]}" = "$c" ] || continue
            has_content=1
            echo
            echo "#### ${FID[$i]} · $(sev_icon "${F_SEV[$i]}") ${F_SEV[$i]} — ${F_TITLE[$i]}"
            echo
            echo "**Constat.** ${F_DETAIL[$i]}"
            echo
            echo "**Action.** ${F_ACTION[$i]}"
            if [ -n "${F_CMD[$i]}" ]; then
                echo
                echo '```bash'
                echo "${F_CMD[$i]}"
                echo '```'
            fi
        done

        oks=""
        for j in "${!OK_CAT[@]}"; do
            [ "${OK_CAT[$j]}" = "$c" ] && oks+="- ✅ ${OK_TXT[$j]}"$'\n'
        done
        if [ -n "$oks" ]; then
            has_content=1
            echo
            echo "**Contrôles conformes**"
            echo
            printf '%s' "$oks"
        fi

        if [ -n "${INVENTORY[$c]:-}" ]; then
            has_content=1
            echo
            echo "**Inventaire**"
            echo
            printf '%s' "${INVENTORY[$c]}"
        fi
        [ "$has_content" -eq 0 ] && { echo; echo "_Aucun élément._"; }
    done

    echo
    echo "---"
    echo
    echo "_Rapport généré par audit-securite.sh v$SCRIPT_VERSION. Relancer l'audit après corrections pour vérifier les points traités._"
} >> "$REPORT"

if [ "$QUIET" -eq 1 ]; then
    echo "$REPORT"
else
    echo
    echo "=========================================="
    echo "Audit terminé en ${DURATION} s"
    for s in "${SEVERITIES[@]}"; do printf '  %s%*s %s\n' "$s" $((10 - ${#s})) "" "${COUNT[$s]}"; done
    printf '  %s%*s %s\n' "Conformes" 1 "" "${#OK_TXT[@]}"
    echo "Rapport : $REPORT"
    echo "=========================================="
fi

exit "$EXIT_CODE"
