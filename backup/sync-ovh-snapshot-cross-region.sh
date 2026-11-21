#!/bin/bash
# Nom        : sync-ovh-snapshot-cross-region.sh
# Description: Copie les sauvegardes automatiques d'instances OVH Public Cloud
#              (images privées OpenStack) du jour d'une région A vers une
#              région B, puis supprime dans la région B les copies faites par
#              ce script qui ont plus de RETENTION_DAYS jours
# Cible      : Ubuntu, client OpenStack (python3-openstackclient) et jq
# Usage      : cp sync-ovh-snapshot-cross-region.conf.example sync-ovh-snapshot-cross-region.conf
#              nano sync-ovh-snapshot-cross-region.conf
#              ./sync-ovh-snapshot-cross-region.sh [chemin/vers/fichier.conf]
# Prérequis  : fichiers openrc OVH des deux régions, espace disque suffisant
#              dans WORK_DIR pour une image qcow2 complète
#
# Sécurité :
# - la purge ne supprime QUE les images nommées par ce script
#   (AAAA-MM-JJ-<nom de sauvegarde>), jamais les autres images privées ;
# - une copie déjà présente dans la région B n'est pas recréée ;
# - si une copie échoue, la purge n'est pas lancée et le script sort en 1.

# ========================================
# Configuration (lue dans le fichier .conf)
# ========================================
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
CONF_FILE="${1:-$SCRIPT_DIR/sync-ovh-snapshot-cross-region.conf}"

if [ ! -f "$CONF_FILE" ]; then
    echo "ERREUR : fichier de configuration introuvable : $CONF_FILE" >&2
    echo "Copiez sync-ovh-snapshot-cross-region.conf.example en sync-ovh-snapshot-cross-region.conf et renseignez-le." >&2
    exit 1
fi
# shellcheck source-path=SCRIPTDIR source=sync-ovh-snapshot-cross-region.conf.example
. "$CONF_FILE"

for v in WORK_DIR OPENRC_SOURCE OPENRC_DEST BACKUP_NAME_PATTERN RETENTION_DAYS; do
    if [ -z "${!v:-}" ] || [[ "${!v}" == *CHANGE_ME* ]]; then
        echo "ERREUR : $v est vide ou contient encore CHANGE_ME dans $CONF_FILE" >&2
        exit 1
    fi
done
if ! [[ "$RETENTION_DAYS" =~ ^[0-9]+$ ]] || [ "$RETENTION_DAYS" -lt 1 ]; then
    echo "ERREUR : RETENTION_DAYS doit être un nombre de jours ≥ 1 ($RETENTION_DAYS)" >&2
    exit 1
fi

# Noms des copies créées par ce script : AAAA-MM-JJ-<nom de sauvegarde>
MANAGED_NAME_REGEX="^[0-9]{4}-[0-9]{2}-[0-9]{2}-(${BACKUP_NAME_PATTERN})$"
FAILURES=0

#List all private images available
fullPath="$WORK_DIR"
fileName="list.txt"
source "$OPENRC_SOURCE"
INFILE="$fullPath/$fileName"
openstack image list --private --sort created_at:desc > "$INFILE"


while read -r LINE
do
        backupID=$(echo $LINE | grep -Eio '([a-zA-Z0-9_]{8})-([a-zA-Z0-9_]{4})-([a-zA-Z0-9_]{4})-([a-zA-Z0-9_]{4})-([a-zA-Z0-9_]{12})')
        if [ -n "$backupID" ]; then
                backupDate=$(openstack image show $backupID | grep -Eio '([0-9_]{4})-([0-9_]{2})-([0-9_]{2})T([0-9_]{2}):([0-9_]{2}):([0-9_]{2}Z)' | head -n1)
                backupName=$(openstack image show $backupID | grep -Eio "$BACKUP_NAME_PATTERN" | head -n1)
                dateOnly=${backupDate%T*}
                dateToday=$(date -Id)
                if [ -n "$backupName" ] && test "$dateOnly" = "$dateToday"
                then
                        targetName="$dateToday-$backupName"
                        qcowFile="$fullPath/$targetName.qcow"

                        # Copie déjà présente dans la région de destination ?
                        source "$OPENRC_DEST"
                        if openstack image list --private -f value -c Name | grep -qxF "$targetName"; then
                                echo "Déjà présente dans la région de destination : $targetName"
                                source "$OPENRC_SOURCE"
                                continue
                        fi
                        source "$OPENRC_SOURCE"

                        echo "Début de la sauvegarde $targetName.qcow"
                        if ! openstack image save -v --file "$qcowFile" $backupID; then
                                echo "ERREUR : téléchargement de $backupID impossible, image ignorée" >&2
                                rm -f "$qcowFile"
                                FAILURES=$((FAILURES + 1))
                                continue
                        fi

                        source "$OPENRC_DEST"
                        #openstack image list --long --sort created_at:desc
                        if ! openstack image create --private --disk-format qcow2 --container-format bare --file "$qcowFile" "$targetName"; then
                                echo "ERREUR : envoi de $targetName vers la région de destination impossible" >&2
                                FAILURES=$((FAILURES + 1))
                        else
                                echo "Fin de la sauvegarde"
                        fi
                        rm -f "$qcowFile"
                        source "$OPENRC_SOURCE"
                else
                        echo "Ne pas synchroniser" $backupID " " $backupName " "  $backupDate " " $dateToday
                fi
        fi
done < "$INFILE"

if [ "$FAILURES" -gt 0 ]; then
        echo "ERREUR : $FAILURES copie(s) en échec : purge des anciennes copies non lancée." >&2
        exit 1
fi

echo "Recherche et suppression des copies de plus de $RETENTION_DAYS jours dans la région de destination..."
source "$OPENRC_DEST"
dateLimit=$(date -Id -d "-$RETENTION_DAYS days")

openstack image list --private -f json | jq -c '.[]' | while read -r image; do
    image_id=$(echo "$image" | jq -r '.ID')
    image_name=$(echo "$image" | jq -r '.Name')

    # Ne toucher qu'aux images créées par ce script
    if ! grep -qE "$MANAGED_NAME_REGEX" <<< "$image_name"; then
        continue
    fi

    created_at=$(openstack image show "$image_id" -f json | jq -r '.created_at')

    # extraire uniquement la date sans l'heure
    image_date=${created_at%%T*}

    if [[ "$image_date" < "$dateLimit" ]]; then
        echo "Suppression de l’image $image_name (créée le $image_date, ID: $image_id)..."
        openstack image delete "$image_id"
    fi
done
