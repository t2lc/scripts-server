#!/bin/bash
# ============================================================
# php-versions-cleanup
#
# Inventaire des versions PHP installées (paquets phpX.Y-*) et
# de leurs modules, détection de leur utilisation (Apache mod_php,
# PHP-FPM + vhosts, Virtualmin, CLI, cron, systemd), puis
# désinstallation guidée : toutes les versions inutilisées
# d'un coup, ou version par version.
#
# Cible : Ubuntu, paquets PHP versionnés (PPA ondrej/php),
#         Apache (mod_php ou PHP-FPM), Virtualmin.
#
# Usage : sudo php-versions-cleanup [options]
#   --report    affiche l'inventaire et quitte
#   --dry-run   simule les désinstallations, ne modifie rien
#   --purge     purge au lieu de remove (supprime aussi /etc/php/X.Y,
#               donc les pools FPM et les php.ini de la version)
#   -h, --help  aide
# ============================================================

set -uo pipefail

TAG="php-versions-cleanup"

APACHE_ENABLED_DIRS=(/etc/apache2/sites-enabled /etc/apache2/conf-enabled)
CRON_PATHS=(/etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily
            /etc/cron.weekly /etc/cron.monthly /var/spool/cron/crontabs)
SYSTEMD_PATHS=(/etc/systemd/system)

DRY_RUN=0
PURGE=0
REPORT_ONLY=0


# ============================================================
# Options
# ============================================================

usage() {
    sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
}

for arg in "$@"; do
    case "$arg" in
        --report)  REPORT_ONLY=1 ;;
        --dry-run) DRY_RUN=1 ;;
        --purge)   PURGE=1 ;;
        -h|--help) usage; exit 0 ;;
        *)         echo "Option inconnue : $arg" >&2; usage; exit 1 ;;
    esac
done


# ============================================================
# Affichage
# ============================================================

if [[ -t 1 ]]; then
    C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'
    C_BLD=$'\e[1m';  C_DIM=$'\e[2m';  C_RST=$'\e[0m'
else
    C_RED=""; C_GRN=""; C_YEL=""; C_BLD=""; C_DIM=""; C_RST=""
fi

log() {
    logger -t "$TAG" "$*"
    echo "$*"
}


# ============================================================
# Vérifications
# ============================================================

if [[ "$(id -u)" -ne 0 ]]; then
    echo "À lancer avec sudo." >&2
    exit 1
fi

for cmd in dpkg-query apt-get; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Commande introuvable : $cmd" >&2
        exit 1
    fi
done


# ============================================================
# Fichiers Apache actifs qui référencent un listen FPM
# (socket ou port TCP, Virtualmin utilise des ports à partir de 8000)
# -R et non -r : sites-enabled ne contient que des liens symboliques
# ============================================================

apache_refs() {
    local listen="$1" port

    if [[ "$listen" == /* ]]; then
        grep -RlsF -- "$listen" "${APACHE_ENABLED_DIRS[@]}"
    else
        port="${listen##*:}"
        [[ "$port" =~ ^[0-9]+$ ]] || return 0
        grep -RlsE -- "fcgi://(localhost|127\.0\.0\.1|\[::1\]):${port}([^0-9]|$)" \
            "${APACHE_ENABLED_DIRS[@]}"
    fi | xargs -r -n1 basename | sort -u | paste -sd ' ' -
}


# ============================================================
# Scan
# ============================================================

declare -A PKGS USED CHECK INFO
VERSIONS=()

scan() {
    PKGS=(); USED=(); CHECK=(); INFO=(); VERSIONS=()

    local pkg v

    # Paquets installés, regroupés par version
    while read -r pkg; do
        v="$(sed -E 's/^(libapache2-mod-)?php([0-9]+\.[0-9]+).*/\2/' <<< "$pkg")"
        PKGS[$v]+="$pkg "
    done < <(
        dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 2>/dev/null \
            | awk '$1 == "ii" {print $2}' \
            | grep -E '^(libapache2-mod-)?php[0-9]+\.[0-9]+(-|$)' \
            | sort
    )

    mapfile -t VERSIONS < <(printf '%s\n' "${!PKGS[@]}" | grep . | sort -V)
    (( ${#VERSIONS[@]} )) || return 0

    # Version CLI par défaut
    local cli_default=""
    if [[ -e /usr/bin/php ]]; then
        cli_default="$(readlink -f /usr/bin/php | sed -nE 's#.*/php([0-9]+\.[0-9]+)$#\1#p')"
    fi

    # Virtualmin : "<version> <domaine>" par ligne
    local vmin_map=""
    if command -v virtualmin >/dev/null 2>&1; then
        vmin_map="$(virtualmin list-domains --multiline 2>/dev/null | awk '
            /^[^[:space:]]/                 { dom = $1 }
            /^[[:space:]]+PHP version:/     { print $3, dom }')"
    fi

    local vre pool name listen files doms

    for v in "${VERSIONS[@]}"; do

        vre="${v//./\\.}"

        # CLI
        if [[ "$v" == "$cli_default" ]]; then
            USED[$v]+="  - version CLI par défaut (/usr/bin/php)"$'\n'
        fi

        # Apache mod_php et handler FPM global
        if command -v a2query >/dev/null 2>&1; then
            if a2query -q -m "php$v" 2>/dev/null; then
                USED[$v]+="  - module Apache mod_php (php$v) activé"$'\n'
            fi
            if a2query -q -c "php$v-fpm" 2>/dev/null; then
                USED[$v]+="  - conf Apache php$v-fpm activée (handler .php global)"$'\n'
            fi
        fi

        # Service FPM (information seulement : actif ne veut pas dire utilisé)
        if systemctl is-active --quiet "php$v-fpm" 2>/dev/null; then
            INFO[$v]+="  - service php$v-fpm actif"$'\n'
        fi

        # Pools FPM et vhosts qui les utilisent
        for pool in /etc/php/"$v"/fpm/pool.d/*.conf; do
            [[ -f "$pool" ]] || continue

            name="$(sed -nE 's/^[[:space:]]*\[([^]]+)\].*/\1/p' "$pool" | head -n1)"
            listen="$(sed -nE 's/^[[:space:]]*listen[[:space:]]*=[[:space:]]*([^;[:space:]]+).*/\1/p' "$pool" | head -n1)"
            [[ -n "$listen" ]] || continue

            files="$(apache_refs "$listen")"

            if [[ -n "$files" ]]; then
                USED[$v]+="  - pool FPM [$name] ($listen) utilisé par : $files"$'\n'
            elif [[ "$(basename "$pool")" != "www.conf" ]]; then
                CHECK[$v]+="  - pool FPM [$name] ($listen) sans vhost Apache actif"$'\n'
            fi
        done

        # Domaines Virtualmin
        if [[ -n "$vmin_map" ]]; then
            doms="$(awk -v v="$v" '$1 == v {print $2}' <<< "$vmin_map" | paste -sd ' ' -)"
            if [[ -n "$doms" ]]; then
                USED[$v]+="  - Virtualmin : $doms"$'\n'
            fi
        fi

        # Appels explicites dans les crons
        files="$(grep -RlsE -- "php${vre}([^0-9.]|$)" "${CRON_PATHS[@]}" 2>/dev/null | paste -sd ' ' -)"
        if [[ -n "$files" ]]; then
            USED[$v]+="  - appelé dans cron : $files"$'\n'
        fi

        # Unités systemd locales
        files="$(grep -RlsE -- "php${vre}([^0-9.]|$)" "${SYSTEMD_PATHS[@]}" 2>/dev/null \
                    | grep -v "php${vre}-fpm" | paste -sd ' ' -)"
        if [[ -n "$files" ]]; then
            CHECK[$v]+="  - référencé dans systemd : $files"$'\n'
        fi
    done
}

status_of() {
    if   [[ -n "${USED[$1]:-}"  ]]; then echo used
    elif [[ -n "${CHECK[$1]:-}" ]]; then echo check
    else                                 echo unused
    fi
}

unused_versions() {
    local v
    for v in "${VERSIONS[@]}"; do
        [[ "$(status_of "$v")" == unused ]] && echo "$v"
    done
}


# ============================================================
# Rapport
# ============================================================

report() {
    local v st label p mods n

    echo
    echo "${C_BLD}================ Versions PHP installées ================${C_RST}"

    if (( ${#VERSIONS[@]} == 0 )); then
        echo "Aucune version PHP versionnée installée."
        return
    fi

    for v in "${VERSIONS[@]}"; do

        st="$(status_of "$v")"
        case "$st" in
            used)   label="${C_GRN}UTILISÉE${C_RST}" ;;
            check)  label="${C_YEL}À VÉRIFIER${C_RST}" ;;
            unused) label="${C_RED}INUTILISÉE${C_RST}" ;;
        esac

        mods=()
        for p in ${PKGS[$v]}; do
            case "$p" in
                libapache2-mod-php*) mods+=("mod_php") ;;
                "php$v")             mods+=("php$v") ;;
                *)                   mods+=("${p#php"$v"-}") ;;
            esac
        done
        n=${#mods[@]}

        echo
        echo "${C_BLD}PHP $v${C_RST}  [$label]  ($n paquets)"
        [[ -n "${USED[$v]:-}"  ]] && printf '%s' "${USED[$v]}"
        [[ -n "${CHECK[$v]:-}" ]] && printf '%s' "${C_YEL}${CHECK[$v]}${C_RST}"
        [[ -n "${INFO[$v]:-}"  ]] && printf '%s' "${C_DIM}${INFO[$v]}${C_RST}"
        echo "  Modules :"
        printf '%s\n' "${mods[@]}" | paste -sd ' ' - | fold -s -w 90 | sed 's/^/    /'
    done

    echo
    echo "${C_DIM}UTILISÉE : référencée par Apache, Virtualmin, le CLI ou un cron."
    echo "À VÉRIFIER : pool FPM ou unité systemd sans usage confirmé."
    echo "INUTILISÉE : aucune référence trouvée.${C_RST}"
}


# ============================================================
# Désinstallation
# ============================================================

confirm_yes() {
    local ans
    read -rp "$1 [o/N] " ans
    [[ "$ans" =~ ^[oOyY]$ ]]
}

remove_versions() {
    local versions=("$@")
    local action="remove"
    (( PURGE )) && action="purge"

    local v p st need_strong=0
    local pkgs=()
    declare -A wanted=()

    for v in "${versions[@]}"; do
        for p in ${PKGS[$v]}; do
            pkgs+=("$p")
            wanted[$p]=1
        done
        st="$(status_of "$v")"
        [[ "$st" != unused ]] && need_strong=1
    done

    if (( ${#versions[@]} == ${#VERSIONS[@]} )); then
        echo "${C_RED}ATTENTION : cela retire TOUTES les versions PHP du serveur.${C_RST}"
        need_strong=1
    fi

    # Simulation : montre tout ce qu'apt retirerait réellement,
    # y compris les méta-paquets non versionnés (php, php-mysql...)
    echo
    echo "Simulation : apt-get $action (${#pkgs[@]} paquets, PHP ${versions[*]})"

    local sim
    if ! sim="$(apt-get -s "$action" "${pkgs[@]}" 2>&1)"; then
        echo "${C_RED}La simulation a échoué :${C_RST}"
        tail -n 20 <<< "$sim"
        return 1
    fi

    local removed=() extras=() r
    mapfile -t removed < <(awk '/^(Remv|Purg) / {print $2}' <<< "$sim")

    for r in "${removed[@]}"; do
        [[ -n "${wanted[$r]:-}" ]] || extras+=("$r")
    done

    echo "Paquets retirés : ${#removed[@]}"
    printf '%s\n' "${removed[@]}" | paste -sd ' ' - | fold -s -w 90 | sed 's/^/    /'

    if (( ${#extras[@]} )); then
        echo
        echo "${C_RED}Paquets supplémentaires retirés par dépendance :${C_RST}"
        printf '%s\n' "${extras[@]}" | paste -sd ' ' - | fold -s -w 90 | sed 's/^/    /'
        echo "${C_DIM}(souvent des méta-paquets non versionnés liés à la version par défaut)${C_RST}"
    fi

    if (( need_strong )); then
        echo
        echo "${C_YEL}Au moins une version est marquée UTILISÉE ou À VÉRIFIER :${C_RST}"
        for v in "${versions[@]}"; do
            [[ -n "${USED[$v]:-}${CHECK[$v]:-}" ]] || continue
            echo "  PHP $v"
            printf '%s' "${USED[$v]:-}" "${CHECK[$v]:-}"
        done
        local ans
        read -rp "Pour confirmer, tape exactement « ${versions[*]} » : " ans
        if [[ "$ans" != "${versions[*]}" ]]; then
            echo "Annulé."
            return 0
        fi
    else
        confirm_yes "Désinstaller PHP ${versions[*]} ?" || { echo "Annulé."; return 0; }
    fi

    if (( DRY_RUN )); then
        echo "[DRY-RUN] Aucun paquet n'a été désinstallé."
        return 0
    fi

    log "apt-get $action PHP ${versions[*]} : ${pkgs[*]}"

    if ! DEBIAN_FRONTEND=noninteractive apt-get -y "$action" "${pkgs[@]}"; then
        log "ERREUR : apt-get $action a échoué pour PHP ${versions[*]}"
        return 1
    fi

    log "PHP ${versions[*]} désinstallé ($action)"

    if [[ "$action" == "remove" ]]; then
        for v in "${versions[@]}"; do
            [[ -d "/etc/php/$v" ]] && echo "${C_DIM}Configuration conservée : /etc/php/$v (relancer avec --purge pour la supprimer)${C_RST}"
        done
    fi

    # Apache toujours valide ?
    if command -v apache2ctl >/dev/null 2>&1; then
        if apache2ctl configtest >/dev/null 2>&1; then
            echo "${C_GRN}Configuration Apache : OK${C_RST}"
        else
            echo "${C_RED}Configuration Apache en erreur :${C_RST}"
            apache2ctl configtest 2>&1 | tail -n 10
        fi
    fi

    # CLI par défaut
    if [[ -e /usr/bin/php ]]; then
        echo "CLI par défaut : $(readlink -f /usr/bin/php)"
    else
        echo "${C_YEL}Plus aucun binaire /usr/bin/php.${C_RST}"
    fi

    # Dépendances devenues inutiles
    local auto=()
    mapfile -t auto < <(apt-get -s autoremove 2>/dev/null | awk '/^Remv / {print $2}')
    if (( ${#auto[@]} )); then
        echo
        echo "Dépendances devenues inutiles (${#auto[@]}) :"
        printf '%s\n' "${auto[@]}" | paste -sd ' ' - | fold -s -w 90 | sed 's/^/    /'
        if confirm_yes "Lancer apt-get autoremove ?"; then
            DEBIAN_FRONTEND=noninteractive apt-get -y autoremove
            log "autoremove : ${auto[*]}"
        fi
    fi
}


# ============================================================
# Menu
# ============================================================

menu() {
    local choice unused=()

    while true; do
        scan
        report

        (( ${#VERSIONS[@]} )) || return 0

        mapfile -t unused < <(unused_versions)

        echo
        echo "${C_BLD}Actions${C_RST}$( (( DRY_RUN )) && echo " ${C_YEL}[DRY-RUN]${C_RST}" )$( (( PURGE )) && echo " ${C_YEL}[PURGE]${C_RST}" )"
        if (( ${#unused[@]} )); then
            echo "  a      désinstaller toutes les versions inutilisées : ${unused[*]}"
        else
            echo "  ${C_DIM}a      (aucune version inutilisée)${C_RST}"
        fi
        echo "  X.Y    désinstaller une version précise (ex. ${VERSIONS[0]})"
        echo "  q      quitter"
        read -rp "> " choice

        case "$choice" in
            q|Q)
                return 0
                ;;
            a|A)
                if (( ${#unused[@]} )); then
                    remove_versions "${unused[@]}"
                else
                    echo "Aucune version inutilisée."
                fi
                ;;
            "")
                continue
                ;;
            *)
                if [[ "$choice" =~ ^[0-9]+\.[0-9]+$ ]] && [[ -n "${PKGS[$choice]:-}" ]]; then
                    remove_versions "$choice"
                else
                    echo "Version inconnue : $choice"
                fi
                ;;
        esac

        echo
        read -rp "Entrée pour rescanner..." _
    done
}


# ============================================================
# Main
# ============================================================

if (( REPORT_ONLY )); then
    scan
    report
    exit 0
fi

menu
