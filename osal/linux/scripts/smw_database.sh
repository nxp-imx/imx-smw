#!/bin/bash

set -euo pipefail

DEFAULT_DATABASE=/usr/share/smw/smw_objects_database.dat

opt_help=0
opt_get_version=0
opt_migrate=0
opt_database=$DEFAULT_DATABASE

if [ "$#" -eq 0 ]; then
    opt_help=1
else
    while [ $# -gt 0 ];
    do
        case "$1" in
        -h|--help)
            opt_help=1
            break
            ;;
        -d|--database)
            if [ $# -eq 1 ]; then
                echo "No database specified"
                exit 1
            fi
            opt_database="$2"
            shift 2
            ;;
        -g|--get-version)
            opt_get_version=1
            shift
            ;;
        -m|--migrate)
            opt_migrate=1
            shift
            ;;
        *)
            break
            ;;
        esac
    done
fi

if [ "$opt_help" -eq 1 ]; then
    echo "Usage: $0 [-g|--get-version] [-m|--migrate] [-d|--database filename]"
    echo "  -g|--get-version: Get the current version of the database"
    echo "  -m|--migrate    : Run database migrations up to the current version"
    echo "  -d|--database   : Database file [default: $DEFAULT_DATABASE]"

    exit 0
fi

if [ ! -f "$opt_database" ]; then
    echo "Database file not found: $opt_database"
    exit 1
fi

echo "Using database: $opt_database"

if [ "$opt_get_version" -eq 1 ]; then
    sqlite3 "$opt_database" <<< "PRAGMA user_version;"
fi

migrate_nop() {
    echo "NOP migration"
}

migrate_1_to_2() {
    echo "Migrating to version 2, adding new column"

    sqlite3 "$opt_database" <<EOF
BEGIN TRANSACTION;
ALTER TABLE OBJECTS ADD COLUMN "0xF" BLOB;
PRAGMA user_version = 2;
COMMIT;
EOF
}

declare -a migration_functions=(
    migrate_nop
    migrate_1_to_2
)

if [ "$opt_migrate" -eq 1 ]; then
    version=$(sqlite3 "$opt_database" <<< "PRAGMA user_version;")

    if [ "$version" -ge "${#migration_functions[@]}" ]; then
        echo "Database is up-to-date."
        exit 0
    fi

    echo "Migrating database - the database will be modified."
    read -p "Continue? [y/N] " yn

    case $yn in
        [Yy]*)
            echo "Migrating database";

            while [ "$version" -lt "${#migration_functions[@]}" ];
            do
                ${migration_functions[$version]}
                version=$((version + 1))
            done
            ;;
        *)
            echo "Exiting"
            exit 0
            ;;
    esac
fi
