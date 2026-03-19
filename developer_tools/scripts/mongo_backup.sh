#!/usr/bin/env bash
set -euo pipefail

CONTAINER="vc_mongo"
DB="verifier"
COLLECTION="clients"
FILE="oidc_dump.json"

usage() {
    echo "Usage: $0 [export|import] [options]"
    echo
    echo "Commands:"
    echo "  export    Export collection to JSON file"
    echo "  import    Import JSON file into collection"
    echo
    echo "Options:"
    echo "  -c, --container NAME    Docker container name (default: ${CONTAINER})"
    echo "  -d, --db NAME           Database name (default: ${DB})"
    echo "  -C, --collection NAME   Collection name (default: ${COLLECTION})"
    echo "  -f, --file PATH         JSON file path (default: ${FILE})"
    echo "  --drop                  Drop collection before import"
    echo "  -h, --help              Show this help message"
    exit 1
}

CMD="${1:-}"
[[ -z "$CMD" ]] && usage
shift

DROP=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -c|--container)  CONTAINER="$2"; shift 2 ;;
        -d|--db)         DB="$2"; shift 2 ;;
        -C|--collection) COLLECTION="$2"; shift 2 ;;
        -f|--file)       FILE="$2"; shift 2 ;;
        --drop)          DROP=true; shift ;;
        -h|--help)       usage ;;
        *)               echo "Unknown option: $1"; usage ;;
    esac
done

case "$CMD" in
    export)
        echo "Exporting ${DB}.${COLLECTION} from ${CONTAINER} -> ${FILE}"
        docker exec -t "$CONTAINER" mongoexport -d "$DB" -c "$COLLECTION" --pretty > "$FILE"
        echo "Done. Exported to ${FILE}"
        ;;
    import)
        if [[ ! -f "$FILE" ]]; then
            echo "Error: file '${FILE}' not found"
            exit 1
        fi

        echo "Copying ${FILE} into ${CONTAINER}:/tmp/"
        docker cp "$FILE" "${CONTAINER}:/tmp/${FILE##*/}"

        IMPORT_ARGS=(--db "$DB" --collection "$COLLECTION" --file "/tmp/${FILE##*/}")
        if [[ "$DROP" == true ]]; then
            IMPORT_ARGS+=(--drop)
        fi

        echo "Importing /tmp/${FILE##*/} -> ${DB}.${COLLECTION}"
        docker exec -t "$CONTAINER" mongoimport "${IMPORT_ARGS[@]}"
        echo "Done."
        ;;
    *)
        echo "Unknown command: ${CMD}"
        usage
        ;;
esac
