#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CONFIG_FILE="$ROOT_DIR/wrangler.toml"
if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "wrangler.toml not found at $CONFIG_FILE" >&2
  exit 1
fi

get_current_id() {
  perl -0777 -ne '
    if (/\[\[kv_namespaces\]\](?:(?!\[\[).)*?binding\s*=\s*"CONFIG"(?:(?!\[\[).)*?\nid\s*=\s*"([^"]+)"/s) {
      print $1;
    }
  ' "$CONFIG_FILE"
}

id_exists() {
  local lookup_id="$1"
  local list_json
  list_json="$(npm exec wrangler kv namespace list -- --json)"
  ID="$lookup_id" printf "%s" "$list_json" | perl -MJSON::PP -e '
    my $id = $ENV{ID};
    my $raw = do { local $/; <STDIN> };
    my $arr = eval { decode_json($raw) } || [];
    my $found = 0;
    for my $ns (@$arr) {
      if (defined $ns->{id} && $ns->{id} eq $id) { $found = 1; last; }
    }
    print $found ? "1" : "0";
  '
}

set_config_id() {
  local new_id="$1"
  NEW_ID="$new_id" perl -0777 -i -pe '
    my $id = $ENV{NEW_ID};
    my $replacement = "[[kv_namespaces]]\nbinding = \"CONFIG\"\nid = \"$id\"\n";
    if (!s/\[\[kv_namespaces\]\]\n(?:(?!\[\[).)*?binding\s*=\s*\"CONFIG\"\n(?:(?!\[\[).)*?/$replacement/s) {
      $_ .= "\n$replacement";
    }
  ' "$CONFIG_FILE"
}

worker_name="$(awk -F'"' '/^name\s*=/{print $2; exit}' "$CONFIG_FILE")"
if [[ -z "${worker_name}" ]]; then
  worker_name="api-transform-proxy"
fi
namespace_title="${worker_name}-CONFIG"

current_id="$(get_current_id || true)"
if [[ -n "$current_id" ]]; then
  if [[ "$(id_exists "$current_id")" == "1" ]]; then
    echo "CONFIG KV namespace exists: $current_id"
    exit 0
  fi
  echo "CONFIG KV namespace id in wrangler.toml no longer exists: $current_id"
fi

echo "Creating KV namespace: $namespace_title"
create_json="$(npm exec wrangler kv namespace create "$namespace_title" -- --json)"
new_id="$(printf "%s" "$create_json" | perl -MJSON::PP -e 'my $raw = do { local $/; <STDIN> }; my $obj = decode_json($raw); print($obj->{id} // "");')"
if [[ -z "$new_id" ]]; then
  echo "Failed to parse new KV namespace id from wrangler output" >&2
  exit 1
fi

set_config_id "$new_id"
echo "Updated wrangler.toml CONFIG id -> $new_id"
