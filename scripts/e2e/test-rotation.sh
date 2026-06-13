N="rot/$(date +%s%N)"

created=$(admin_post api1 /v1/secrets \
    "{\"name\":\"$N\",\"kind\":\"automatic\",\"value\":\"orig\",\"rotation_interval_secs\":1,\"grace_period_secs\":300}")
old=$(jget "$created" .value)
check "automatic secret created at version 1" test "$(jget "$created" .version)" = "1"

rotated=$(admin_post api1 "/v1/secrets/$N/rotate" "{}")
new=$(jget "$rotated" .value)
check "manual rotate bumps to version 2" test "$(jget "$rotated" .version)" = "2"
check "rotate produces a new value" test "$new" != "$old"

old_ok=$(verify_value api1 "/v1/secrets/$N" "$old")
check "old value still valid within grace window" test "$(jget "$old_ok" .valid)" = "true"
check "old value resolves to version 1" test "$(jget "$old_ok" .version)" = "1"

new_ok=$(verify_value api1 "/v1/secrets/$N" "$new")
check "new value valid" test "$(jget "$new_ok" .valid)" = "true"
check "new value resolves to version 2" test "$(jget "$new_ok" .version)" = "2"

bad=$(verify_value api1 "/v1/secrets/$N" "definitely-not-the-secret")
check "wrong value is reported invalid" test "$(jget "$bad" .valid)" = "false"

sleep 2
psql_node1 "SELECT vault.enqueue_due_rotations()" >/dev/null
ver=0
for _ in $(seq 1 40); do
    ver=$(read_get api1 "/v1/secrets/$N" | jq -r '.version')
    [ "$ver" -ge 3 ] && break
    sleep 1
done
check "rotation worker advanced version via the queue (>=3)" test "$ver" -ge 3
