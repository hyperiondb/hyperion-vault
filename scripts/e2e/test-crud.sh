N="crud/$(date +%s%N)"

created=$(admin_post api1 /v1/secrets "{\"name\":\"$N\",\"kind\":\"manual\",\"value\":\"v1\"}")
check "create returns the stored value" test "$(jget "$created" .value)" = "v1"
check "create reports version 1" test "$(jget "$created" .version)" = "1"

got=$(read_get api1 "/v1/secrets/$N")
check "get returns v1" test "$(jget "$got" .value)" = "v1"

upd=$(admin_put api1 "/v1/secrets/$N" '{"value":"v2"}')
check "update reports version 2" test "$(jget "$upd" .version)" = "2"

got2=$(read_get api1 "/v1/secrets/$N")
check "get returns v2 after update" test "$(jget "$got2" .value)" = "v2"

check "delete returns 204" test "$(status_delete_auth api1 "/v1/secrets/$N")" = "204"
check "get after delete returns 404" test "$(status_get api1 "/v1/secrets/$N")" = "404"
