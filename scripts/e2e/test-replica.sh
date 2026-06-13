N="replica/$(date +%s%N)"

admin_post api2 /v1/secrets "{\"name\":\"$N\",\"kind\":\"manual\",\"value\":\"replicated\"}" >/dev/null
check "write via api2 is accepted (routed to the primary)" test "$?" = "0"

sleep 3

for h in api1 api2 api3; do
    value=$(read_get "$h" "/v1/secrets/$N" 2>/dev/null | jq -r '.value' 2>/dev/null)
    check "read of '$N' via $h sees the replicated value" test "$value" = "replicated"
done
