no_token=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://api1:8200/v1/secrets \
    -H 'content-type: application/json' -d '{"name":"na","kind":"manual","value":"x"}')
check "write without a token is 401" test "$no_token" = "401"

bad_token=$(status_post_auth api1 /v1/secrets "not-a-real-token" \
    '{"name":"na2","kind":"manual","value":"x"}')
check "write with a wrong token is 401" test "$bad_token" = "401"

N="auth/$(date +%s%N)"
ok_token=$(status_post_auth api1 /v1/secrets "$ADMIN_TOKEN" \
    "{\"name\":\"$N\",\"kind\":\"manual\",\"value\":\"x\"}")
check "write with the valid admin token is 201" test "$ok_token" = "201"
