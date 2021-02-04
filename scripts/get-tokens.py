#!/usr/bin/python

import os
import re
import json

authorize_cmd = "curl -v 'http://oidc.example.com:9000/auth/authorize?" \
                "client_id=example-backend&" \
                "response_type=code&" \
                "scope=openid&" \
                "redirect_uri=https%3A%2F%2Fexample.com&" \
                "email=eugene%2B10%40gokernel.com&" \
                "password=11111111' 2>&1"
code = re.findall(r'code=([\w-]+)', os.popen(authorize_cmd).read())[0]

token_cmd = "curl -v 'http://oidc.example.com:9000/auth/token' " \
            "-H 'Authorization: Basic ZXhhbXBsZS1iYWNrZW5kOkV4QW1QbEUkMjIx' " \
            "--data-urlencode 'code=%s' " \
            "--data-urlencode 'grant_type=authorization_code' " \
            "--data-urlencode 'redirect_uri=https://example.com' 2>&1" % code
token_cmd_output = os.popen(token_cmd).read()
token_response = json.loads(re.findall(r'{[^{}]*}', token_cmd_output)[0])

print "ACCESS TOKEN:\n%s\n" % token_response["access_token"]
print "ID TOKEN:\n%s\n" % token_response["id_token"]
