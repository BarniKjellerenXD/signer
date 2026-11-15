#!/bin/bash
# Smoke test against a running instance with a FAKE identity (self-made CA, not Apple).
# Usage: OWNER_LOGIN=owner@example tests/smoke.sh http://127.0.0.1:18080 /path/to/test.ipa
#   (the container must run with OWNER_LOGINS=<same login>; never point this at a live data dir, it imports a fake p12)
# Proves: upload -> zsign -> manifest -> download, p12/profile import, enroll callback, ASC key error path, CSRF guard.
set -u
B=${1:-http://127.0.0.1:18080}; IPA=${2:?ipa}
W=$(mktemp -d); cd "$W"
OWN=(-H "Tailscale-User-Login: ${OWNER_LOGIN:-owner@example}")
pass=0; fail=0
ok() { echo "PASS $*"; pass=$((pass+1)); }
no() { echo "FAIL $*"; fail=$((fail+1)); }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
p() { echo "$1" | sed -E 's#^https://[^/]+##'; }   # strip scheme+host from an absolute URL

# fake CA + "Apple Distribution" cert + ad hoc wildcard profile
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 30 -subj "/CN=Fake WWDR CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" 2>/dev/null
openssl req -new -newkey rsa:2048 -nodes -keyout key.pem -out req.csr \
  -subj "/UID=ABCDE12345/CN=Apple Distribution: Test Person (ABCDE12345)/OU=ABCDE12345/O=Test Person/C=NO" 2>/dev/null
printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning\n" > ext.cnf
openssl x509 -req -in req.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out cert.pem -days 30 -extfile ext.cnf 2>/dev/null
openssl x509 -in cert.pem -outform der -out cert.der
python3 - <<'EOF'
import plistlib, datetime, uuid
now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
p = {"AppIDName": "Wildcard", "CreationDate": now, "DeveloperCertificates": [open('cert.der', 'rb').read()],
     "Entitlements": {"application-identifier": "ABCDE12345.*", "com.apple.developer.team-identifier": "ABCDE12345",
                      "get-task-allow": False, "keychain-access-groups": ["ABCDE12345.*"]},
     "ExpirationDate": now + datetime.timedelta(days=30), "Name": "Test AdHoc", "Platform": ["iOS"],
     "ProvisionedDevices": ["00008110-000A1B2C3D4E5F60"], "TeamIdentifier": ["ABCDE12345"], "TeamName": "Test Person",
     "UUID": str(uuid.uuid4()).upper(), "Version": 1}
open('prof.plist', 'wb').write(plistlib.dumps(p))
open('dev.plist', 'wb').write(plistlib.dumps({"UDID": "00008110-000A1B2C3D4E5F61", "PRODUCT": "iPhone14,3", "VERSION": "22A100"}))
EOF
openssl cms -sign -in prof.plist -signer cert.pem -inkey key.pem -outform der -nodetach -binary -out test.mobileprovision
openssl pkcs12 -export -inkey key.pem -in cert.pem -certfile ca.pem -out test.p12 -passout pass:test 2>/dev/null
openssl cms -sign -in dev.plist -signer cert.pem -inkey key.pem -outform der -nodetach -binary -out dev.p7

# 1 access control
[ "$(code $B/)" = 200 ] && ok "index 200" || no "index"
[ "$(code $B/setup)" = 403 ] && ok "setup 403 without owner header" || no "setup not protected"
[ "$(code "${OWN[@]}" $B/setup)" = 200 ] && ok "setup 200 for owner" || no "setup owner"
[ "$(code -X POST -H 'Origin: https://evil.example' $B/resign-all)" = 403 ] && ok "cross-site POST blocked" || no "csrf"

# 2 upload before identity -> waiting
loc=$(curl -s -o /dev/null -w '%{redirect_url}' -F "ipa=@$IPA" $B/upload); AID1=${loc##*/}
sleep 2; curl -s $B/app/$AID1 | grep -q 'Waiting' && ok "upload without identity -> waiting ($AID1)" || no "waiting state"

# 3 import p12 + profile -> auto re-sign
r=$(curl -s -o /dev/null -w '%{redirect_url}' "${OWN[@]}" -F p12=@test.p12 -F password=test -F profile=@test.mobileprovision $B/setup/p12)
echo "   import -> $r"
for i in $(seq 30); do s=$(curl -s $B/api/status | python3 -c "import json,sys;print(json.load(sys.stdin)['apps'].get('$AID1'))"); [ "$s" = signed ] && break; sleep 1; done
[ "$s" = signed ] && ok "signed after identity import" || no "sign status=$s"

# 4 manifest + download + verify
page=$(curl -s $B/app/$AID1)
itms=$(echo "$page" | grep -o 'itms-services://[^"]*' | head -1 | sed 's/&amp;/\&/g')
murl=$(python3 -c "import urllib.parse,sys;print(urllib.parse.parse_qs(urllib.parse.urlparse(sys.argv[1]).query)['url'][0])" "$itms")
mpath=$(p "$murl")
curl -s $B$mpath > manifest.plist
python3 -c "import plistlib;m=plistlib.load(open('manifest.plist','rb'));i=m['items'][0];print('   manifest:',i['metadata'],[a['url'] for a in i['assets']])"
ipaurl=$(python3 -c "import plistlib;print(plistlib.load(open('manifest.plist','rb'))['items'][0]['assets'][0]['url'])")
curl -s -o signed.ipa $B$(p "$ipaurl")
unzip -p signed.ipa 'Payload/*.app/embedded.mobileprovision' > emb.mp 2>/dev/null
cmp -s emb.mp test.mobileprovision && ok "signed IPA embeds our profile" || no "embedded profile mismatch"
zsign -C signed.ipa 2>/dev/null | grep -q 'Test Person' && ok "signature is ours (zsign -C)" || { command -v zsign >/dev/null || echo "   (no zsign on host, skipped -C)"; }
[ "$(curl -s -o /dev/null -w '%{http_code}' -r 0-99 $B$(p "$ipaurl"))" = 206 ] && ok "range requests 206" || no "range"
[ "$(code $B/i/$AID1.png)" = 200 ] && ok "icon 200" || no "icon"

# 5 options: new bundle id + name
loc=$(curl -s -o /dev/null -w '%{redirect_url}' -F "ipa=@$IPA" -F bundle_id=com.test.renamed -F name=Renamed -F rm_extensions=on $B/upload); AID2=${loc##*/}
for i in $(seq 30); do s=$(curl -s $B/api/status | python3 -c "import json,sys;print(json.load(sys.stdin)['apps'].get('$AID2'))"); [ "$s" = signed ] && break; sleep 1; done
curl -s $B/app/$AID2 | grep -q 'com.test.renamed' && ok "bundle id override applied" || no "bundle override ($s)"

# 6 junk upload rejected
echo notazip > junk.ipa
loc=$(curl -s -o /dev/null -w '%{redirect_url}' -F "ipa=@junk.ipa" $B/upload); AID3=${loc##*/}
curl -s $B/app/$AID3 | grep -q 'an .ipa (not a zip' && ok "junk upload rejected" || no "junk"

# 7 enroll
curl -s -D h.txt -o enroll.mobileconfig "$B/enroll/profile?name=Test%20Phone" >/dev/null
grep -qi 'application/x-apple-aspen-config' h.txt && ok "mobileconfig content-type" || no "mobileconfig ct"
cb=$(python3 -c "import plistlib;print(plistlib.load(open('enroll.mobileconfig','rb'))['PayloadContent']['URL'])")
cbpath=$(p "$cb")
out=$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -X POST --data-binary @dev.p7 -H 'Content-Type: application/pkcs7-signature' $B$cbpath)
echo "   callback -> $out"
[ "${out%% *}" = 301 ] && ok "enroll callback 301" || no "enroll callback"
curl -s $B/devices | grep -q '00008110-000A1B2C3D4E5F61' && ok "device listed" || no "device list"
done_path=$(echo "$out" | awk '{print $2}'); curl -s $B$(p "$done_path") | grep -q '00008110-000A1B2C3D4E5F61' && ok "done page shows UDID" || no "done page"
[ "$(code -X POST --data-binary @dev.p7 $B/enroll/cb/bogus)" = 400 ] && ok "bogus enroll token rejected" || no "token check"

# 8 ASC key error path (random EC key -> Apple must answer 401)
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt > AuthKey_TEST.p8
r=$(curl -s -o /dev/null -w '%{redirect_url}' "${OWN[@]}" -F issuer_id=57246542-96fe-1a63-e053-0824d011072a -F key_id=2X9R4HXF34 -F p8=@AuthKey_TEST.p8 $B/setup/asc)
python3 -c "import urllib.parse,sys;print('   asc ->',urllib.parse.unquote_plus(sys.argv[1].split('?',1)[1]))" "$r"
echo "$r" | grep -q 'Apple+API+401' && ok "Apple rejects fake key with 401 (JWT+network path works)" || no "asc path"

# 9 p12 export roundtrip
curl -s "${OWN[@]}" -F password=hunter22 -o out.p12 $B/setup/export-p12
openssl pkcs12 -in out.p12 -passin pass:hunter22 -nokeys -legacy 2>/dev/null | grep -q 'Test Person' && ok "exported p12 opens (legacy 3DES)" || \
 { openssl pkcs12 -in out.p12 -passin pass:hunter22 -nokeys 2>/dev/null | grep -q 'Test Person' && ok "exported p12 opens" || no "p12 export"; }

# cleanup apps
for a in $AID1 $AID2 $AID3; do curl -s -o /dev/null -X POST $B/app/$a/delete; done
echo "== $pass passed, $fail failed"; rm -rf "$W"
