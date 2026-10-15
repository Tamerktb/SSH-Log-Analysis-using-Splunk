#!/bin/bash
# Regression tests for the four custom ElastAlert 2 rule types (ssh_ruletypes.py).
#
# ElastAlert's `--data` mode mocks the Elasticsearch query layer and feeds a JSON
# fixture straight into rule.add_data(), so this exercises the rule LOGIC only
# (windowing, distinct/total counting, failed-then-success pairing, haversine) with
# no cluster, no network and no data pollution. The ES filters / ingest pipeline are
# covered by the real-data run documented in ../README.md.
#
# Usage (on the lab VM, from anywhere):
#   bash /home/ubuntu/elk/elastalert2/tests/run_tests.sh
#
# Requires: docker + the jertel/elastalert2 image, and DIR below pointing at the
# deployed elastalert2 folder (config.yaml, rules/, ssh_ruletypes.py, tests/).
DIR=${ELASTALERT_DIR:-/home/ubuntu/elk/elastalert2}
IMG=${ELASTALERT_IMAGE:-jertel/elastalert2:latest}
NET=${ELASTALERT_NET:-elk_default}

RUN="docker run --rm --network $NET --entrypoint elastalert-test-rule -w /opt/elastalert \
  -v $DIR/config.yaml:/opt/elastalert/config.yaml:ro \
  -v $DIR/rules:/opt/elastalert/rules:ro \
  -v $DIR/tests:/opt/elastalert/tests:ro \
  -v $DIR/ssh_ruletypes.py:/opt/elastalert/ssh_ruletypes.py:ro \
  $IMG --config /opt/elastalert/config.yaml --alert"

fail=0
check() {  # check <rule file> <fixture> <expected matches> <description>
  rule=$1; data=$2; want=$3; desc=$4
  out=$($RUN --data "/opt/elastalert/tests/$data" "/opt/elastalert/rules/$rule" 2>&1)
  got=$(echo "$out" | grep -oE "'matches': [0-9]+" | head -1 | grep -oE "[0-9]+")
  got=${got:-none}
  if [ "$got" = "$want" ]; then
    echo "PASS  matches=$got  $desc"
  else
    echo "FAIL  matches=$got (expected $want)  $desc"
    echo "----- rule output -----"
    echo "$out" | tail -30
    echo "-----------------------"
    fail=1
  fi
  # Also fail loudly if the rule blew up instead of running.
  if echo "$out" | grep -qiE "Traceback|Invalid rules|Unknown rule"; then
    echo "FAIL  $desc - rule raised an exception"
    echo "$out" | grep -iE "Traceback|Error|line [0-9]+" | head -12
    fail=1
  fi
}

echo "ElastAlert 2 custom rule-type tests ($DIR)"
check 02-ssh-distributed-brute-force.yaml data-02-distributed.json          1 "8 source IPs / 20 attempts on one account"
check 03-ssh-credential-stuffing.yaml     data-03-stuffing.json             1 "1 source IP / 15 distinct accounts in 2 min"
check 04-ssh-brute-force-success.yaml     data-04-brute-force-success.json  1 "6 failures then an accepted login, same src+account"
check 05-ssh-impossible-travel.yaml       data-05-impossible-travel.json    1 "Cape Town -> New York in 30 min (and NY->NY must not fire)"

if [ "$fail" = "0" ]; then echo "ALL TESTS PASSED"; else echo "SOME TESTS FAILED"; fi
exit $fail
