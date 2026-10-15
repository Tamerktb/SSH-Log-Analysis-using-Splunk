#!/usr/bin/env python3
"""
ssh_ruletypes.py - ElastAlert 2 custom rule types for the SSHLogAnalysis ELK port.

Four of the nine Splunk correlation searches cannot be expressed with ElastAlert 2's
built-in rule types: Splunk's `stats` computes a DISTINCT count and a TOTAL count in
one pass (ElastAlert 2's CardinalityRule only tracks distinct values), and Impossible
Travel needs geo arithmetic (haversine) that Elasticsearch cannot evaluate in a query.

    SSH - Distributed Brute Force   dc(src_ip)>=8  AND count>=20  by target_user
    SSH - Credential Stuffing       dc(target_user)>=15 AND count>=20 by src_ip
    SSH - Successful Brute Force    failures>=5 AND successes>0, per src_ip + account
    SSH - Impossible Travel         2 accepted logins, >=500 km apart, <=1 h

A rule selects one of these with the dotted form (loaders.load_modules -> util.get_module):

    type: ssh_ruletypes.SshCredentialStuffing

util.get_module() appends os.getcwd() to sys.path and the elastalert2 image runs with
WORKDIR /opt/elastalert, so this file has to be readable as
/opt/elastalert/ssh_ruletypes.py - docker-compose.elastalert2.yml mounts it there.

ElastAlert 2 2.31.0 API used here:
  * RuleType.add_data(data) receives a LIST of events, timestamp_field already
    converted to a datetime by the loader.
  * lookup_es_key(event, 'a.b.c') -> value of a dotted field.
  * EventWindow(timeframe, getTimestamp) -> .append((event, count)), .count(),
    .data (SortedKeyList of (event, count) tuples), .clear().
  * add_match(event) records an alert for this event.
  * required_options is enforced as: required - set(rule.keys()) must be empty, so
    every option listed there has to exist in the rule YAML.
"""
from datetime import timedelta

from elastalert.ruletypes import EventWindow, RuleType
from elastalert.util import hashable, lookup_es_key, new_get_event_ts

EARTH_RADIUS_KM = 6371.0
FAILED_ACTIONS = ['ssh_login_failed', 'ssh_pam_failure']
SUCCESS_ACTIONS = ['ssh_login']


def haversine_km(lat1, lon1, lat2, lon2):
    """Great-circle distance in km between two WGS84 points."""
    import math

    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2.0) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2.0) ** 2
    return 2.0 * EARTH_RADIUS_KM * math.asin(min(1.0, math.sqrt(a)))


def geo_point(event, field):
    """(lat, lon) from an Elasticsearch geo_point field, else None.

    The ingest pipeline maps source.geo via the geoip processor with
    `location` in `properties`, so the indexed shape is
    {'city_name': .., 'country_iso_code': .., 'location': {'lat': .., 'lon': ..}}.
    A bare geo_point field ({'lat':..,'lon':..}) is accepted too.
    """
    value = lookup_es_key(event, field)
    if isinstance(value, dict):
        lat, lon = value.get('lat'), value.get('lon')
        if lat is None or lon is None:
            loc = value.get('location')
            if isinstance(loc, dict):
                lat, lon = loc.get('lat'), loc.get('lon')
        if lat is not None and lon is not None:
            return float(lat), float(lon)
    return None


class SshRuleBase(RuleType):
    """Shared windowing boilerplate: one EventWindow per composite group key."""

    def __init__(self, rules, args=None):
        super(SshRuleBase, self).__init__(rules, args)
        self.ts_field = self.rules.get('timestamp_field', '@timestamp')
        self.get_ts = new_get_event_ts(self.ts_field)
        self.windows = {}

    def group_fields(self):
        """Composite grouping key: `group_by` if set, else `query_key`, else 'all'."""
        fields = self.rules.get('group_by') or [self.rules.get('query_key')]
        return [f for f in fields if f]

    def group_key(self, event):
        """Composite grouping key for an event, or None if it cannot be grouped.

        Fails closed when any grouping field is missing: an SSH attack that has no
        source IP or no target account cannot be attributed, so it is not counted
        (verified live - `pam_unix(sshd:auth): authentication failure` lines carry
        rhost but no user=, and grouping them under a null account produced a second,
        meaningless "distributed brute force on (null)" alert for the same burst).
        The Splunk searches group by the same field and emit a null-valued row for
        these events; skipping is the deliberate, documented divergence.
        Set `allow_missing_group_key: true` in a rule to group them anyway.
        """
        fields = self.group_fields()
        if not fields:
            return 'all'
        values = [hashable(lookup_es_key(event, f)) for f in fields]
        if any(v is None for v in values) and not self.rules.get('allow_missing_group_key'):
            return None
        return tuple(values)

    def window(self, key):
        return self.windows.setdefault(key, EventWindow(self.rules['timeframe'], getTimestamp=self.get_ts))

    def garbage_collect(self, timestamp):
        """Drop windows whose most recent event fell out of the timeframe.

        Called by the runner after each query with the newest timestamp seen.
        """
        for key in list(self.windows):
            window = self.windows.get(key)
            if not window or not window.data:
                self.windows.pop(key, None)
                continue
            if timestamp - lookup_es_key(window.data[-1][0], self.ts_field) > self.rules['timeframe']:
                self.windows.pop(key, None)


class SshDistinctCountRule(SshRuleBase):
    """Base: N distinct values AND M total events inside one window (Splunk `stats`)."""

    def add_data(self, data):
        distinct_field = self.rules['distinct_key']
        min_distinct = int(self.rules['min_distinct'])
        min_count = int(self.rules['min_count'])

        for event in data:
            key = self.group_key(event)
            if key is None:
                continue
            window = self.window(key)
            window.append((event, 1))

            distinct = set()
            for ev, _ in window.data:
                value = lookup_es_key(ev, distinct_field)
                if value is not None:
                    distinct.add(hashable(value))

            if len(distinct) >= min_distinct and window.count() >= min_count:
                match = dict(event)
                match['distinct_count'] = len(distinct)
                match['event_count'] = window.count()
                match['distinct_values'] = sorted(str(v) for v in distinct)[:50]
                match['threshold'] = '%s>=%d AND count>=%d' % (distinct_field, min_distinct, min_count)
                self.add_match(match)
                # Reset, otherwise every further event in the window re-fires the rule.
                window.clear()


class SshDistributedBruteForce(SshDistinctCountRule):
    """Many source IPs -> one account. Splunk: dc(src_ip)>=8 AND count>=20 by target_user."""

    def get_match_str(self, match):
        return ('SSH distributed brute force: %s distinct source IPs over %s attempts '
                'against account %s (thresholds %s)\n\n'
                % (match.get('distinct_count'), match.get('event_count'),
                   match.get('user', {}).get('name'), match.get('threshold')))


class SshCredentialStuffing(SshDistinctCountRule):
    """One source IP -> many accounts. Splunk: dc(target_user)>=15 AND count>=20 by src_ip."""

    def get_match_str(self, match):
        return ('SSH credential stuffing: %s hit %s distinct accounts over %s attempts '
                '(thresholds %s)\n\n'
                % (match.get('source', {}).get('ip'), match.get('distinct_count'),
                   match.get('event_count'), match.get('threshold')))


class SshBruteForceSuccess(SshRuleBase):
    """Repeated failures followed by an accepted login.

    Splunk: `ssh_events` | stats sum(is_fail) as failed, sum(is_success) as success
            by src_ip, target_user | where failed>=5 AND success>0
    """

    def add_data(self, data):
        failed_actions = self.rules.get('failed_actions') or FAILED_ACTIONS
        success_actions = self.rules.get('success_actions') or SUCCESS_ACTIONS
        min_failed = int(self.rules['min_failed'])
        min_success = int(self.rules['min_success'])

        for event in data:
            action = lookup_es_key(event, 'event.action')
            if action not in failed_actions and action not in success_actions:
                continue

            key = self.group_key(event)
            if key is None:
                continue
            window = self.window(key)
            window.append((event, 1))

            failed = success = 0
            for ev, _ in window.data:
                ev_action = lookup_es_key(ev, 'event.action')
                if ev_action in failed_actions:
                    failed += 1
                elif ev_action in success_actions:
                    success += 1

            if failed >= min_failed and success >= min_success:
                match = dict(event)
                match['failed_count'] = failed
                match['success_count'] = success
                match['threshold'] = 'failed>=%d AND success>=%d' % (min_failed, min_success)
                self.add_match(match)
                window.clear()


class SshImpossibleTravel(RuleType):
    """Two accepted logins for one account that are faster than a plane.

    Splunk: `ssh_accepted_logins` | iplocation src_ip | sort 0 user_name +_time
            | streamstats current=f window=1 values(lat) values(lon) by user_name
            | eval hours=round((now-prev)/3600, 2)
            | where distance >= 500 AND hours <= 1

    Keeps the previous accepted login per account and compares every new one against it.
    """

    def __init__(self, rules, args=None):
        super(SshImpossibleTravel, self).__init__(rules, args)
        self.ts_field = self.rules.get('timestamp_field', '@timestamp')
        self.geo_field = self.rules.get('geo_field', 'source.geo.location')
        self.min_distance_km = float(self.rules['min_distance_km'])
        self.max_hours = float(self.rules['max_hours'])
        self.state_ttl = timedelta(hours=int(self.rules.get('state_ttl_hours', 24)))
        self.last_login = {}

    def add_data(self, data):
        for event in data:
            account = hashable(lookup_es_key(event, self.rules['query_key']))
            point = geo_point(event, self.geo_field)
            timestamp = lookup_es_key(event, self.ts_field)
            if account is None or point is None or timestamp is None:
                continue

            previous = self.last_login.get(account)
            self.last_login[account] = (timestamp, point)
            if not previous:
                continue

            hours = (timestamp - previous[0]).total_seconds() / 3600.0
            km = haversine_km(previous[1][0], previous[1][1], point[0], point[1])
            if km >= self.min_distance_km and hours <= self.max_hours:
                match = dict(event)
                match['travel_km'] = round(km, 1)
                match['travel_hours'] = round(hours, 3)
                match['travel_kmh'] = round(km / hours, 1) if hours > 0 else None
                match['origin_geo'] = {'lat': previous[1][0], 'lon': previous[1][1]}
                match['threshold'] = 'distance>=%skm AND hours<=%s' % (self.min_distance_km, self.max_hours)
                self.add_match(match)
                # Consumed: the next login starts a fresh comparison from this point.
                self.last_login[account] = None

    def garbage_collect(self, timestamp):
        """Forget accounts that have not logged in for state_ttl_hours."""
        for account in list(self.last_login):
            state = self.last_login.get(account)
            if not state or timestamp - state[0] > self.state_ttl:
                self.last_login.pop(account, None)

    def get_match_str(self, match):
        return ('SSH impossible travel for %s: %s km in %s hours (~%s km/h), %s (thresholds %s)\n\n'
                % (match.get('user', {}).get('name'), match.get('travel_km'),
                   match.get('travel_hours'), match.get('travel_kmh'),
                   match.get('source', {}).get('ip'), match.get('threshold')))
