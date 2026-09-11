"""Synthetic lab telemetry.

Two jobs:

* **Normal activity** - the baseline a SIEM spends most of its time on: sign-ins
  and sign-outs, API calls, password changes, permission changes, file and
  object reads.  Used to seed the dashboard and to give the load harness
  realistic shapes.
* **Benign simulations of suspicious sequences** - deterministic, seeded
  reproductions of the *telemetry shape* an attack would leave (a burst of
  failed logons, a success, an escalation, a new token).  Nothing here attacks
  anything: it emits log records into SignalForge's own pipeline so the
  detections can be exercised without touching a real system.

Everything is seeded, so the same seed always produces the same corpus - which
is what makes the load numbers and screenshots reproducible.
"""

from __future__ import annotations

import hashlib
import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterator, List, Optional

from ..models.ocsf import RawLogRecord

HOSTS = ["web-01", "web-02", "prod-api-01", "prod-payments-01", "staging-01"]
USERS = ["alex", "dana", "sam", "priya", "jordan"]
EMAILS = {
    "alex": "alex@example.com",
    "dana": "dana@example.com",
    "sam": "sam@example.com",
    "priya": "priya@example.com",
    "jordan": "jordan@example.com",
}
INTERNAL_IPS = ["10.0.4.82", "10.0.4.91", "10.0.5.20", "10.0.7.14", "192.168.12.30"]
EXTERNAL_IPS = ["203.0.113.24", "198.51.100.77", "203.0.113.90"]
#: Present in the bundled static intel feed, so enrichment has something to say.
FLAGGED_IPS = ["185.220.101.7", "203.0.113.66", "198.51.100.23"]
ENDPOINTS = ["/api/v1/orders", "/api/v1/customers", "/api/v1/reports", "/api/v1/settings"]
RESOURCES = [
    ("internal-wiki", "low"),
    ("billing-export", "high"),
    ("customer-records", "critical"),
    ("prod-payments-db", "critical"),
]
S3_BUCKETS = ["prod-payments-exports", "internal-reports", "customer-archive"]


def _syslog_stamp(moment: datetime) -> str:
    return "%s %2d %s" % (moment.strftime("%b"), moment.day, moment.strftime("%H:%M:%S"))


def _stable_id(prefix: str, value: str) -> str:
    """Deterministic surrogate id.

    ``hash()`` is salted per process, so it cannot be used here: the whole point
    of seeding the generator is that the same seed produces the same corpus.
    """
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return "%s%s" % (prefix, digest[:10])


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class Scenario:
    name: str
    title: str
    description: str
    expected_detections: List[str]
    builder: Callable[..., List[RawLogRecord]] = field(repr=False, default=None)  # type: ignore[assignment]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "expected_detections": list(self.expected_detections),
        }


class TelemetryGenerator:
    def __init__(self, tenant: str = "acme", seed: int = 1337) -> None:
        self.tenant = tenant
        self.random = random.Random(seed)

    # ------------------------------------------------------------------ #
    # Record builders
    # ------------------------------------------------------------------ #
    def sshd(
        self,
        moment: datetime,
        user: str,
        ip: str,
        *,
        success: bool,
        host: str = "web-01",
        method: str = "password",
        port: Optional[int] = None,
    ) -> RawLogRecord:
        port = port or self.random.randint(40000, 65000)
        pid = self.random.randint(1000, 9999)
        verb = "Accepted" if success else "Failed"
        line = "%s %s sshd[%d]: %s %s for %s from %s port %d ssh2" % (
            _syslog_stamp(moment),
            host,
            pid,
            verb,
            method,
            user,
            ip,
            port,
        )
        return RawLogRecord(
            source="linux.sshd",
            tenant=self.tenant,
            raw=line,
            received_at=moment,
            collector="lab-generator",
        )

    def sshd_logout(self, moment: datetime, user: str, host: str = "web-01") -> RawLogRecord:
        line = "%s %s sshd[%d]: pam_unix(sshd:session): session closed for user %s" % (
            _syslog_stamp(moment),
            host,
            self.random.randint(1000, 9999),
            user,
        )
        return RawLogRecord(
            source="linux.sshd",
            tenant=self.tenant,
            raw=line,
            received_at=moment,
            collector="lab-generator",
        )

    def sudo(
        self, moment: datetime, user: str, command: str, host: str = "web-01", target: str = "root"
    ) -> RawLogRecord:
        line = "%s %s sudo: %s : TTY=pts/0 ; PWD=/home/%s ; USER=%s ; COMMAND=%s" % (
            _syslog_stamp(moment),
            host,
            user,
            user,
            target,
            command,
        )
        return RawLogRecord(
            source="linux.sudo",
            tenant=self.tenant,
            raw=line,
            received_at=moment,
            collector="lab-generator",
        )

    def usermod(
        self, moment: datetime, user: str, group: str, host: str = "web-01"
    ) -> RawLogRecord:
        line = "%s %s usermod[%d]: add '%s' to group '%s'" % (
            _syslog_stamp(moment),
            host,
            self.random.randint(1000, 9999),
            user,
            group,
        )
        return RawLogRecord(
            source="linux.usermod",
            tenant=self.tenant,
            raw=line,
            received_at=moment,
            collector="lab-generator",
        )

    def app(self, moment: datetime, action: str, **payload: Any) -> RawLogRecord:
        body: Dict[str, Any] = {
            "action": action,
            "timestamp": _iso(moment),
            "request_id": str(uuid.uuid4()),
            "host": "prod-api-01",
            "service": "lab-app",
        }
        body.update(payload)
        return RawLogRecord(
            source="app.audit",
            tenant=self.tenant,
            payload=body,
            received_at=moment,
            collector="lab-generator",
        )

    def cloudtrail(
        self, moment: datetime, event_name: str, user: str, ip: str, **overrides: Any
    ) -> RawLogRecord:
        payload: Dict[str, Any] = {
            "eventTime": _iso(moment),
            "eventName": event_name,
            "eventSource": "%s.amazonaws.com" % overrides.pop("service", "iam"),
            "awsRegion": "us-east-1",
            "sourceIPAddress": ip,
            "userAgent": "aws-cli/2.15.0",
            "userIdentity": {
                "type": "IAMUser",
                "userName": user,
                "principalId": "AIDAEXAMPLE%s" % user.upper(),
                "accountId": "123456789012",
                "arn": "arn:aws:iam::123456789012:user/%s" % user,
            },
            "eventID": str(uuid.uuid4()),
            "recipientAccountId": "123456789012",
            "readOnly": False,
            "managementEvent": True,
        }
        payload.update(overrides)
        return RawLogRecord(
            source="aws.cloudtrail",
            tenant=self.tenant,
            payload=payload,
            received_at=moment,
            collector="lab-generator",
        )

    def okta(
        self,
        moment: datetime,
        event_type: str,
        actor_email: str,
        ip: str,
        *,
        result: str = "SUCCESS",
        country: str = "US",
        city: str = "Boston",
        target_email: Optional[str] = None,
        **extra: Any,
    ) -> RawLogRecord:
        payload: Dict[str, Any] = {
            "published": _iso(moment),
            "uuid": str(uuid.uuid4()),
            "eventType": event_type,
            "outcome": {"result": result},
            "actor": {
                "alternateId": actor_email,
                "id": _stable_id("usr", actor_email),
                "type": "User",
                "displayName": actor_email.split("@")[0].title(),
            },
            "client": {
                "ipAddress": ip,
                "userAgent": {"rawUserAgent": "Mozilla/5.0", "os": "Mac OS X"},
                "geographicalContext": {"country": country, "city": city},
            },
            "authenticationContext": {"externalSessionId": "sess-%s" % uuid.uuid4().hex[:10]},
        }
        if target_email:
            payload["target"] = [
                {"type": "User", "alternateId": target_email, "id": _stable_id("usr", target_email)}
            ]
        payload.update(extra)
        return RawLogRecord(
            source="okta.system",
            tenant=self.tenant,
            payload=payload,
            received_at=moment,
            collector="lab-generator",
        )

    # ------------------------------------------------------------------ #
    # Normal activity
    # ------------------------------------------------------------------ #
    def normal_activity(
        self,
        count: int = 200,
        start: Optional[datetime] = None,
        *,
        spread_seconds: int = 3600,
    ) -> List[RawLogRecord]:
        """A baseline of routine, benign telemetry."""
        start = start or datetime.now(tz=timezone.utc) - timedelta(seconds=spread_seconds)
        records: List[RawLogRecord] = []
        step = max(spread_seconds / max(count, 1), 0.01)
        for index in range(count):
            moment = start + timedelta(seconds=step * index)
            records.append(self._one_normal(moment))
        return records

    def _one_normal(self, moment: datetime) -> RawLogRecord:
        user = self.random.choice(USERS)
        email = EMAILS[user]
        ip = self.random.choice(INTERNAL_IPS + EXTERNAL_IPS[:1])
        roll = self.random.random()

        if roll < 0.30:
            return self.app(
                moment,
                "api_request",
                user=email,
                ip=ip,
                endpoint=self.random.choice(ENDPOINTS),
                method="GET",
                path=self.random.choice(ENDPOINTS),
                status_code=200,
                session_id="sess-%s" % uuid.uuid4().hex[:8],
            )
        if roll < 0.45:
            return self.sshd(moment, user, ip, success=True, host=self.random.choice(HOSTS))
        if roll < 0.52:
            return self.sshd(moment, user, ip, success=False, host=self.random.choice(HOSTS))
        if roll < 0.58:
            return self.sshd_logout(moment, user)
        if roll < 0.68:
            resource, criticality = self.random.choice(RESOURCES[:2])
            return self.app(
                moment,
                "data_access",
                user=email,
                ip=ip,
                resource=resource,
                resource_criticality=criticality,
                record_count=self.random.randint(1, 40),
            )
        if roll < 0.74:
            return self.app(
                moment,
                "login",
                user=email,
                ip=ip,
                mfa_used=True,
                session_id="sess-%s" % uuid.uuid4().hex[:8],
            )
        if roll < 0.80:
            return self.app(moment, "logout", user=email, ip=ip)
        if roll < 0.85:
            return self.app(moment, "password_change", user=email, ip=ip)
        if roll < 0.90:
            return self.okta(moment, "user.session.start", email, ip)
        if roll < 0.94:
            return self.cloudtrail(
                moment,
                "GetObject",
                user,
                ip,
                service="s3",
                readOnly=True,
                requestParameters={
                    "bucketName": self.random.choice(S3_BUCKETS),
                    "key": "reports/monthly.csv",
                },
            )
        if roll < 0.97:
            return self.sudo(moment, user, "/usr/bin/systemctl status lab-app")
        return self.app(
            moment,
            "http_request",
            user=email,
            ip=ip,
            method="POST",
            path="/api/v1/orders",
            status_code=self.random.choice([200, 201, 400]),
            user_agent="curl/8.4.0",
        )

    # ------------------------------------------------------------------ #
    # Benign attack-shape simulations
    # ------------------------------------------------------------------ #
    def account_compromise(
        self,
        start: Optional[datetime] = None,
        *,
        user: str = "alex",
        ip: str = "185.220.101.7",
        host: str = "prod-api-01",
        failures: int = 9,
    ) -> List[RawLogRecord]:
        """Failed logons -> success -> escalation -> new token -> data access."""
        start = start or datetime.now(tz=timezone.utc) - timedelta(minutes=10)
        email = EMAILS.get(user, "%s@example.com" % user)
        records: List[RawLogRecord] = []
        moment = start
        for _ in range(failures):
            records.append(self.sshd(moment, user, ip, success=False, host=host))
            moment += timedelta(seconds=7)
        moment += timedelta(seconds=20)
        records.append(self.sshd(moment, user, ip, success=True, host=host))
        moment += timedelta(seconds=45)
        records.append(
            self.app(
                moment,
                "role_change",
                user=email,
                target_user=email,
                previous_role="member",
                new_role="admin",
                ip=ip,
                session_id="sess-compromise",
            )
        )
        moment += timedelta(seconds=40)
        records.append(
            self.app(
                moment,
                "api_key_created",
                user=email,
                ip=ip,
                token_id="tok_%s" % uuid.uuid4().hex[:8],
                resource="api-keys",
                resource_criticality="high",
                status_code=201,
                session_id="sess-compromise",
            )
        )
        moment += timedelta(seconds=90)
        records.append(
            self.app(
                moment,
                "data_export",
                user=email,
                ip=ip,
                resource="customer-records",
                resource_criticality="critical",
                data_classification="pii",
                record_count=48000,
                session_id="sess-compromise",
            )
        )
        return records

    def brute_force(
        self,
        start: Optional[datetime] = None,
        *,
        user: str = "admin",
        ip: str = "203.0.113.66",
        attempts: int = 25,
    ) -> List[RawLogRecord]:
        """A password-guessing burst against one account, no success."""
        start = start or datetime.now(tz=timezone.utc) - timedelta(minutes=5)
        records = []
        moment = start
        for _ in range(attempts):
            records.append(self.sshd(moment, user, ip, success=False, host="web-01"))
            moment += timedelta(seconds=4)
        return records

    def impossible_travel(
        self, start: Optional[datetime] = None, *, user: str = "dana"
    ) -> List[RawLogRecord]:
        """One account, two countries, twenty minutes apart."""
        start = start or datetime.now(tz=timezone.utc) - timedelta(minutes=30)
        email = EMAILS.get(user, "%s@example.com" % user)
        return [
            self.okta(
                start, "user.session.start", email, "203.0.113.24", country="US", city="Boston"
            ),
            self.okta(
                start + timedelta(minutes=20),
                "user.session.start",
                email,
                "185.220.101.7",
                country="NL",
                city="Amsterdam",
            ),
        ]

    def cloud_persistence(
        self, start: Optional[datetime] = None, *, user: str = "sam"
    ) -> List[RawLogRecord]:
        """Console sign-in without MFA, then a new access key and a policy attach."""
        start = start or datetime.now(tz=timezone.utc) - timedelta(minutes=8)
        ip = "198.51.100.23"
        return [
            self.cloudtrail(
                start,
                "ConsoleLogin",
                user,
                ip,
                service="signin",
                responseElements={"ConsoleLogin": "Success"},
                additionalEventData={"MFAUsed": "No"},
            ),
            self.cloudtrail(
                start + timedelta(minutes=2),
                "CreateAccessKey",
                user,
                ip,
                requestParameters={"userName": user},
                responseElements={"accessKey": {"accessKeyId": "AKIALABEXAMPLE"}},
            ),
            self.cloudtrail(
                start + timedelta(minutes=3),
                "AttachUserPolicy",
                user,
                ip,
                requestParameters={
                    "userName": user,
                    "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                },
            ),
        ]

    def audit_tampering(
        self, start: Optional[datetime] = None, *, user: str = "jordan"
    ) -> List[RawLogRecord]:
        """Someone turns the logging off - the one that blinds everything else."""
        start = start or datetime.now(tz=timezone.utc) - timedelta(minutes=4)
        ip = "203.0.113.90"
        return [
            self.cloudtrail(
                start,
                "StopLogging",
                user,
                ip,
                service="cloudtrail",
                requestParameters={"name": "org-trail"},
            ),
            self.cloudtrail(
                start + timedelta(minutes=1),
                "DeleteTrail",
                user,
                ip,
                service="cloudtrail",
                requestParameters={"name": "org-trail"},
            ),
        ]

    def insider_data_access(
        self, start: Optional[datetime] = None, *, user: str = "priya"
    ) -> List[RawLogRecord]:
        """A legitimate account reading far more critical data than usual."""
        start = start or datetime.now(tz=timezone.utc) - timedelta(minutes=15)
        email = EMAILS.get(user, "%s@example.com" % user)
        records = [
            self.app(
                start, "login", user=email, ip="10.0.7.14", mfa_used=True, session_id="sess-insider"
            )
        ]
        moment = start + timedelta(minutes=1)
        for _ in range(6):
            records.append(
                self.app(
                    moment,
                    "data_access",
                    user=email,
                    ip="10.0.7.14",
                    resource="customer-records",
                    resource_criticality="critical",
                    data_classification="pii",
                    record_count=9000,
                    session_id="sess-insider",
                )
            )
            moment += timedelta(minutes=2)
        return records

    def credential_dumping(
        self, start: Optional[datetime] = None, *, user: str = "alex"
    ) -> List[RawLogRecord]:
        """Reading the local credential store via sudo."""
        start = start or datetime.now(tz=timezone.utc) - timedelta(minutes=3)
        return [
            self.sudo(start, user, "/usr/bin/cat /etc/shadow", host="prod-api-01"),
            self.sudo(
                start + timedelta(seconds=30),
                user,
                "/bin/cp /root/.ssh/id_ed25519 /tmp/k",
                host="prod-api-01",
            ),
        ]

    def mfa_removal(
        self, start: Optional[datetime] = None, *, user: str = "dana"
    ) -> List[RawLogRecord]:
        start = start or datetime.now(tz=timezone.utc) - timedelta(minutes=6)
        email = EMAILS.get(user, "%s@example.com" % user)
        return [
            self.okta(
                start, "user.session.start", email, "185.220.101.7", country="NL", city="Amsterdam"
            ),
            self.okta(
                start + timedelta(minutes=1),
                "user.mfa.factor.deactivate",
                email,
                "185.220.101.7",
                country="NL",
                target_email=email,
            ),
        ]

    # ------------------------------------------------------------------ #
    def scenario(
        self, name: str, start: Optional[datetime] = None, **kwargs: Any
    ) -> List[RawLogRecord]:
        scenario = SCENARIOS.get(name)
        if scenario is None:
            raise KeyError(
                "unknown scenario %r (available: %s)" % (name, ", ".join(sorted(SCENARIOS)))
            )
        return scenario.builder(self, start, **kwargs)

    def full_demo(
        self, start: Optional[datetime] = None, *, normal_events: int = 400
    ) -> List[RawLogRecord]:
        """Baseline noise plus one run of every scenario, in time order."""
        start = start or datetime.now(tz=timezone.utc) - timedelta(hours=1)
        records = self.normal_activity(normal_events, start, spread_seconds=3600)
        offset = timedelta(minutes=12)
        for index, name in enumerate(sorted(SCENARIOS)):
            records.extend(self.scenario(name, start + offset * (index + 1)))
        records.sort(key=lambda record: record.received_at)
        return records

    def stream(
        self, rate_per_second: int, duration_seconds: int, start: Optional[datetime] = None
    ) -> Iterator[RawLogRecord]:
        """Generate at a fixed logical rate (used by the load harness)."""
        start = start or datetime.now(tz=timezone.utc)
        total = rate_per_second * duration_seconds
        step = 1.0 / max(rate_per_second, 1)
        for index in range(total):
            yield self._one_normal(start + timedelta(seconds=step * index))


SCENARIOS: Dict[str, Scenario] = {
    "account_compromise": Scenario(
        name="account_compromise",
        title="Potential account compromise",
        description=(
            "Failed logons, a success, a self-service privilege grant, a new API key "
            "and a bulk export - the full chain across three sources."
        ),
        expected_detections=[
            "sf-auth-0001",
            "sf-auth-0002",
            "sf-idn-0001",
            "sf-cred-0001",
            "sf-app-0001",
            "sf-corr-0003",
        ],
        builder=lambda gen, start, **kw: gen.account_compromise(start, **kw),
    ),
    "brute_force": Scenario(
        name="brute_force",
        title="Password guessing burst",
        description="Twenty-five failed logons for one account from a flagged address.",
        expected_detections=["sf-auth-0001"],
        builder=lambda gen, start, **kw: gen.brute_force(start, **kw),
    ),
    "impossible_travel": Scenario(
        name="impossible_travel",
        title="Impossible travel",
        description="One account signing in from two countries twenty minutes apart.",
        expected_detections=["sf-auth-0002", "sf-corr-0002"],
        builder=lambda gen, start, **kw: gen.impossible_travel(start, **kw),
    ),
    "cloud_persistence": Scenario(
        name="cloud_persistence",
        title="Cloud persistence",
        description="Console sign-in without MFA, then a new access key and an admin policy.",
        expected_detections=["sf-cloud-0001", "sf-cred-0001", "sf-idn-0001"],
        builder=lambda gen, start, **kw: gen.cloud_persistence(start, **kw),
    ),
    "audit_tampering": Scenario(
        name="audit_tampering",
        title="Audit logging disabled",
        description="CloudTrail logging stopped and the trail deleted.",
        expected_detections=["sf-cloud-0002"],
        builder=lambda gen, start, **kw: gen.audit_tampering(start, **kw),
    ),
    "insider_data_access": Scenario(
        name="insider_data_access",
        title="Unusual bulk access to critical data",
        description="A valid account reading tens of thousands of customer records.",
        expected_detections=["sf-auth-0002", "sf-app-0001"],
        builder=lambda gen, start, **kw: gen.insider_data_access(start, **kw),
    ),
    "credential_dumping": Scenario(
        name="credential_dumping",
        title="Local credential store accessed",
        description="Reading /etc/shadow and root's SSH key via sudo.",
        expected_detections=["sf-end-0001"],
        builder=lambda gen, start, **kw: gen.credential_dumping(start, **kw),
    ),
    "mfa_removal": Scenario(
        name="mfa_removal",
        title="MFA factor removed after remote sign-in",
        description="A sign-in from an anonymising network followed by MFA deactivation.",
        expected_detections=["sf-auth-0002", "sf-idn-0002"],
        builder=lambda gen, start, **kw: gen.mfa_removal(start, **kw),
    ),
}


def list_scenarios() -> List[Dict[str, Any]]:
    return [scenario.to_dict() for scenario in SCENARIOS.values()]
