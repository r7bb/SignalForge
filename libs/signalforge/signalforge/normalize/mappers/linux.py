"""Linux host telemetry -> OCSF.

Handles the shapes a Vector/Fluent Bit ``journald``/``file`` source produces for
``sshd``, ``sudo``, the shadow-utils tools and auditd, including bare syslog
lines when the collector could not parse them itself.
"""

from __future__ import annotations

import re
from typing import Dict, Optional

from ...models.ocsf import (
    Actor,
    ClassUid,
    Device,
    Endpoint,
    FileObj,
    Group,
    OcsfEvent,
    Os,
    Process,
    RawLogRecord,
    Session,
    SeverityId,
    StatusId,
    User,
)
from ...timeutil import parse_time
from ..base import Mapper, NormalizationError, register

#: Reused fragments: a unix account name and an IPv4/IPv6 literal.
_USER = r"[\w.\-@$]"
_IP = r"[\d.a-fA-F:]"

# sshd
_SSHD_ACCEPTED = re.compile(
    r"Accepted (?P<method>\w+) for (?P<user>%s+) "
    r"from (?P<ip>%s+) port (?P<port>\d+)" % (_USER, _IP)
)
_SSHD_FAILED = re.compile(
    r"Failed (?P<method>\w+) for (?:invalid user )?(?P<user>%s+) "
    r"from (?P<ip>%s+) port (?P<port>\d+)" % (_USER, _IP)
)
_SSHD_INVALID_USER = re.compile(r"Invalid user (?P<user>[\w.\-@$]*) from (?P<ip>[\d.a-fA-F:]+)")
_SSHD_DISCONNECT = re.compile(
    r"(?:Disconnected from|Connection closed by) (?:authenticating |invalid )?"
    r"user (?P<user>%s+) (?P<ip>%s+)" % (_USER, _IP)
)
_SSHD_SESSION_CLOSED = re.compile(
    r"pam_unix\(sshd:session\): session closed for user (?P<user>[\w.\-@$]+)"
)
_SSHD_PUBKEY = re.compile(r"Accepted publickey for (?P<user>[\w.\-@$]+)")

# sudo
_SUDO_COMMAND = re.compile(
    r"(?P<user>%s+) : TTY=\S+ ; PWD=(?P<pwd>\S+) ; "
    r"USER=(?P<target>%s+) ; COMMAND=(?P<cmd>.+)$" % (_USER, _USER)
)
_SUDO_FAILURE = re.compile(
    r"(?P<user>[\w.\-@$]+) : (?:\d+ incorrect password attempts?|user NOT in sudoers)"
)
_SUDO_SESSION_OPEN = re.compile(
    r"pam_unix\(sudo:session\): session opened for user (?P<target>%s+)"
    r"(?:\(uid=\d+\))? by (?P<user>%s*)" % (_USER, _USER)
)

# shadow-utils
_USERADD = re.compile(r"new user: name=(?P<user>[\w.\-@$]+), UID=(?P<uid>\d+), GID=(?P<gid>\d+)")
_USERMOD_GROUP = re.compile(r"add '(?P<user>[\w.\-@$]+)' to group '(?P<group>[\w.\-]+)'")
_USERDEL = re.compile(r"delete user '(?P<user>[\w.\-@$]+)'")
_PASSWD_CHANGED = re.compile(r"password changed for (?P<user>[\w.\-@$]+)")

_PRIVILEGED_GROUPS = {"root", "sudo", "wheel", "admin", "adm", "docker"}

_SYSLOG_LINE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<program>[\w./\-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)


def _split_syslog(raw: str) -> Dict[str, object]:
    match = _SYSLOG_LINE.match(raw.strip())
    if not match:
        return {"message": raw.strip()}
    data = match.groupdict()
    return {
        "timestamp": data["ts"],
        "host": data["host"],
        "program": data["program"],
        "pid": int(data["pid"]) if data["pid"] else None,
        "message": data["message"],
    }


@register
class LinuxMapper(Mapper):
    source = "linux"
    product_name = "Linux Host"
    vendor_name = "Linux"

    def map(self, record: RawLogRecord) -> Optional[OcsfEvent]:
        payload = dict(record.payload or {})
        if not payload.get("message") and record.raw:
            payload.update(_split_syslog(record.raw))

        message = str(payload.get("message") or payload.get("MESSAGE") or "")
        program = str(
            payload.get("program")
            or payload.get("SYSLOG_IDENTIFIER")
            or payload.get("unit")
            or (record.source.split(".", 1)[1] if "." in record.source else "")
        ).lower()
        hostname = payload.get("host") or payload.get("hostname") or payload.get("_HOSTNAME")
        timestamp = (
            parse_time(
                payload.get("timestamp")
                or payload.get("@timestamp")
                or payload.get("__REALTIME_TIMESTAMP"),
                reference=record.received_at,
            )
            or record.received_at
        )

        device = Device(
            hostname=str(hostname) if hostname else None,
            ip=payload.get("host_ip"),
            type="Server",
            os=Os(name=payload.get("os_name") or "Linux", type="Linux"),
        )

        builder = None
        if "sshd" in program:
            builder = self._map_sshd
        elif "sudo" in program:
            builder = self._map_sudo
        elif program in {"useradd", "usermod", "userdel", "groupadd", "passwd", "chage"}:
            builder = self._map_shadow_utils
        elif program in {"audit", "auditd", "audispd"} or payload.get("audit_type"):
            builder = self._map_auditd

        if builder is None:
            raise NormalizationError(
                "unsupported linux program %r" % (program or "<unknown>"), record
            )

        event = builder(payload, message, program)
        if event is None:
            raise NormalizationError("unrecognized %s message" % (program or "linux"), record)

        event.time = timestamp
        event.device = device
        event.message = event.message or message
        event.metadata.log_name = program or "syslog"
        event.metadata.product.feature = program or None
        if payload.get("pid") and event.actor and event.actor.process:
            event.actor.process.pid = int(payload["pid"])
        return event

    # -- sshd -------------------------------------------------------------
    def _map_sshd(
        self, payload: Dict[str, object], message: str, program: str
    ) -> Optional[OcsfEvent]:
        match = _SSHD_ACCEPTED.search(message)
        if match:
            return OcsfEvent(
                class_uid=ClassUid.AUTHENTICATION,
                activity_id=1,
                status_id=StatusId.SUCCESS,
                severity_id=SeverityId.INFORMATIONAL,
                actor=Actor(
                    user=User(name=match.group("user"), type="User"),
                    session=Session(uid=payload.get("session_id"), is_remote=True),
                ),
                src_endpoint=Endpoint(ip=match.group("ip"), port=int(match.group("port"))),
                dst_endpoint=Endpoint(svc_name="sshd", port=22),
                auth_protocol=match.group("method").capitalize(),
                logon_type="Network",
                is_mfa=match.group("method").lower() == "publickey",
            )

        match = _SSHD_FAILED.search(message) or _SSHD_INVALID_USER.search(message)
        if match:
            groups = match.groupdict()
            invalid = "invalid user" in message.lower()
            return OcsfEvent(
                class_uid=ClassUid.AUTHENTICATION,
                activity_id=1,
                status_id=StatusId.FAILURE,
                status_detail="Invalid user" if invalid else "Invalid credentials",
                severity_id=SeverityId.LOW,
                actor=Actor(user=User(name=groups.get("user") or "unknown", type="User")),
                src_endpoint=Endpoint(
                    ip=groups.get("ip"),
                    port=int(groups["port"]) if groups.get("port") else None,
                ),
                dst_endpoint=Endpoint(svc_name="sshd", port=22),
                auth_protocol=(groups.get("method") or "password").capitalize(),
                logon_type="Network",
                unmapped={"invalid_user": invalid},
            )

        match = _SSHD_SESSION_CLOSED.search(message) or _SSHD_DISCONNECT.search(message)
        if match:
            groups = match.groupdict()
            return OcsfEvent(
                class_uid=ClassUid.AUTHENTICATION,
                activity_id=2,  # Logoff
                status_id=StatusId.SUCCESS,
                actor=Actor(user=User(name=groups.get("user"), type="User")),
                src_endpoint=Endpoint(ip=groups.get("ip")) if groups.get("ip") else None,
                dst_endpoint=Endpoint(svc_name="sshd", port=22),
                logon_type="Network",
            )
        return None

    # -- sudo -------------------------------------------------------------
    def _map_sudo(
        self, payload: Dict[str, object], message: str, program: str
    ) -> Optional[OcsfEvent]:
        match = _SUDO_COMMAND.search(message)
        if match:
            target = match.group("target")
            privileged = target in {"root"} or target in _PRIVILEGED_GROUPS
            return OcsfEvent(
                class_uid=ClassUid.PROCESS_ACTIVITY,
                activity_id=1,  # Launch
                status_id=StatusId.SUCCESS,
                severity_id=SeverityId.MEDIUM if privileged else SeverityId.INFORMATIONAL,
                actor=Actor(
                    user=User(name=match.group("user"), type="User"),
                    process=Process(
                        name="sudo",
                        cmd_line=match.group("cmd"),
                        user=User(name=target, type="Admin" if privileged else "User"),
                    ),
                    authorizations=["sudo"],
                ),
                user=User(name=target, type="Admin" if privileged else "User"),
                unmapped={"pwd": match.group("pwd"), "elevated": privileged},
                message=message,
            )

        match = _SUDO_SESSION_OPEN.search(message)
        if match:
            return OcsfEvent(
                class_uid=ClassUid.AUTHORIZE_SESSION,
                activity_id=1,  # Assign Privileges
                status_id=StatusId.SUCCESS,
                severity_id=SeverityId.MEDIUM,
                actor=Actor(user=User(name=match.group("user") or "unknown", type="User")),
                user=User(name=match.group("target"), type="Admin"),
                group=Group(name="sudo", privileges=["root"]),
                message=message,
            )

        match = _SUDO_FAILURE.search(message)
        if match:
            return OcsfEvent(
                class_uid=ClassUid.AUTHORIZE_SESSION,
                activity_id=1,
                status_id=StatusId.FAILURE,
                status_detail="sudo authorization denied",
                severity_id=SeverityId.MEDIUM,
                actor=Actor(user=User(name=match.group("user"), type="User")),
                group=Group(name="sudo"),
                message=message,
            )
        return None

    # -- useradd / usermod / passwd ---------------------------------------
    def _map_shadow_utils(
        self, payload: Dict[str, object], message: str, program: str
    ) -> Optional[OcsfEvent]:
        match = _USERADD.search(message)
        if match:
            return OcsfEvent(
                class_uid=ClassUid.ACCOUNT_CHANGE,
                activity_id=1,  # Create
                status_id=StatusId.SUCCESS,
                severity_id=SeverityId.MEDIUM,
                actor=Actor(user=User(name=str(payload.get("actor") or "root"), type="Admin")),
                user=User(name=match.group("user"), uid=match.group("uid"), type="User"),
                unmapped={"gid": match.group("gid")},
                message=message,
            )

        match = _USERMOD_GROUP.search(message)
        if match:
            group_name = match.group("group")
            privileged = group_name.lower() in _PRIVILEGED_GROUPS
            return OcsfEvent(
                class_uid=ClassUid.GROUP_MANAGEMENT,
                activity_id=3,  # Add User
                status_id=StatusId.SUCCESS,
                severity_id=SeverityId.HIGH if privileged else SeverityId.LOW,
                actor=Actor(user=User(name=str(payload.get("actor") or "root"), type="Admin")),
                user=User(name=match.group("user"), type="User"),
                group=Group(
                    name=group_name,
                    type="Privileged" if privileged else "Standard",
                    privileges=["root"] if privileged else [],
                ),
                message=message,
            )

        match = _USERDEL.search(message)
        if match:
            return OcsfEvent(
                class_uid=ClassUid.ACCOUNT_CHANGE,
                activity_id=6,  # Delete
                status_id=StatusId.SUCCESS,
                severity_id=SeverityId.MEDIUM,
                actor=Actor(user=User(name=str(payload.get("actor") or "root"), type="Admin")),
                user=User(name=match.group("user"), type="User"),
                message=message,
            )

        match = _PASSWD_CHANGED.search(message)
        if match:
            return OcsfEvent(
                class_uid=ClassUid.ACCOUNT_CHANGE,
                activity_id=3,  # Password Change
                status_id=StatusId.SUCCESS,
                actor=Actor(user=User(name=str(payload.get("actor") or match.group("user")))),
                user=User(name=match.group("user"), type="User"),
                message=message,
            )
        return None

    # -- auditd -----------------------------------------------------------
    def _map_auditd(
        self, payload: Dict[str, object], message: str, program: str
    ) -> Optional[OcsfEvent]:
        audit_type = str(payload.get("audit_type") or payload.get("type") or "").upper()
        actor_user = User(
            name=str(payload.get("auid_name") or payload.get("user") or "unknown"),
            uid=str(payload.get("auid")) if payload.get("auid") is not None else None,
        )
        if audit_type in {"EXECVE", "SYSCALL"}:
            return OcsfEvent(
                class_uid=ClassUid.PROCESS_ACTIVITY,
                activity_id=1,
                status_id=StatusId.SUCCESS
                if payload.get("success", "yes") in (True, "yes")
                else StatusId.FAILURE,
                actor=Actor(
                    user=actor_user,
                    process=Process(
                        name=str(payload.get("exe") or payload.get("comm") or ""),
                        cmd_line=str(payload.get("cmdline") or message),
                        pid=int(str(payload["pid"]))
                        if str(payload.get("pid") or "").isdigit()
                        else None,
                    ),
                ),
                unmapped={"audit_type": audit_type, "key": payload.get("key")},
                message=message,
            )
        if audit_type in {"PATH", "OPEN", "FILE"}:
            path = str(payload.get("path") or payload.get("name") or "")
            sensitive = any(
                token in path for token in ("/etc/shadow", "/etc/sudoers", "/root/.ssh", "secrets")
            )
            return OcsfEvent(
                class_uid=ClassUid.FILE_SYSTEM_ACTIVITY,
                activity_id=int(str(payload.get("activity_id") or 2)),  # default Read
                status_id=StatusId.SUCCESS,
                severity_id=SeverityId.MEDIUM if sensitive else SeverityId.INFORMATIONAL,
                actor=Actor(user=actor_user),
                file=FileObj(
                    name=path.rsplit("/", 1)[-1] or None,
                    path=path or None,
                    type="Regular File",
                ),
                unmapped={"audit_type": audit_type, "sensitive_path": sensitive},
                message=message,
            )
        return None
