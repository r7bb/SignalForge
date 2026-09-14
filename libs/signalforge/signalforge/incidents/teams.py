"""Team and membership management, plus the queue projections built on them."""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker

from ..models.incident import ACTIVE_STATUSES
from ..models.team import TEAM_ROLES, Team, TeamMember, normalise_slug
from ..storage import db as dbm

logger = logging.getLogger("signalforge.teams")


class TeamError(Exception):
    """Raised for conflicting or impossible team operations."""


class TeamService:
    def __init__(self, session_factory: Optional[sessionmaker] = None) -> None:
        self.session_factory = session_factory or dbm.get_session_factory()

    # ---------------------------------------------------------------- teams
    def create(
        self,
        tenant: str,
        name: str,
        *,
        slug: Optional[str] = None,
        description: Optional[str] = None,
        is_default: bool = False,
        actor: str = "system",
    ) -> Team:
        slug = normalise_slug(slug or name)
        with self.session_factory() as session:
            existing = session.scalars(
                select(dbm.Team).where(dbm.Team.tenant == tenant, dbm.Team.slug == slug)
            ).first()
            if existing is not None:
                raise TeamError("team %r already exists in tenant %r" % (slug, tenant))

            if is_default:
                self._clear_default(session, tenant)

            row = dbm.Team(
                tenant=tenant,
                slug=slug,
                name=name,
                description=description,
                is_default=is_default,
            )
            session.add(row)
            session.flush()
            dbm.record_audit(
                session,
                tenant=tenant,
                actor=actor,
                action="team.created",
                entity_type="team",
                entity_id=row.id,
                detail=name,
                slug=slug,
                is_default=is_default,
            )
            session.commit()
            logger.info("created team", extra={"tenant": tenant, "slug": slug})
            return self._to_model(row, members=[])

    def list(self, tenant: str, *, with_counts: bool = True) -> List[Team]:
        with self.session_factory() as session:
            rows = session.scalars(
                select(dbm.Team).where(dbm.Team.tenant == tenant).order_by(dbm.Team.name)
            ).all()
            teams = [self._to_model(row, self._members(session, row.id)) for row in rows]
            if with_counts and teams:
                self._attach_counts(session, tenant, teams)
            return teams

    def get(self, tenant: str, reference: str, *, with_counts: bool = False) -> Optional[Team]:
        """Look a team up by slug or id."""
        with self.session_factory() as session:
            row = self._find(session, tenant, reference)
            if row is None:
                return None
            team = self._to_model(row, self._members(session, row.id))
            if with_counts:
                self._attach_counts(session, tenant, [team])
            return team

    def require(self, tenant: str, reference: str) -> Team:
        team = self.get(tenant, reference)
        if team is None:
            raise TeamError("no such team: %r" % reference)
        return team

    def default_team(self, tenant: str) -> Optional[Team]:
        with self.session_factory() as session:
            row = session.scalars(
                select(dbm.Team).where(dbm.Team.tenant == tenant, dbm.Team.is_default.is_(True))
            ).first()
            if row is None:
                return None
            return self._to_model(row, self._members(session, row.id))

    def set_default(self, tenant: str, reference: str, actor: str = "system") -> Team:
        with self.session_factory() as session:
            row = self._find(session, tenant, reference)
            if row is None:
                raise TeamError("no such team: %r" % reference)
            self._clear_default(session, tenant)
            row.is_default = True
            dbm.record_audit(
                session,
                tenant=tenant,
                actor=actor,
                action="team.set_default",
                entity_type="team",
                entity_id=row.id,
                detail=row.slug,
            )
            session.commit()
            return self._to_model(row, self._members(session, row.id))

    def ensure_default(self, tenant: str, *, name: str = "SOC", actor: str = "system") -> Team:
        """The tenant must always have somewhere to put an unrouted incident."""
        existing = self.default_team(tenant)
        if existing is not None:
            return existing
        try:
            return self.create(
                tenant,
                name,
                description="Default queue for incidents no routing rule claimed.",
                is_default=True,
                actor=actor,
            )
        except TeamError:
            # The slug already exists without the default flag - promote it.
            return self.set_default(tenant, normalise_slug(name), actor=actor)

    def delete(self, tenant: str, reference: str, actor: str = "system") -> None:
        with self.session_factory() as session:
            row = self._find(session, tenant, reference)
            if row is None:
                raise TeamError("no such team: %r" % reference)
            open_count = session.scalar(
                select(func.count())
                .select_from(dbm.Incident)
                .where(
                    dbm.Incident.team_id == row.id,
                    dbm.Incident.status.in_([s.value for s in ACTIVE_STATUSES]),
                )
            )
            if open_count:
                raise TeamError(
                    "team %r still owns %d open incident(s); move them first"
                    % (row.slug, open_count)
                )
            dbm.record_audit(
                session,
                tenant=tenant,
                actor=actor,
                action="team.deleted",
                entity_type="team",
                entity_id=row.id,
                detail=row.slug,
            )
            session.delete(row)
            session.commit()

    # ----------------------------------------------------------- membership
    def add_member(
        self,
        tenant: str,
        reference: str,
        user: str,
        *,
        role: str = "member",
        actor: str = "system",
    ) -> TeamMember:
        if role not in TEAM_ROLES:
            raise TeamError(
                "invalid team role %r (expected one of %s)" % (role, ", ".join(TEAM_ROLES))
            )
        with self.session_factory() as session:
            team = self._find(session, tenant, reference)
            if team is None:
                raise TeamError("no such team: %r" % reference)
            user_row = self._find_user(session, tenant, user)
            if user_row is None:
                raise TeamError("no such user in tenant %r: %r" % (tenant, user))

            existing = session.scalars(
                select(dbm.TeamMember).where(
                    dbm.TeamMember.team_id == team.id,
                    dbm.TeamMember.user_id == user_row.id,
                )
            ).first()
            if existing is not None:
                existing.role = role
                member_row = existing
                action = "team.member_role_changed"
            else:
                member_row = dbm.TeamMember(team_id=team.id, user_id=user_row.id, role=role)
                session.add(member_row)
                action = "team.member_added"
            session.flush()
            dbm.record_audit(
                session,
                tenant=tenant,
                actor=actor,
                action=action,
                entity_type="team",
                entity_id=team.id,
                detail=user_row.email,
                team=team.slug,
                role=role,
            )
            session.commit()
            return TeamMember(
                id=member_row.id,
                team_id=team.id,
                user_id=user_row.id,
                email=user_row.email,
                full_name=user_row.full_name,
                role=member_row.role,
                joined_at=member_row.created_at,
            )

    def remove_member(
        self, tenant: str, reference: str, user: str, *, actor: str = "system"
    ) -> None:
        with self.session_factory() as session:
            team = self._find(session, tenant, reference)
            if team is None:
                raise TeamError("no such team: %r" % reference)
            user_row = self._find_user(session, tenant, user)
            if user_row is None:
                raise TeamError("no such user in tenant %r: %r" % (tenant, user))
            member = session.scalars(
                select(dbm.TeamMember).where(
                    dbm.TeamMember.team_id == team.id,
                    dbm.TeamMember.user_id == user_row.id,
                )
            ).first()
            if member is None:
                return
            session.delete(member)
            dbm.record_audit(
                session,
                tenant=tenant,
                actor=actor,
                action="team.member_removed",
                entity_type="team",
                entity_id=team.id,
                detail=user_row.email,
                team=team.slug,
            )
            session.commit()

    def teams_for_user(self, tenant: str, user_id: str) -> List[Team]:
        with self.session_factory() as session:
            rows = session.scalars(
                select(dbm.Team)
                .join(dbm.TeamMember, dbm.TeamMember.team_id == dbm.Team.id)
                .where(dbm.Team.tenant == tenant, dbm.TeamMember.user_id == user_id)
                .order_by(dbm.Team.name)
            ).all()
            return [self._to_model(row, self._members(session, row.id)) for row in rows]

    def leads_of(self, tenant: str, user_id: str) -> List[str]:
        """Team ids where this user is a lead - the extra authority they hold."""
        with self.session_factory() as session:
            return list(
                session.scalars(
                    select(dbm.Team.id)
                    .join(dbm.TeamMember, dbm.TeamMember.team_id == dbm.Team.id)
                    .where(
                        dbm.Team.tenant == tenant,
                        dbm.TeamMember.user_id == user_id,
                        dbm.TeamMember.role == "lead",
                    )
                ).all()
            )

    def is_lead(self, tenant: str, team_id: Optional[str], user_id: str) -> bool:
        if not team_id:
            return False
        return team_id in set(self.leads_of(tenant, user_id))

    # -------------------------------------------------------------- helpers
    @staticmethod
    def _find(session, tenant: str, reference: str) -> Optional[dbm.Team]:
        return session.scalars(
            select(dbm.Team).where(
                dbm.Team.tenant == tenant,
                (dbm.Team.slug == reference) | (dbm.Team.id == reference),
            )
        ).first()

    @staticmethod
    def _find_user(session, tenant: str, reference: str) -> Optional[dbm.User]:
        tenant_row = session.scalars(select(dbm.Tenant).where(dbm.Tenant.key == tenant)).first()
        if tenant_row is None:
            return None
        return session.scalars(
            select(dbm.User).where(
                dbm.User.tenant_id == tenant_row.id,
                (dbm.User.email == reference) | (dbm.User.id == reference),
            )
        ).first()

    @staticmethod
    def _clear_default(session, tenant: str) -> None:
        for row in session.scalars(
            select(dbm.Team).where(dbm.Team.tenant == tenant, dbm.Team.is_default.is_(True))
        ).all():
            row.is_default = False

    @staticmethod
    def _members(session, team_id: str) -> List[TeamMember]:
        rows = session.execute(
            select(dbm.TeamMember, dbm.User)
            .join(dbm.User, dbm.User.id == dbm.TeamMember.user_id)
            .where(dbm.TeamMember.team_id == team_id)
            .order_by(dbm.User.email)
        ).all()
        return [
            TeamMember(
                id=member.id,
                team_id=member.team_id,
                user_id=member.user_id,
                email=user.email,
                full_name=user.full_name,
                role=member.role,
                joined_at=member.created_at,
            )
            for member, user in rows
        ]

    @staticmethod
    def _attach_counts(session, tenant: str, teams: Sequence[Team]) -> None:
        """One grouped query for the queue depth shown beside every team."""
        active = [status.value for status in ACTIVE_STATUSES]
        open_counts: Dict[str, int] = dict(
            session.execute(
                select(dbm.Incident.team_id, func.count())
                .where(dbm.Incident.tenant == tenant, dbm.Incident.status.in_(active))
                .group_by(dbm.Incident.team_id)
            ).all()
        )
        unclaimed: Dict[str, int] = dict(
            session.execute(
                select(dbm.Incident.team_id, func.count())
                .where(
                    dbm.Incident.tenant == tenant,
                    dbm.Incident.status.in_(active),
                    dbm.Incident.assignee_id.is_(None),
                )
                .group_by(dbm.Incident.team_id)
            ).all()
        )
        for team in teams:
            team.open_incidents = int(open_counts.get(team.id, 0))
            team.unclaimed_incidents = int(unclaimed.get(team.id, 0))

    @staticmethod
    def _to_model(row: dbm.Team, members: List[TeamMember]) -> Team:
        return Team(
            id=row.id,
            tenant=row.tenant,
            slug=row.slug,
            name=row.name,
            description=row.description,
            is_default=row.is_default,
            members=members,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )
