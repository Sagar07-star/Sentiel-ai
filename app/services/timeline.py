"""
Sentinel AI
Forensic Timeline Reconstruction

Builds a normalized investigation timeline from observable evidence.

Design principles:
- Never invent timestamps.
- Preserve timezone information.
- Normalize timestamps to UTC for reliable ordering.
- Support email Date and Received-header evidence.
- Support timestamped authentication and analysis observations.
- Preserve source provenance for every timeline event.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime


@dataclass(frozen=True, slots=True)
class TimelineEvent:
    """One observable event in the forensic timeline."""

    event_id: str
    timestamp: datetime
    event_type: str
    title: str
    description: str
    source: str


class TimelineBuilder:
    """Construct a chronological forensic timeline."""

    def build(
        self,
        *,
        received_hops: list[dict[str, str | None]] | None = None,
        email_date: str | None = None,
        authentication_events: (
            list[str | dict[str, str | None]]
            | None
        ) = None,
    ) -> list[TimelineEvent]:
        """
        Build a chronological timeline.

        Authentication events are only included when they contain a
        trustworthy timestamp. A plain string authentication observation
        is intentionally ignored because no timestamp can safely be
        inferred from Authentication-Results.
        """

        events: list[TimelineEvent] = []

        if email_date:
            timestamp = self._parse_timestamp(email_date)

            if timestamp:
                events.append(
                    TimelineEvent(
                        event_id="email_date",
                        timestamp=timestamp,
                        event_type="email",
                        title="Message date",
                        description=(
                            "Timestamp declared by the email Date header."
                        ),
                        source="Date",
                    )
                )

        for index, hop in enumerate(
            received_hops or [],
            start=1,
        ):
            timestamp = self._parse_timestamp(
                hop.get("timestamp")
            )

            if not timestamp:
                continue

            host = (
                hop.get("from_host")
                or hop.get("by_host")
                or "unknown host"
            )

            description = (
                f"Routing evidence associated with {host}."
            )

            to_host = hop.get("to_host")

            if to_host:
                description = (
                    f"Routing evidence from {host} to {to_host}."
                )

            events.append(
                TimelineEvent(
                    event_id=f"received_{index}",
                    timestamp=timestamp,
                    event_type="routing",
                    title=f"Received hop {index}",
                    description=description,
                    source="Received",
                )
            )

        self._add_timestamped_observations(
            events=events,
            observations=authentication_events or [],
            default_event_type="authentication",
            default_title="Authentication observation",
            default_source="Authentication-Results",
        )

        return self._sort_events(events)

    def build_extended(
        self,
        *,
        received_hops: list[dict[str, str | None]] | None = None,
        email_date: str | None = None,
        authentication_events: (
            list[str | dict[str, str | None]]
            | None
        ) = None,
        evidence_events: list[dict[str, str | None]] | None = None,
    ) -> list[TimelineEvent]:
        """
        Build a timeline with additional timestamped evidence.

        `evidence_events` may contain:
        - timestamp
        - event_type
        - title
        - description
        - source
        - event_id
        """

        events = self.build(
            received_hops=received_hops,
            email_date=email_date,
            authentication_events=authentication_events,
        )

        self._add_timestamped_observations(
            events=events,
            observations=evidence_events or [],
            default_event_type="evidence",
            default_title="Forensic evidence observation",
            default_source="Sentinel AI",
        )

        return self._sort_events(events)

    @classmethod
    def _add_timestamped_observations(
        cls,
        *,
        events: list[TimelineEvent],
        observations: Sequence[
            str | dict[str, str | None]
        ],
        default_event_type: str,
        default_title: str,
        default_source: str,
    ) -> None:
        """Add observations only when an explicit timestamp is available."""

        for index, observation in enumerate(
            observations,
            start=1,
        ):
            if isinstance(observation, str):
                # No timestamp means no safe chronological placement.
                continue

            timestamp = cls._parse_timestamp(
                observation.get("timestamp")
            )

            if not timestamp:
                continue

            event_type = (
                observation.get("event_type")
                or default_event_type
            )

            title = (
                observation.get("title")
                or default_title
            )

            description = (
                observation.get("description")
                or observation.get("message")
                or title
            )

            source = (
                observation.get("source")
                or default_source
            )

            event_id = (
                observation.get("event_id")
                or f"{default_event_type}_{index}"
            )

            events.append(
                TimelineEvent(
                    event_id=event_id,
                    timestamp=timestamp,
                    event_type=event_type,
                    title=title,
                    description=description,
                    source=source,
                )
            )

    @staticmethod
    def _sort_events(
        events: list[TimelineEvent],
    ) -> list[TimelineEvent]:
        """Sort events chronologically with deterministic tie-breaking."""

        return sorted(
            events,
            key=lambda event: (
                event.timestamp,
                event.event_id,
            ),
        )

    @staticmethod
    def _parse_timestamp(
        value: str | None,
    ) -> datetime | None:
        """Parse ISO-8601 or RFC email timestamps into UTC."""

        if not value:
            return None

        parsed: datetime | None = None

        try:
            parsed = datetime.fromisoformat(
                value.strip()
            )
        except ValueError:
            pass

        if parsed is None:
            try:
                parsed = parsedate_to_datetime(
                    value.strip()
                )
            except (
                TypeError,
                ValueError,
                OverflowError,
            ):
                return None

        if parsed.tzinfo is None:
            parsed = parsed.replace(
                tzinfo=UTC
            )

        return parsed.astimezone(UTC)


__all__ = [
    "TimelineBuilder",
    "TimelineEvent",
]