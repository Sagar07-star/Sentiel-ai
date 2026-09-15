from app.services.timeline import TimelineBuilder


def test_timeline_orders_events() -> None:
    builder = TimelineBuilder()

    result = builder.build(
        email_date="2026-09-03T12:00:00+00:00",
        received_hops=[
            {
                "timestamp": "2026-09-03T11:00:00+00:00",
                "from_host": "mail.example.com",
            },
        ],
    )

    assert len(result) == 2
    assert result[0].event_type == "routing"
    assert result[1].event_type == "email"


def test_email_date_header_is_supported() -> None:
    builder = TimelineBuilder()

    result = builder.build(
        email_date="Thu, 03 Sep 2026 12:00:00 +0000",
    )

    assert len(result) == 1
    assert result[0].title == "Message date"


def test_invalid_timestamp_is_ignored() -> None:
    builder = TimelineBuilder()

    result = builder.build(
        received_hops=[
            {
                "timestamp": "not-a-date",
                "from_host": "example.com",
            },
        ],
    )

    assert result == []