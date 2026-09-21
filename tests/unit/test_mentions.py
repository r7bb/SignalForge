"""@mention parsing and resolution."""

from __future__ import annotations

from signalforge.incidents.mentions import (
    extract_handles,
    render_note,
    resolve_mentions,
)

TENANT_USERS = ["dana@acme.test", "sam@acme.test", "rio@acme.test"]


def test_handles_are_extracted_in_order_without_duplicates() -> None:
    body = "@dana can you check this, then tell @sam and @dana again"
    assert extract_handles(body) == ["dana", "sam"]


def test_trailing_punctuation_is_not_part_of_the_handle() -> None:
    assert extract_handles("ask @dana, then @sam.") == ["dana", "sam"]
    assert extract_handles("@rio!") == ["rio"]


def test_an_empty_body_has_no_handles() -> None:
    assert extract_handles("") == []
    assert extract_handles(None) == []  # type: ignore[arg-type]


def test_a_local_part_resolves_when_it_is_unambiguous() -> None:
    result = resolve_mentions("@dana please look", TENANT_USERS)
    assert result.resolved == ["dana@acme.test"]
    assert result.unresolved == []


def test_a_full_address_resolves() -> None:
    result = resolve_mentions("@sam@acme.test over to you", TENANT_USERS)
    assert result.resolved == ["sam@acme.test"]


def test_the_same_person_named_twice_resolves_once() -> None:
    result = resolve_mentions("@dana and @dana@acme.test", TENANT_USERS)
    assert result.resolved == ["dana@acme.test"]


def test_an_unknown_handle_is_reported_not_dropped() -> None:
    """Silently dropping it leaves the author thinking somebody was told."""
    result = resolve_mentions("@nobody take a look", TENANT_USERS)
    assert result.resolved == []
    assert result.unresolved == ["nobody"]
    assert result.any_unresolved


def test_an_ambiguous_local_part_is_not_guessed_at() -> None:
    users = ["dana@acme.test", "dana@contractor.test"]
    result = resolve_mentions("@dana ping", users)
    assert result.resolved == []
    assert result.unresolved == ["dana"]
    assert result.ambiguous["dana"] == ["dana@acme.test", "dana@contractor.test"]

    # The full address is still unambiguous.
    exact = resolve_mentions("@dana@contractor.test ping", users)
    assert exact.resolved == ["dana@contractor.test"]


def test_resolution_is_case_insensitive() -> None:
    result = resolve_mentions("@DANA look", TENANT_USERS)
    assert result.resolved == ["dana@acme.test"]


def test_an_email_in_prose_is_not_a_mention() -> None:
    """Only an @-prefixed handle counts; a bare address in text does not."""
    result = resolve_mentions("the account dana@acme.test was disabled", TENANT_USERS)
    assert result.resolved == []


def test_no_candidates_means_nothing_resolves() -> None:
    result = resolve_mentions("@dana", [])
    assert result.resolved == [] and result.unresolved == ["dana"]


# ------------------------------------------------------------- rendering
def test_render_splits_the_body_into_segments() -> None:
    segments = render_note("hey @dana look here", ["dana@acme.test"])
    assert segments == [("hey ", False), ("@dana", True), (" look here", False)]


def test_render_leaves_unresolved_handles_as_plain_text() -> None:
    segments = render_note("hey @nobody", ["dana@acme.test"])
    assert segments == [("hey @nobody", False)]


def test_render_handles_a_mention_at_each_end() -> None:
    segments = render_note("@dana ping @sam", ["dana@acme.test", "sam@acme.test"])
    assert segments == [("@dana", True), (" ping ", False), ("@sam", True)]


def test_render_round_trips_the_original_text() -> None:
    """Whatever the segmentation, reassembling must give the body back."""
    body = "@dana and @sam, see the note from @nobody about dana@acme.test"
    segments = render_note(body, ["dana@acme.test", "sam@acme.test"])
    assert "".join(text for text, _ in segments) == body


def test_a_bare_address_in_prose_produces_no_spurious_handle() -> None:
    """Without a word boundary, "dana@acme.test" yields a bogus "@acme.test"
    handle, and the author gets warned about a mention they never wrote."""
    body = "the account dana@acme.test was disabled at 13:40"
    assert extract_handles(body) == []

    result = resolve_mentions(body, TENANT_USERS)
    assert result.resolved == []
    assert result.unresolved == [], "a plain address must not look like a mention"


def test_a_mention_after_punctuation_still_counts() -> None:
    assert extract_handles("(@dana)") == ["dana"]
    assert extract_handles("cc:@sam") == ["sam"]
    assert extract_handles("line one\n@rio") == ["rio"]
