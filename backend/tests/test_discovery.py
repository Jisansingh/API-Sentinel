"""Path-normalization unit tests."""

from app.discovery import extract_query_param_names, normalize_path


def test_numeric_ids_normalize_to_id():
    assert normalize_path("/users/101") == "/users/{id}"
    assert normalize_path("/users/202") == "/users/{id}"
    # Same normalized key, so they aggregate into one inventory row.
    assert normalize_path("/users/101") == normalize_path("/users/202")


def test_uuid_like_ids_normalize_to_id():
    assert (
        normalize_path("/orders/123e4567-e89b-12d3-a456-426614174000")
        == "/orders/{id}"
    )
    assert normalize_path("/orders/abcdef0123456789abcdef0123456789") == "/orders/{id}"


def test_static_segments_are_preserved():
    # 'search' is static, so it must NOT merge with /users/{id}.
    assert normalize_path("/users/search") == "/users/search"
    assert normalize_path("/users/search") != normalize_path("/users/101")
    assert normalize_path("/api/health") == "/api/health"


def test_query_string_is_dropped_but_names_survive_separately():
    assert normalize_path("/users/101?token=abc&next=/home") == "/users/{id}"
    assert extract_query_param_names("/users/101?token=abc&next=/home") == [
        "next",
        "token",
    ]
    assert extract_query_param_names("/api/health") == []


def test_unrelated_routes_stay_distinct():
    paths = {
        normalize_path("/users/101"),
        normalize_path("/users/search"),
        normalize_path("/orders/xyz"),
        normalize_path("/api/health"),
    }
    # /orders/xyz is NOT numeric/UUID-shaped, so it stays literal.
    assert paths == {"/users/{id}", "/users/search", "/orders/xyz", "/api/health"}


def test_trailing_slash_and_root():
    assert normalize_path("/users/") == "/users"
    assert normalize_path("/") == "/"
