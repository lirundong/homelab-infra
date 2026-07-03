import time

import requests

_FETCH_TIMEOUT_SECONDS = 30.0
_FETCH_ATTEMPTS = 3
_FETCH_BACKOFF_SECONDS = 2.0


def fetch_url(
    url: str,
    params: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
) -> requests.Response:
    last_error: requests.RequestException | None = None
    for attempt in range(_FETCH_ATTEMPTS):
        if attempt:
            time.sleep(_FETCH_BACKOFF_SECONDS * attempt)
        try:
            response = requests.get(
                url, params=params, headers=headers, timeout=_FETCH_TIMEOUT_SECONDS
            )
            response.raise_for_status()
            return response
        except requests.HTTPError as error:
            # Client errors are deterministic; only server errors merit a retry.
            if error.response is not None and error.response.status_code < 500:
                raise
            last_error = error
        except requests.RequestException as error:
            last_error = error
    assert last_error is not None
    raise last_error
