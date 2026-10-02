"""Phone and SSN detection: fewer false positives, international numbers, undashed SSNs.

References:
- NANP numbers are NXX-NXX-XXXX, where N is 2-9: area codes and central office codes
  never start with 0 or 1 (NANPA, https://nationalnanpa.com/area_codes/index.html).
- E.164 numbers have at most 15 digits including the country code (ITU-T E.164).
- SSA never assigns area numbers 000, 666 or 900-999
  (https://www.ssa.gov/employer/randomization.html); group 00 and serial 0000 are
  invalid and all-same-digit numbers are rejected, as in Presidio's UsSsnRecognizer
  (presidio_analyzer/predefined_recognizers/country_specific/us/us_ssn_recognizer.py).
"""

from __future__ import annotations

import pytest

from toolkit_policy_test_bench.detectors import detect_pii


@pytest.mark.parametrize(
    "text",
    [
        "Call (415) 555-2671 today",
        "Call 415-555-2671 today",
        "Call 415.555.2671 today",
        "Call 415 555 2671 today",
        "Call +1 415 555 2671 today",
        "call me at 4155552671",
        "my cell: 4155552671",
        "UK office +44 20 7946 0958",
        "Paris +33 1 23 45 67 89",
        "Tokyo +81-3-1234-5678",
    ],
)
def test_phone_numbers_detected(text: str) -> None:
    assert detect_pii(text)["phone"] == 1


@pytest.mark.parametrize(
    "text",
    [
        "Invoice 4155552671 is paid",  # bare 10 digits without phone context
        "Order 1234567890 shipped",  # NPA cannot start with 1
        "Ref 123-456-7890",  # NPA cannot start with 1
        "Tracking 0155552671",  # NPA cannot start with 0
        "timestamp 1727366400123",  # 13 digits
        "version 2.10.3.4567",
        "+12",  # too short for E.164 use
    ],
)
def test_non_phone_numbers_ignored(text: str) -> None:
    assert detect_pii(text)["phone"] == 0


def test_bare_number_with_context_must_still_be_valid_nanp() -> None:
    assert detect_pii("call 4151552671")["phone"] == 0  # exchange cannot start with 1


def test_international_and_us_numbers_are_not_double_counted() -> None:
    assert detect_pii("US +1 (415) 555-2671, UK +44 20 7946 0958")["phone"] == 2


@pytest.mark.parametrize(
    "text",
    [
        "SSN 219-09-9999",
        "SSN 219 09 9999",
        "my ssn is 219099999",
        "Social Security number: 219099999",
    ],
)
def test_ssn_detected(text: str) -> None:
    assert detect_pii(text)["ssn"] == 1


@pytest.mark.parametrize(
    "text",
    [
        "000-12-3456",  # area 000
        "666-12-3456",  # area 666
        "900-12-3456",  # area 900-999
        "999-12-3456",
        "219-00-9999",  # group 00
        "219-09-0000",  # serial 0000
        "111-11-1111",  # all same digit
        "219-09 9999",  # mixed separators
        "Order 219099999",  # undashed without SSN context
    ],
)
def test_invalid_or_contextless_ssn_ignored(text: str) -> None:
    assert detect_pii(text)["ssn"] == 0
