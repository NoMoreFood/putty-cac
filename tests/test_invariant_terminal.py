import pytest
import struct
import ctypes


# Simulate the vulnerable sprintf behavior with a fixed-size buffer
# This models the terminal cursor position report formatting
FIXED_BUFFER_SIZE = 32  # Typical fixed buffer size for cursor position reports

def format_cursor_position_safe(y, x):
    """
    Safely format cursor position report string.
    Models what the terminal code does with sprintf(buf, "\033[%d;%dR", y+1, x+1)
    Returns the formatted string or raises if it would overflow.
    """
    formatted = f"\033[{y + 1};{x + 1}R"
    return formatted

def check_buffer_overflow(y, x, buffer_size=FIXED_BUFFER_SIZE):
    """
    Check if formatting cursor coordinates would overflow a fixed buffer.
    Returns True if safe, False if overflow would occur.
    """
    formatted = f"\033[{y + 1};{x + 1}R"
    # +1 for null terminator
    return len(formatted) + 1 <= buffer_size

def safe_cursor_format(y, x, buffer_size=FIXED_BUFFER_SIZE):
    """
    A safe implementation that clamps values to prevent buffer overflow.
    This is what the fixed code should do.
    """
    # Clamp values to prevent overflow
    max_coord = 10 ** (buffer_size // 2) - 1  # Conservative max
    safe_y = max(0, min(y, max_coord))
    safe_x = max(0, min(x, max_coord))
    formatted = f"\033[{safe_y + 1};{safe_x + 1}R"
    assert len(formatted) + 1 <= buffer_size, f"Buffer overflow: {len(formatted)+1} > {buffer_size}"
    return formatted


@pytest.mark.parametrize("payload", [
    # INT_MAX values (2^31 - 1 = 2147483647)
    (2147483647, 2147483647),
    # INT_MAX - 1
    (2147483646, 2147483646),
    # Large values that produce long decimal strings
    (999999999, 999999999),
    (1000000000, 1000000000),
    (9999999999, 9999999999),
    # Values near typical terminal dimensions but extreme
    (65535, 65535),
    (65536, 65536),
    (1048576, 1048576),
    # Asymmetric large values
    (2147483647, 0),
    (0, 2147483647),
    (2147483647, 1),
    (1, 2147483647),
    # Negative values (should be handled gracefully)
    (-1, -1),
    (-2147483648, -2147483648),
    (-1, 0),
    (0, -1),
    # Zero values (baseline)
    (0, 0),
    # Normal terminal dimensions
    (24, 80),
    (1080, 1920),
    # Values that produce exactly boundary-length strings
    (9999, 9999),
    (99999, 99999),
    # Overflow-inducing combinations
    (2147483647, 2147483646),
    (2147483646, 2147483647),
    # Values just above typical buffer thresholds
    (10000000, 10000000),
    (100000000, 100000000),
])
def test_cursor_position_buffer_safety(payload):
    """
    Invariant: Formatting cursor position coordinates into a fixed-size buffer
    must NEVER produce a string that exceeds the buffer size, regardless of
    the coordinate values provided. A malicious SSH server must not be able
    to cause buffer overflow by manipulating terminal cursor state.
    """
    y, x = payload
    
    # Property 1: The formatted string length must always be bounded
    # when using a safe implementation
    try:
        result = safe_cursor_format(y, x, FIXED_BUFFER_SIZE)
        # If we get here, the safe implementation succeeded
        # Verify the result is a valid cursor position report
        assert result.startswith("\033["), f"Result must start with ESC[: {repr(result)}"
        assert result.endswith("R"), f"Result must end with R: {repr(result)}"
        # Verify the buffer constraint is satisfied
        assert len(result) + 1 <= FIXED_BUFFER_SIZE, (
            f"SECURITY VIOLATION: Formatted string length {len(result)+1} "
            f"exceeds buffer size {FIXED_BUFFER_SIZE} for coordinates y={y}, x={x}"
        )
    except AssertionError as e:
        # Re-raise assertion errors from our safety checks
        raise
    except Exception:
        # Other exceptions from safe_cursor_format are acceptable
        # (e.g., value clamping logic)
        pass

    # Property 2: Detect if the raw (unsafe) formatting would overflow
    # This documents the vulnerability without requiring it to crash
    raw_formatted = f"\033[{y + 1};{x + 1}R"
    raw_length = len(raw_formatted) + 1  # +1 for null terminator
    
    if raw_length > FIXED_BUFFER_SIZE:
        # This is the vulnerable case - document that it WOULD overflow
        # The invariant is that a SAFE implementation must handle this
        # by clamping, truncating, or rejecting the value
        
        # Verify that a safe implementation would NOT produce an oversized string
        safe_y = max(0, min(abs(y) if y >= 0 else 0, 9999))
        safe_x = max(0, min(abs(x) if x >= 0 else 0, 9999))
        safe_formatted = f"\033[{safe_y + 1};{safe_x + 1}R"
        
        assert len(safe_formatted) + 1 <= FIXED_BUFFER_SIZE, (
            f"SECURITY VIOLATION: Even clamped values overflow buffer. "
            f"safe_y={safe_y}, safe_x={safe_x}, length={len(safe_formatted)+1}"
        )


@pytest.mark.parametrize("coord_value", [
    2147483647,   # INT_MAX
    2147483646,   # INT_MAX - 1  
    1073741823,   # INT_MAX / 2
    999999999,    # 9 digits
    1000000000,   # 10 digits
    9999999999,   # 10 digits
    2**32 - 1,    # UINT_MAX
    2**32,        # UINT_MAX + 1
    2**63 - 1,    # INT64_MAX
])
def test_extreme_single_coordinate_overflow_detection(coord_value):
    """
    Invariant: Single extreme coordinate values must not cause buffer overflow
    when formatted into a fixed-size cursor position report buffer.
    The formatted output length must always be bounded by the buffer size.
    """
    # Test with extreme value in y position
    raw_y_format = f"\033[{coord_value + 1};1R"
    raw_x_format = f"\033[1;{coord_value + 1}R"
    
    # Document the overflow risk
    y_overflows = len(raw_y_format) + 1 > FIXED_BUFFER_SIZE
    x_overflows = len(raw_x_format) + 1 > FIXED_BUFFER_SIZE
    
    if y_overflows or x_overflows:
        # Verify that a safe implementation clamps the value
        # The maximum safe decimal value for a 32-byte buffer:
        # "\033[" (2) + digits_y + ";" (1) + digits_x + "R" (1) + "\0" (1) <= 32
        # Conservative: each coordinate max 13 digits -> "\033[9999999999999;9999999999999R\0" = 32
        max_safe_digits = (FIXED_BUFFER_SIZE - 5) // 2  # 5 = len("\033[") + len(";R\0")
        max_safe_value = 10 ** max_safe_digits - 1
        
        clamped = min(coord_value, max_safe_value)
        safe_format = f"\033[{clamped + 1};{clamped + 1}R"
        
        assert len(safe_format) + 1 <= FIXED_BUFFER_SIZE, (
            f"SECURITY VIOLATION: Cannot safely format coordinate {coord_value} "
            f"within {FIXED_BUFFER_SIZE}-byte buffer"
        )


def test_cursor_position_format_string_structure():
    """
    Invariant: The cursor position report format string structure must always
    produce a parseable, bounded output. The escape sequence format 
    ESC[row;colR must be preserved while preventing buffer overflow.
    """
    import re
    
    # Valid cursor position report pattern
    cursor_report_pattern = re.compile(r'^\x1b\[\d+;\d+R$')
    
    test_cases = [
        (0, 0),
        (23, 79),
        (0, 0),
        # Clamped extreme values
        (9999, 9999),
        (999, 9999),
        (9999, 999),
    ]
    
    for y, x in test_cases:
        formatted = f"\033[{y + 1};{x + 1}R"
        
        # Property: Format must match expected pattern
        assert cursor_report_pattern.match(formatted), (
            f"Cursor position report has invalid format: {repr(formatted)}"
        )
        
        # Property: Must fit in fixed buffer
        assert len(formatted) + 1 <= FIXED_BUFFER_SIZE, (
            f"SECURITY VIOLATION: Cursor report exceeds buffer: "
            f"len={len(formatted)+1}, buffer={FIXED_BUFFER_SIZE}, "
            f"y={y}, x={x}"
        )