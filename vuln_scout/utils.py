import logging
from packaging import version

# Configure logging (optional, but handy for debugging)
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)

def version_in_vulnerable_range(current_version_str, affected_ranges):
    """
    Return True if current_version_str falls within any of the affected range events.

    affected_ranges is a list of dicts, each with:
        {
            "type": "ECOSYSTEM",
            "events": [
                {"introduced": "2.0.0"},
                {"fixed": "2.25.2"}
            ]
        }
    or
        {
            "events": [
                {"introduced": "2.0.0"},
                {"last_affected": "2.25.1"}
            ]
        }

    Example usage:
        v_in_range = version_in_vulnerable_range("2.25.1", [{
            "type": "ECOSYSTEM",
            "events": [
                {"introduced": "2.0.0"},
                {"fixed": "2.25.2"}
            ]
        }])
        # v_in_range would be True, since 2.25.1 < 2.25.2
    """

    v_current = version.parse(current_version_str)

    for r in affected_ranges:
        # Most Python vulnerabilities fall under type='ECOSYSTEM', but let's be safe
        if r.get("type") != "ECOSYSTEM":
            continue

        events = r.get("events", [])
        introduced = None
        fixed = None
        last_affected = None

        for e in events:
            if "introduced" in e:
                introduced = version.parse(e["introduced"])
            elif "fixed" in e:
                fixed = version.parse(e["fixed"])
            elif "last_affected" in e:
                last_affected = version.parse(e["last_affected"])

        # If 'introduced' wasn't specified, assume it's something very low (e.g., "0")
        if introduced is None:
            introduced = version.parse("0")

        # Check if current version is >= introduced and < fixed
        if fixed is not None:
            if introduced <= v_current < fixed:
                return True

        # Check if current version is >= introduced and <= last_affected
        if last_affected is not None:
            if introduced <= v_current <= last_affected:
                return True

    return False
