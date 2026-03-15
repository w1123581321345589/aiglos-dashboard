import sys
from aiglos.integrations.memory_guard import _score_memory_content


def _cmd_scan_message(args):
    if not args:
        print("Usage: aiglos scan-message <message_text>")
        return

    text = " ".join(args)
    score, risk, signals = _score_memory_content(text)

    if risk == "LOW" and not signals:
        print(f"CLEAN — risk={risk} score={score:.2f}")
    else:
        print(f"FLAGGED — risk={risk} score={score:.2f}")
        if signals:
            print(f"  signals: {', '.join(signals)}")
        if risk == "HIGH":
            print("  DO NOT store this content in agent memory.")
        elif risk == "MEDIUM":
            print("  Review before storing in agent memory.")


def main():
    if len(sys.argv) < 2:
        print("Usage: aiglos <command> [args]")
        print("Commands: scan-message")
        return

    cmd = sys.argv[1]
    if cmd == "scan-message":
        _cmd_scan_message(sys.argv[2:])
    else:
        print(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()
