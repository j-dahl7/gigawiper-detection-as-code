# Isolated native Repository retest

This orphan branch intentionally contains one disabled, impossible-match custom-detection canary and no production detection IDs.

It exists only to test a fresh Microsoft Sentinel Repository connection without touching the six Graph-fallback-owned rules. A successful deployment proves only that this isolated canary passed through the native path at the recorded time; it does not explain the earlier provider failure.

