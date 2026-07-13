# Retained Sentinel Repository artifacts

These files preserve the connection-generated native workflow and helper used
during the July 2026 validation. They are retained to support the recorded
failed synchronization result and contain connection-specific, non-secret lab
identifiers.

They are deliberately outside `.github/workflows` and are not active or
reusable automation. Do not move, copy, or dispatch them. To test the native
Sentinel Repositories path, create a new Repository connection in your own
environment and review its freshly generated workflow and helper before use.
Ensure no Graph fallback writer is active or queued, add explicit manual and
branch gates, pin third-party actions, and serialize the fresh native writer
with the `nls-gigawiper-custom-detection-writer` concurrency group before a
deliberate ownership transition.

The observed native failure has an unconfirmed root cause. These artifacts do
not establish a Microsoft defect, and they did not generate any of the three
portal-native Defender custom alerts.
