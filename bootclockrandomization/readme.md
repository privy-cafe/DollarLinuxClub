 Randomizes clock when systems boots by adding a few seconds and nanoseconds to enforce the design goal, that the host clock and Gateway/Workstation clock should always slightly differ (even before secure timesync succeeded!) to prevent time based fingerprinting / linkablity issues. For better anonymity and privacy.
 Randomizes clock when systems boots

Randomizes clock at boot time. Moves clock a few seconds and nanoseconds to past or future. Useful in context of anonymity/privacy/Tor.

This is useful to enforce the design goal, that the host clock and Gateway/Workstation clock should always slightly differ (even before secure timesync succeeded!) to prevent time based fingerprinting / linkablity issues.

Runs before Tor / sdwdate (if installed).

See also: https://www.whonix.org/wiki/Dev/TimeSync
