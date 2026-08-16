# Safe Operation

Water Utility Protector is for authorized water and wastewater OT/SCADA assessment only.

Before scanning, obtain written authorization defining scope, window, scan host, contacts, and stop conditions; coordinate with plant operations, OT, network, cybersecurity, and the control-system owner. Start with the smallest scope and conservative settings.

During scanning, use only approved targets. Never attempt credentials, exploitation, configuration changes, or device commands. Monitor OT/HMI/network alarms and stop immediately for instability or unexpected behavior.

After scanning, treat reachability as an exposure candidate—not proof of a vulnerability or compromise. Validate with engineering, protect reports as sensitive operational data, and document remediation ownership. Use `Ctrl+C` to stop, notify operations, and preserve the partial report.
