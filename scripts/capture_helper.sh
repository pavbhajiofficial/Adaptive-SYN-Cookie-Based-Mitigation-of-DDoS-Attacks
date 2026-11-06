#!/bin/bash
# capture_helper.sh
# Run this ON THE SERVER HOST inside the Mininet CLI to start a labeled
# tcpdump capture for a given test scenario.
#
# Usage (inside mininet> prompt):
#   server bash scripts/capture_helper.sh baseline
#   server bash scripts/capture_helper.sh attack
#   server bash scripts/capture_helper.sh defended
#
# Stop capture with Ctrl+C when the scenario test is done.

SCENARIO=$1
if [ -z "$SCENARIO" ]; then
  echo "Usage: bash capture_helper.sh <scenario_name>"
  exit 1
fi

OUTFILE="${SCENARIO}.pcap"
echo "Starting capture -> $OUTFILE (Ctrl+C to stop)"
tcpdump -i server-eth0 -w "$OUTFILE"
