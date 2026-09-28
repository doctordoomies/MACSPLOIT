# Synthetic fixtures only

Phase 0 provider tests generate invented structured output through the synthetic
provider and exercise its parser, graph ingestion, and evidence persistence.
Temporary runtime output stays outside Git. No real assessment captures belong here.

Phase 1 should add static synthetic fixtures for each real provider's supported
structured-output versions, malformed/truncated output, and scope boundaries.
