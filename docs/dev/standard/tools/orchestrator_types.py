#!/usr/bin/env python3
# ======================================================================
# orchestrator_types.py — версия 1.0
# Shared trust-boundary constants and stable control-plane exception.
# ======================================================================

TRUST_ENV = "APS_TRUSTED_ORCHESTRATOR"
ATTESTATION_KEY_ENV = "APS_TRUSTED_ATTESTATION_KEY"
ATTESTATION_KEY_ID_ENV = "APS_TRUSTED_ATTESTATION_KEY_ID"
REVOKED_KEY_IDS_ENV = "APS_TRUSTED_REVOKED_KEY_IDS"
SIGNER_IDENTITY_ENV = "APS_TRUSTED_SIGNER_IDENTITY"


class ControlPlaneError(RuntimeError):
    """Fail-closed control-plane error with stable finding code."""
