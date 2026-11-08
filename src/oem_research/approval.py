class ApprovalRequired(PermissionError): pass
BLOCKED={"flash","unlock-bootloader","write-device","exploit"}

def authorize(action: str, approved: bool=False) -> str:
    action=action.strip().lower()
    if action in BLOCKED: raise PermissionError(f"Action '{action}' is blocked by safety policy")
    if action=="static-read": return "authorized-read-only"
    if action=="dynamic-test" and approved: return "authorized-by-explicit-human-approval"
    if action=="dynamic-test": raise ApprovalRequired("Dynamic testing requires explicit human approval")
    raise PermissionError("Unknown action")
