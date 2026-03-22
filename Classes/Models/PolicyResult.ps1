class PolicyResult {

    [string]$PolicyName
    [bool]$Compliant
    [string]$Evidence
    [string]$Remediation

    PolicyResult([string]$PolicyName, [bool]$Compliant, [string]$Evidence, [string]$Remediation) {
        $this.PolicyName  = $PolicyName
        $this.Compliant   = $Compliant
        $this.Evidence    = $Evidence
        $this.Remediation = $Remediation
    }
}
