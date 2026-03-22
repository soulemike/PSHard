class Logger {

    [string]$Component

    Logger([string]$Component) {
        $this.Component = $Component
    }

    [void] Info([string]$Message) {
        Write-Verbose "[INFO][$($this.Component)] $Message"
    }

    [void] Warning([string]$Message) {
        Write-Warning "[WARN][$($this.Component)] $Message"
    }

    [void] Error([string]$Message) {
        Write-Error "[ERROR][$($this.Component)] $Message"
    }
}
