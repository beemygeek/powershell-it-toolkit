@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # Console output is intentional: these are interactive technician tools.
        'PSAvoidUsingWriteHost',
        # Temporary/scramble passwords are generated in-script by a CSPRNG and
        # converted immediately; no plaintext password is ever accepted as input.
        'PSAvoidUsingConvertToSecureStringWithPlainText'
    )
}
