# ProxyPunch

## SSL Blindspots for Red Teams

### Usage:

    -i, --inputfile=VALUE   Powershell filename
    -u, --url=VALUE         URL eg. https://10.1.1.1/Invoke-NinjaCopy.ps1
    -f, --format=VALUE      Output Format:
                                1 - Only show Triggers
                                2 - Show Triggers with Line numbers
                                3 - Show Triggers inline with code
                                4 - Show AMSI calls (xmas tree mode)
    -d, --debug             Show Debug Info
    -h, -?, --help          Show Help

Find SSL inpection whitelisted categories through proxy
Usage:
  -m, --maxsites=VALUE       Maximum sites to check in each category
                               (increasing will improve accuracy)
  -f, --fqdn=VALUE           check issuing CA for single site eg. ww-
                               w.microsoft.com (https:// will be added)
  -v, --verbose              Increase Verbosity
  -h, -?, --help             Show Help
  
    
For details see https://www.rythmstick.net/posts/sslblindspots/

