$FirewallIP = "172.16.255.1"

function Write-Header($text) {
    Write-Host "`n=====================================" -ForegroundColor Cyan
    Write-Host "   $text" -ForegroundColor Cyan
    Write-Host "=====================================`n" -ForegroundColor Cyan
}

function Ask-ToRun($testName) {
    $response = Read-Host "Run $testName test? (y/n)"
    return $response -eq 'y'
}

# 1. Basic Connectivity Test
function Test-BasicConnectivity {
    Write-Header "BASIC CONNECTIVITY TEST"
    
    Write-Host "Testing ping connectivity..."
    ping -n 4 $FirewallIP
    
    Write-Host "`nTesting common ports..."
    $ports = @(22, 80, 443)
    
    foreach ($port in $ports) {
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $beginConnect = $client.BeginConnect($FirewallIP, $port, $null, $null)
            $waitResult = $beginConnect.AsyncWaitHandle.WaitOne(1000, $true)
            
            if ($waitResult) {
                Write-Host "Port $port is OPEN" -ForegroundColor Green
            } else {
                Write-Host "Port $port is CLOSED" -ForegroundColor Red
            }
            
            $client.Close()
        } catch {
            Write-Host "Error connecting to port $port" -ForegroundColor Red
        }
    }
}

# 2. Port Scan Test
function Test-PortScan {
    Write-Header "PORT SCAN TEST"
    
    # Check if nmap is available
    try {
        $null = &nmap --version
        $nmapAvailable = $true
    } catch {
        $nmapAvailable = $false
        Write-Host "Nmap is not installed. Skipping port scan test." -ForegroundColor Yellow
        return
    }
    
    if ($nmapAvailable) {
        Write-Host "Running port scan (should trigger firewall alerts)..."
        &nmap -sS $FirewallIP
        
        Write-Host "`nRunning more aggressive scan..."
        &nmap -p 1-1000 -T4 $FirewallIP
    }
}

# 3. SSH Dictionary Attack Simulation
function Test-SSHAttack {
    Write-Header "SSH DICTIONARY ATTACK TEST"
    
    Write-Host "Simulating multiple SSH connection attempts..."
    $sshPort = 22
    
    for ($i = 1; $i -le 15; $i++) {
        Write-Host "SSH attempt $i"
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $client.Connect($FirewallIP, $sshPort)
            Start-Sleep -Milliseconds 500
            $client.Close()
        } catch {
            # Expected to fail, continue silently
        }
        Start-Sleep -Milliseconds 300
    }
}

# 4. DPI Test (HTTP Attack Simulation)
function Test-DPI {
    Write-Header "DEEP PACKET INSPECTION TEST"
    
    $testUrls = @(
        "/?id=1'%20OR%201=1--",                   # SQL Injection
        "/search?q=<script>alert(1)</script>",    # XSS
        "/file?path=../../../etc/passwd",         # Path Traversal
        "/exec?cmd=ls;cat%20/etc/passwd"          # Command Injection
    )
    
    foreach ($path in $testUrls) {
        $url = "http://$FirewallIP$path"
        Write-Host "Sending request: $url"
        
        try {
            Invoke-WebRequest -Uri $url -TimeoutSec 2 -ErrorAction SilentlyContinue
        } catch {
            # Expected to fail, continue silently
        }
        
        Start-Sleep -Seconds 1
    }
}

# 5. Anomaly Detection Test
function Test-Anomaly {
    Write-Header "ANOMALY DETECTION TEST"
    
    Write-Host "Testing unusual packet pattern (many rapid connections)..."
    
    # Many connections in a short time
    for ($i = 1; $i -le 30; $i++) {
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $client.BeginConnect($FirewallIP, 80, $null, $null)
            $client.Close()
        } catch {
            # Expected to fail, continue silently
        }
        
        if ($i % 5 -eq 0) {
            Write-Host "Created $i connections..."
        }
    }
    
    # Unusual ports
    $unusualPorts = @(31337, 8080, 12345)
    
    Write-Host "`nTesting unusual ports..."
    foreach ($port in $unusualPorts) {
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $client.Connect($FirewallIP, $port)
            $client.Close()
            Write-Host "Connected to unusual port $port"
        } catch {
            Write-Host "Failed to connect to port $port (expected)"
        }
    }
}

# Main script execution
Clear-Host
Write-Host "Firewall Testing Script" -ForegroundColor Green
Write-Host "Target: $FirewallIP`n" -ForegroundColor Green

# Run the tests (with confirmation for each)
if (Ask-ToRun "Basic Connectivity") { Test-BasicConnectivity }
if (Ask-ToRun "Port Scan") { Test-PortScan }
if (Ask-ToRun "SSH Dictionary Attack") { Test-SSHAttack }
if (Ask-ToRun "Deep Packet Inspection") { Test-DPI }
if (Ask-ToRun "Anomaly Detection") { Test-Anomaly }

Write-Host "`nAll tests completed. Check your firewall logs for detection results." -ForegroundColor Green
