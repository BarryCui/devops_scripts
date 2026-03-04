<#
.SYNOPSIS
    企业级 Windows 高级威胁狩猎与应急响应引擎 (Windows Threat Hunter)
.DESCRIPTION
    包含 7 大核心狩猎模块，只读不写。自动在当前目录生成高管级 HTML 溯源战报。
.REQUIREMENTS
    需要管理员权限运行 (Run as Administrator)
#>

#Requires -RunAsAdministrator

# ==========================================
# 0. 核心引擎与全局数据池
# ==========================================
$script:Findings = @()  # 存放所有告警记录的全局池

function Write-SecAlert {
    param([string]$ModuleName, [string]$Title, [string]$Details, [string]$Playbook)
    
    # 1. 控制台 UI 输出
    Write-Host "`n[🚨 严重告警] $Title" -ForegroundColor Red -BackgroundColor Black
    Write-Host " |__ 所属模块: $ModuleName" -ForegroundColor DarkGray
    Write-Host " |__ 异常详情: $Details" -ForegroundColor Yellow
    Write-Host " |__ [🛠️ 战术指导手册 (Playbook)]:" -ForegroundColor Cyan
    $Playbook -split "`n" | ForEach-Object { Write-Host "     $($_.Trim())" -ForegroundColor Cyan }

    # 2. 存入全局数据池，供 HTML 引擎使用
    $script:Findings += [PSCustomObject]@{
        Module   = $ModuleName
        Title    = $Title
        Details  = $Details
        Playbook = $Playbook
    }
}

function Write-SecInfo {
    param([string]$Msg)
    Write-Host "[*] $Msg" -ForegroundColor Green
}

# ==========================================
# 模块一：驻留机制扫描 (已加入白名单与元数据过滤)
# ==========================================
function Check-Persistence {
    Write-SecInfo "启动模块一：注册表与无文件驻留机制扫描 (智能降噪模式)..."
    $modName = "驻留机制 (Persistence)"
    
    $runPaths = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run")
    
    # 真正的恶意特征关键字 (去掉了宽泛的 appdata，精准定位 temp 和脚本)
    $suspiciousKeywords = "\\Temp\\|cmd\.exe|powershell|wscript|mshta|\.vbs|\.bat"
    
    # 【核心修复 1】：建立合法业务白名单 (正则表达式，支持常见软件)
    $whitelist = "ms-teams\.exe|BaiduNetdisk|YunDetectService|OneDrive|Update\.exe|BingWallpaper|WeChat"
    
    foreach ($path in $runPaths) {
        if (Test-Path $path) {
            $items = Get-ItemProperty $path -ErrorAction SilentlyContinue
            foreach ($prop in $items.psobject.properties) {
                # 【核心修复 2】：物理屏蔽 PowerShell 自动生成的系统元数据 (PSPath 等)
                if ($prop.Name -match "^PS") { continue }
                
                $val = [string]$prop.Value
                if ([string]::IsNullOrWhiteSpace($val)) { continue }

                $isSuspicious = $false
                
                # 规则 1：命中高危关键字
                if ($val -match $suspiciousKeywords) { $isSuspicious = $true }
                
                # 规则 2：如果在 AppData 运行，但不在白名单内，视为可疑 (防范伪装软件)
                if ($val -match "AppData" -and $val -notmatch $whitelist) { $isSuspicious = $true }
                
                # 规则 3：一票否决权 (只要在白名单里，绝对放行)
                if ($val -match $whitelist -or $prop.Name -match $whitelist) { $isSuspicious = $false }

                if ($isSuspicious) {
                    Write-SecAlert -ModuleName $modName -Title "发现高危注册表自启动项" `
                        -Details "键值名: $($prop.Name)`n启动路径: $val`n所在注册表: $path" `
                        -Playbook "1. 确认该程序是否为未知第三方软件`n2. 使用 Remove-ItemProperty 删除恶意键值`n3. 提取执行文件进行沙箱分析"
                }
            }
        }
    }

    try {
        $wmiFilters = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction Stop | Where-Object { $_.Name -notmatch "SCM Event Log" }
        if ($wmiFilters) {
            foreach ($filter in $wmiFilters) {
                Write-SecAlert -ModuleName $modName -Title "发现异常 WMI 事件订阅 (疑似无文件后门)" `
                    -Details "过滤器名称: $($filter.Name)`n查询语句: $($filter.Query)" `
                    -Playbook "1. 严禁直接重启服务器 (会导致内存证据丢失)`n2. 导出 WMI 订阅记录用于取证`n3. 使用 Remove-WmiObject 清除对应的 Filter 和 Consumer"
            }
        }
    } catch { }
}

# ==========================================
# 模块二：进程与内存异常分析
# ==========================================
function Check-ProcessMemory {
    Write-SecInfo "启动模块二：现行进程与内存特征核查..."
    $modName = "进程与内存 (Process & Memory)"
    $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    
    foreach ($proc in $processes) {
        if ($proc.CommandLine -match "-enc|-EncodedCommand|FromBase64String|IEX|Invoke-Expression|AmsiScanBuffer") {
            Write-SecAlert -ModuleName $modName -Title "捕获恶意 PowerShell 内存加载行为" `
                -Details "进程: $($proc.Name) (PID: $($proc.ProcessId))`n命令行: $($proc.CommandLine)" `
                -Playbook "1. 冻结该进程: Suspend-Process -Id $($proc.ProcessId)`n2. 转储内存: procdump.exe -ma $($proc.ProcessId)`n3. 杀掉进程: Stop-Process -Id $($proc.ProcessId) -Force"
        }
        
        if ($proc.ExecutablePath -match "(?i)\\Temp\\|\\AppData\\|\\\$Recycle\.Bin\\|\\ProgramData\\[^\\]+\.exe") {
            $sig = Get-AuthenticodeSignature $proc.ExecutablePath -ErrorAction SilentlyContinue
            if ($sig.Status -ne "Valid") {
                Write-SecAlert -ModuleName $modName -Title "发现在高危临时目录运行且无签名的进程" `
                    -Details "进程: $($proc.Name) (PID: $($proc.ProcessId))`n路径: $($proc.ExecutablePath)`n签名状态: $($sig.Status)" `
                    -Playbook "1. 使用 taskkill /PID $($proc.ProcessId) /F 结束进程`n2. 将该文件提取到沙箱分析"
            }
        }

        if ($proc.Name -match "cmd\.exe|powershell\.exe") {
            $parent = $processes | Where-Object ProcessId -eq $proc.ParentProcessId
            if ($parent.Name -match "w3wp\.exe|tomcat|java\.exe|winword\.exe|excel\.exe") {
                Write-SecAlert -ModuleName $modName -Title "捕获异常父子进程树 (疑似 WebShell 或宏病毒执行)" `
                    -Details "父进程: $($parent.Name) -> 衍生了子进程: $($proc.Name) (PID: $($proc.ProcessId))`n执行参数: $($proc.CommandLine)" `
                    -Playbook "1. 如果父进程是 w3wp，立即排查 IIS 目录下的 WebShell`n2. 如果是 Office 进程，排查近期打开的钓鱼附件"
            }
        }
    }
}

# ==========================================
# 模块三：网络连接与外联检测 (已修复 HOSTS 注释误报)
# ==========================================
function Check-Network {
    Write-SecInfo "启动模块三：网络 Socket 与隐藏隧道检测..."
    $modName = "网络外联 (Network & C2)"
    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    $highRiskPorts = @(4444, 1337, 8888, 9999, 445)
    
    foreach ($conn in $connections) {
        if ($highRiskPorts -contains $conn.RemotePort -and $conn.RemoteAddress -notmatch "^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^127\.") {
            $procName = (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).Name
            Write-SecAlert -ModuleName $modName -Title "发现连接到外网高危端口的异常 Socket" `
                -Details "进程: $procName (PID: $($conn.OwningProcess)) -> 外联: $($conn.RemoteAddress):$($conn.RemotePort)" `
                -Playbook "1. 立即在防火墙封堵目的 IP: $($conn.RemoteAddress)`n2. 抓取该进程的内存快照后杀掉该进程"
        }
    }

    # 【核心修复 3】：只读取非注释行 (不以 # 开头的行)
    $hostsContent = Get-Content "C:\Windows\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue | Where-Object { $_ -notmatch "^\s*#" }
    
    if ($hostsContent -join " " -match "microsoft|windowsupdate|kaspersky|symantec|mcafee|360") {
        Write-SecAlert -ModuleName $modName -Title "HOSTS 文件被恶意劫持" `
            -Details "系统 HOSTS 文件中发现屏蔽安全厂商或微软更新的真实解析记录" `
            -Playbook "1. 打开 C:\Windows\System32\drivers\etc\hosts`n2. 清除恶意重定向记录，恢复系统更新及查杀能力"
    }
}

# ==========================================
# 模块四：系统日志与行为审计
# ==========================================
function Check-EventLogs {
    Write-SecInfo "启动模块四：系统日志擦除与高危行为溯源..."
    $modName = "系统日志 (Event Logs)"
    
    $clearedLogs = Get-WinEvent -FilterHashtable @{LogName='System'; ID=104} -MaxEvents 1 -ErrorAction SilentlyContinue
    $clearedSec = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=1102} -MaxEvents 1 -ErrorAction SilentlyContinue
    
    if ($clearedLogs -or $clearedSec) {
        $time = if($clearedSec){$clearedSec.TimeCreated}else{$clearedLogs.TimeCreated}
        Write-SecAlert -ModuleName $modName -Title "捕获到系统/安全日志被清空痕迹 (极度危险)" `
            -Details "最后一次清空时间: $time" `
            -Playbook "1. 100% 确认已被黑客入侵，并正在掩盖痕迹`n2. 立即全盘断网，隔离设备`n3. 提取现存的剩余日志进行法医鉴定"
    }
}

# ==========================================
# 模块五：账户与权限异常
# ==========================================
function Check-Accounts {
    Write-SecInfo "启动模块五：本地影子账户与后门账户盘点..."
    $modName = "账户异常 (Account Deviations)"
    
    $hiddenUsers = Get-LocalUser | Where-Object { $_.Name -match '\$$' -and $_.Name -notmatch '^DefaultAccount$|^WDAGUtilityAccount$' }
    if ($hiddenUsers) {
        foreach ($u in $hiddenUsers) {
            Write-SecAlert -ModuleName $modName -Title "发现高危本地隐藏账户" `
                -Details "账户名: $($u.Name)`n启用状态: $($u.Enabled)" `
                -Playbook "1. 禁用该账户: Disable-LocalUser -Name $($u.Name)`n2. 检查 Administrators 组，看其是否已被暗中提权"
        }
    }
}

# ==========================================
# 模块六：安全防护降级检测
# ==========================================
function Check-DefenseEvasion {
    Write-SecInfo "启动模块六：防病毒与防护机制降级检测..."
    $modName = "防护降级 (Defense Evasion)"
    
    $regDef = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -ErrorAction SilentlyContinue
    if ($regDef -and $regDef.DisableAntiSpyware -eq 1) {
        Write-SecAlert -ModuleName $modName -Title "安全防护被强制降级 (勒索软件前兆)" `
            -Details "Windows Defender 被注册表 DisableAntiSpyware 强行关闭" `
            -Playbook "1. 立即删除恶意注册表键值`n2. 重启 WinDefend 服务`n3. 高度警惕，立即断网防勒索"
    }
}

# ==========================================
# 模块七：服务器专属检测项
# ==========================================
function Check-ServerRoles {
    Write-SecInfo "启动模块七：服务器核心业务资产异常排查..."
    $modName = "服务暴露 (Server Focus)"
    
    $webRoot = "C:\inetpub\wwwroot"
    if (Test-Path $webRoot) {
        $recentWebFiles = Get-ChildItem -Path $webRoot -Recurse -Include *.aspx, *.ashx, *.php -ErrorAction SilentlyContinue | 
                          Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-3) }
        
        if ($recentWebFiles) {
            foreach ($file in $recentWebFiles) {
                Write-SecAlert -ModuleName $modName -Title "IIS 目录发现近期变动的脚本 (疑似 WebShell)" `
                    -Details "文件路径: $($file.FullName)`n最后修改: $($file.LastWriteTime)" `
                    -Playbook "1. 立即审查该文件源码，寻找 eval, request, cmd.exe 等木马特征`n2. 提取 IIS 访问日志排查是谁上传了该文件"
            }
        }
    }
}

# ==========================================
# 🌐 HTML 报告生成引擎
# ==========================================
function Generate-HtmlReport {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostName = $env:COMPUTERNAME
    $reportPath = "$PSScriptRoot\SecHunter_Report_${hostName}_${timestamp}.html"
    
    $tbodyHtml = ""
    if ($script:Findings.Count -eq 0) {
        $tbodyHtml = "<tr><td colspan='4' style='text-align:center; padding:30px; color:#10b981; font-size:16px;'>🎯 完美！本次狩猎未发现任何已知驻留或高危异常行为。</td></tr>"
    } else {
        foreach ($item in $script:Findings) {
            # 自动将文本的换行符替换为 HTML 的换行标签
            $detailsHtml = ($item.Details -replace "`n", "<br>")
            $playbookHtml = ($item.Playbook -replace "`n", "<br>")
            
            $tbodyHtml += @"
            <tr>
                <td><span class='badge'>$($item.Module)</span></td>
                <td style='color:#f87171; font-weight:bold;'>$($item.Title)</td>
                <td class='code-block'>$detailsHtml</td>
                <td class='playbook-block'>$playbookHtml</td>
            </tr>
"@
        }
    }

    $htmlTemplate = @"
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <title>Windows 威胁狩猎与应急响应战报</title>
        <style>
            :root { --bg: #0f172a; --panel: #1e293b; --text: #e2e8f0; --accent: #ef4444; --border: #334155; }
            body { font-family: -apple-system, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); padding: 30px; margin: 0; }
            .container { max-width: 1500px; margin: auto; background: var(--panel); padding: 30px; border-radius: 12px; border: 1px solid var(--border); box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
            h1 { border-bottom: 2px solid var(--accent); padding-bottom: 15px; color: #f8fafc; font-size: 24px; margin-top: 0; }
            .header-info { display: flex; gap: 30px; margin-bottom: 25px; color: #94a3b8; font-size: 14px; }
            .header-info span { background: #0f172a; padding: 5px 12px; border-radius: 6px; border: 1px solid #334155; }
            
            .summary { display: flex; gap: 20px; margin-bottom: 30px; }
            .card { flex: 1; background: #0f172a; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #3b82f6; }
            .card.alert { border-left-color: var(--accent); }
            .card h3 { margin: 0 0 10px 0; font-size: 13px; color: #94a3b8; text-transform: uppercase; }
            .card p { font-size: 32px; font-weight: bold; margin: 0; color: #f8fafc; }
            .card.alert p { color: var(--accent); }
            
            table { width: 100%; border-collapse: collapse; font-size: 13.5px; text-align: left; table-layout: fixed; }
            th, td { padding: 14px; border-bottom: 1px solid var(--border); vertical-align: top; }
            th { background: #0f172a; color: #cbd5e1; font-weight: 600; }
            th:nth-child(1) { width: 15%; } th:nth-child(2) { width: 20%; } th:nth-child(3) { width: 30%; } th:nth-child(4) { width: 35%; }
            tr:hover { background: #233145; }
            
            .badge { background: #3b82f6; color: white; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }
            .code-block { font-family: 'Courier New', monospace; font-size: 12px; color: #fbbf24; word-break: break-all; line-height: 1.5; }
            .playbook-block { color: #34d399; line-height: 1.6; font-size: 13px; }
            
            .footer { text-align: center; margin-top: 40px; font-size: 12px; color: #64748b; border-top: 1px solid var(--border); padding-top: 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>☠️ Windows 威胁狩猎与应急响应战报 (SecHunter)</h1>
            <div class="header-info">
                <span>💻 目标主机: <strong>$hostName</strong></span>
                <span>⏱️ 狩猎时间: <strong>$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</strong></span>
                <span>👤 执行权限: <strong>SYSTEM / Administrator</strong></span>
            </div>
            
            <div class="summary">
                <div class="card"><h3>覆盖攻击面模块</h3><p>7 个</p></div>
                <div class="card alert"><h3>发现高危异常总计</h3><p>$($script:Findings.Count)</p></div>
            </div>
            
            <table>
                <thead>
                    <tr>
                        <th>核查模块 (Module)</th>
                        <th>异常行为定性 (Threat Alert)</th>
                        <th>内存与取证线索 (Forensics Evidence)</th>
                        <th>🛠️ 战术动作指导 (Remediation Playbook)</th>
                    </tr>
                </thead>
                <tbody>
                    $tbodyHtml
                </tbody>
            </table>
            
            <div class="footer">驱动引擎: PowerShell SecHunter | 报告自动生成，绝密数据请妥善保管</div>
        </div>
    </body>
    </html>
"@
    
    $htmlTemplate | Out-File -FilePath $reportPath -Encoding UTF8
    Write-Host "`n[+] 🎉 应急响应战报已生成: $reportPath" -ForegroundColor Magenta
}

# ==========================================
# 🚀 调度入口 (Main Runner)
# ==========================================
function Invoke-SecHunter {
    Clear-Host
    Write-Host @"
===================================================================
      [ Windows 高级威胁狩猎与应急响应引擎 (SecHunter) ]      
      执行模式: 深度内存与行为扫描 + 自动化 HTML 战报输出
===================================================================
"@ -ForegroundColor Cyan

    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "[-] 严重错误: 必须以管理员权限(Run as Administrator)运行此脚本！" -ForegroundColor Red
        Exit
    }

    try {
        Check-Persistence
        Check-ProcessMemory
        Check-Network
        Check-EventLogs
        Check-Accounts
        Check-DefenseEvasion
        Check-ServerRoles
        
        # 核心环节：执行完毕后渲染并导出 HTML 大屏
        Generate-HtmlReport
        
        Write-Host "`n===================================================================" -ForegroundColor Cyan
        Write-Host "[+] 扫描任务结束。请将生成的 HTML 报告移交至安全运营中心 (SOC) 闭环。" -ForegroundColor Green
        Write-Host "===================================================================" -ForegroundColor Cyan
    } catch {
        Write-Host "`n[-] 扫描过程发生意外错误: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# 执行主函数
Invoke-SecHunter
