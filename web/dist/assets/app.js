        // ========== 全局变量 ==========
        let ws = null;
        let allEvents = [];
        let execveEvents = [];
        let networkEvents = [];
        let alertEvents = [];
        let currentTab = 'all';
        let startTime = Date.now();
        let eventCountLastSecond = 0;
        let lastRateUpdate = Date.now();
        let alertHistoryLoaded = false;
        
        // 策略状态（客户端缓存，避免突显已停用的事件）
        let policyState = {
            execveEnabled: true,
            networkEnabled: true
        };

        let networkWhitelistRules = [];
        let adminToken = localStorage.getItem('sentinelAdminToken') || '';

        // 系统指标
        let systemStats = {
            cpuUsage: 0,
            memoryUsage: 0,
            netSpeedIn: 0,
            netSpeedOut: 0
        };

        const networkSpeedHistoryLimit = 60;
        let networkSpeedHistory = [];
        let networkSearchQuery = '';
        
        // ========== WebSocket连接 ==========
        function connect() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${window.location.host}/ws`;
            
            updateConnectionStatus('connecting', '连接中...');
            
            ws = new WebSocket(wsUrl);
            
            ws.onopen = () => {
                console.log('WebSocket connected');
                updateConnectionStatus('connected', '已连接');
                loadPolicyStatus();
                loadAlertConfig();
                loadNetworkWhitelist();
                if (!alertHistoryLoaded) {
                    loadAlertHistory();
                    alertHistoryLoaded = true;
                }
            };
            
            ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    handleEvent(data);
                } catch (e) {
                    console.error('Failed to parse message:', e);
                }
            };
            
            ws.onclose = () => {
                console.log('WebSocket disconnected');
                updateConnectionStatus('disconnected', '已断开');
                setTimeout(connect, 3000);
            };
            
            ws.onerror = (error) => {
                console.error('WebSocket error:', error);
                updateConnectionStatus('disconnected', '错误');
            };
        }
        
        function updateConnectionStatus(status, text) {
            const el = document.getElementById('connectionStatus');
            el.className = `connection-status ${status}`;
            el.textContent = text;
        }
        
        // ========== 标签页切换 ==========
        function switchTab(tab, element) {
            currentTab = tab;

            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            if (element) {
                element.classList.add('active');
            } else {
                document.querySelector(`.tab:nth-child(${getTabIndex(tab)})`).classList.add('active');
            }

            document.getElementById('all-events').classList.toggle('hidden', tab !== 'all');
            document.getElementById('execve-events').classList.toggle('hidden', tab !== 'execve');
            document.getElementById('network-events').classList.toggle('hidden', tab !== 'network');
            document.getElementById('alert-events').classList.toggle('hidden', tab !== 'alert');

            if (tab === 'execve') {
                startProcessPolling();
            } else {
                stopProcessPolling();
            }

            if (tab === 'network') {
                drawNetworkSpeedChart();
            }
        }
        
        function getTabIndex(tab) {
            const tabs = ['all', 'execve', 'network', 'alert'];
            return tabs.indexOf(tab) + 1;
        }
        
        // ========== 事件处理 ==========
        function handleEvent(data) {
            if (!data.type || !data.data) return;

            if (data.type === 'system') {
                updateSystemStats(data.data);
                return;
            }

            // Client-side gate: drop events for disabled monitors
            if (data.type === 'execve' && !policyState.execveEnabled) return;
            if (data.type === 'network' && !policyState.networkEnabled) return;

            eventCountLastSecond++;

            const event = {
                type: data.type,
                timestamp: Date.now(),
                ...data.data
            };

            allEvents.unshift(event);
            if (allEvents.length > 500) allEvents = allEvents.slice(0, 500);

            if (data.type === 'execve') {
                execveEvents.unshift(event);
                if (execveEvents.length > 500) execveEvents = execveEvents.slice(0, 500);
            } else if (data.type === 'network') {
                networkEvents.unshift(event);
                if (networkEvents.length > 500) networkEvents = networkEvents.slice(0, 500);
                renderNetworkEvents();
            } else if (data.type === 'alert') {
                alertEvents.unshift(event);
                if (alertEvents.length > 500) alertEvents = alertEvents.slice(0, 500);
                renderAlertEvent(event);
            }

            renderAllEvent(event);
            updateStats();
        }
        
        function updateSystemStats(data) {
            let hasNetworkSpeed = false;

            // 更新CPU使用率
            if (data.cpu_usage !== undefined) {
                systemStats.cpuUsage = parseFloat(data.cpu_usage);
                document.getElementById('cpuUsage').textContent = systemStats.cpuUsage.toFixed(1) + '%';
            }

            if (data.memory_usage !== undefined) {
                systemStats.memoryUsage = parseFloat(data.memory_usage);
                document.getElementById('memoryUsage').textContent = systemStats.memoryUsage.toFixed(1) + '%';
            }
            
            // 更新下载速度
            if (data.net_speed_in !== undefined) {
                systemStats.netSpeedIn = parseFloat(data.net_speed_in);
                document.getElementById('netSpeedIn').textContent = formatSpeed(systemStats.netSpeedIn);
                hasNetworkSpeed = true;
            }
            
            // 更新上传速度
            if (data.net_speed_out !== undefined) {
                systemStats.netSpeedOut = parseFloat(data.net_speed_out);
                document.getElementById('netSpeedOut').textContent = formatSpeed(systemStats.netSpeedOut);
                hasNetworkSpeed = true;
            }

            if (hasNetworkSpeed) {
                addNetworkSpeedSample(systemStats.netSpeedIn, systemStats.netSpeedOut);
            }
        }

        function addNetworkSpeedSample(speedIn, speedOut) {
            networkSpeedHistory.push({
                timestamp: Date.now(),
                in: Number.isFinite(speedIn) ? speedIn : 0,
                out: Number.isFinite(speedOut) ? speedOut : 0
            });

            if (networkSpeedHistory.length > networkSpeedHistoryLimit) {
                networkSpeedHistory = networkSpeedHistory.slice(-networkSpeedHistoryLimit);
            }

            drawNetworkSpeedChart();
        }

        function drawNetworkSpeedChart() {
            const canvas = document.getElementById('networkSpeedChart');
            if (!canvas) return;

            const parent = canvas.parentElement;
            const width = Math.max(parent.clientWidth, 320);
            const height = Math.max(parent.clientHeight, 220);
            const ratio = window.devicePixelRatio || 1;

            if (canvas.width !== Math.floor(width * ratio) || canvas.height !== Math.floor(height * ratio)) {
                canvas.width = Math.floor(width * ratio);
                canvas.height = Math.floor(height * ratio);
            }

            const ctx = canvas.getContext('2d');
            ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
            ctx.clearRect(0, 0, width, height);

            const padding = { top: 18, right: 18, bottom: 28, left: 64 };
            const chartWidth = width - padding.left - padding.right;
            const chartHeight = height - padding.top - padding.bottom;
            const maxSpeed = Math.max(1, ...networkSpeedHistory.flatMap(point => [point.in, point.out]));
            const yMax = niceSpeedCeil(maxSpeed);

            drawChartGrid(ctx, padding, chartWidth, chartHeight, yMax);

            if (networkSpeedHistory.length === 0) {
                ctx.fillStyle = '#64748b';
                ctx.font = '13px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif';
                ctx.textAlign = 'center';
                ctx.fillText('等待网速数据...', width / 2, height / 2);
                return;
            }

            drawSpeedLine(ctx, networkSpeedHistory.map(point => point.in), '#22c55e', padding, chartWidth, chartHeight, yMax);
            drawSpeedLine(ctx, networkSpeedHistory.map(point => point.out), '#38bdf8', padding, chartWidth, chartHeight, yMax);
        }

        function drawChartGrid(ctx, padding, chartWidth, chartHeight, yMax) {
            ctx.strokeStyle = '#1e293b';
            ctx.lineWidth = 1;
            ctx.fillStyle = '#94a3b8';
            ctx.font = '12px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif';
            ctx.textAlign = 'right';
            ctx.textBaseline = 'middle';

            for (let i = 0; i <= 4; i++) {
                const y = padding.top + (chartHeight / 4) * i;
                const value = yMax - (yMax / 4) * i;

                ctx.beginPath();
                ctx.moveTo(padding.left, y);
                ctx.lineTo(padding.left + chartWidth, y);
                ctx.stroke();

                ctx.fillText(formatSpeed(value), padding.left - 10, y);
            }

            ctx.textAlign = 'center';
            ctx.textBaseline = 'top';
            ctx.fillStyle = '#64748b';
            ctx.fillText('-60s', padding.left, padding.top + chartHeight + 10);
            ctx.fillText('现在', padding.left + chartWidth, padding.top + chartHeight + 10);
        }

        function drawSpeedLine(ctx, values, color, padding, chartWidth, chartHeight, yMax) {
            if (values.length === 0) return;

            ctx.strokeStyle = color;
            ctx.lineWidth = 2;
            ctx.lineJoin = 'round';
            ctx.lineCap = 'round';
            ctx.beginPath();

            values.forEach((value, index) => {
                const denominator = Math.max(networkSpeedHistoryLimit - 1, 1);
                const x = padding.left + chartWidth - ((values.length - 1 - index) / denominator) * chartWidth;
                const y = padding.top + chartHeight - (Math.min(value, yMax) / yMax) * chartHeight;

                if (index === 0) {
                    ctx.moveTo(x, y);
                } else {
                    ctx.lineTo(x, y);
                }
            });

            ctx.stroke();

            const latest = values[values.length - 1];
            const latestX = padding.left + chartWidth;
            const latestY = padding.top + chartHeight - (Math.min(latest, yMax) / yMax) * chartHeight;
            ctx.fillStyle = color;
            ctx.beginPath();
            ctx.arc(latestX, latestY, 3, 0, Math.PI * 2);
            ctx.fill();
        }

        function niceSpeedCeil(value) {
            const magnitude = Math.pow(10, Math.floor(Math.log10(value)));
            const normalized = value / magnitude;

            if (normalized <= 2) return 2 * magnitude;
            if (normalized <= 5) return 5 * magnitude;
            return 10 * magnitude;
        }
        
        function formatSpeed(kbPerSec) {
            if (kbPerSec >= 1024) {
                return (kbPerSec / 1024).toFixed(1) + ' MB/s';
            }
            return kbPerSec.toFixed(1) + ' KB/s';
        }

        function formatSize(bytes) {
            if (bytes >= 1024 * 1024) {
                return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
            }
            if (bytes >= 1024) {
                return (bytes / 1024).toFixed(1) + ' KB';
            }
            return bytes + ' B';
        }
        
        function renderAllEvent(event) {
            const tbody = document.getElementById('allEventsBody');
            const emptyState = document.getElementById('allEmptyState');
            
            emptyState.style.display = 'none';
            
            const row = document.createElement('tr');
            const time = new Date(event.timestamp).toLocaleTimeString('zh-CN');
            
            let details = '';
            if (event.type === 'execve') {
                details = `PID=${event.pid} PPID=${event.ppid} ${escapeHtml(event.comm)}: ${escapeHtml(event.argv0)}`;
            } else if (event.type === 'network') {
                details = `${event.protocol} ${event.direction} ${event.src_ip}:${event.src_port} -> ${event.dst_ip}:${event.dst_port} (${formatSize(event.packet_size)})`;
            } else if (event.type === 'alert') {
                details = `[${escapeHtml(event.severity)}] ${escapeHtml(event.rule_id)}: ${escapeHtml(event.message)}`;
            }
            
            row.innerHTML = `
                <td><span class="badge badge-${event.type}">${event.type}</span></td>
                <td class="time">${time}</td>
                <td>${details}</td>
            `;
            
            tbody.insertBefore(row, tbody.firstChild);
            while (tbody.children.length > 500) tbody.removeChild(tbody.lastChild);
        }
        
        function renderExecveEvent(event) {
            const tbody = document.getElementById('execveBody');
            const emptyState = document.getElementById('execveEmptyState');
            
            emptyState.style.display = 'none';
            
            const row = document.createElement('tr');
            const time = new Date(event.timestamp).toLocaleTimeString('zh-CN');
            
            row.innerHTML = `
                <td><span class="badge badge-execve">execve</span></td>
                <td class="time">${time}</td>
                <td class="pid">${event.pid}</td>
                <td class="ppid">${event.ppid}</td>
                <td class="comm">${escapeHtml(event.comm)}</td>
                <td class="argv0" title="${escapeHtml(event.argv0)}">${escapeHtml(event.argv0)}</td>
                <td>
                    <button class="btn btn-danger btn-small" onclick="killProcess(${event.pid}, '${escapeHtml(event.comm)}')">终止</button>
                </td>
            `;
            
            tbody.insertBefore(row, tbody.firstChild);
            while (tbody.children.length > 500) tbody.removeChild(tbody.lastChild);
        }
        
        function filterNetworkEvents(query) {
            networkSearchQuery = query.trim().toLowerCase();
            renderNetworkEvents();
        }

        function renderNetworkEvents() {
            const tbody = document.getElementById('networkBody');
            const emptyState = document.getElementById('networkEmptyState');
            const countEl = document.getElementById('networkFilterCount');
            const events = filteredNetworkEvents();

            tbody.innerHTML = '';
            countEl.textContent = events.length + ' / ' + networkEvents.length + ' events';

            if (events.length === 0) {
                emptyState.style.display = 'block';
                if (networkSearchQuery) {
                    emptyState.innerHTML = '<div class="empty-state-icon">🔍</div><p>未找到匹配的网络事件</p>';
                } else if (hasActiveNetworkWhitelist()) {
                    emptyState.innerHTML = '<div class="empty-state-icon">🌐</div><p>暂无命中网络白名单的事件</p>';
                } else {
                    emptyState.innerHTML = '<div class="empty-state-icon">🌐</div><p>等待网络事件...</p>';
                }
                return;
            }

            emptyState.style.display = 'none';
            const fragment = document.createDocumentFragment();
            events.slice(0, 500).forEach(event => {
                fragment.appendChild(createNetworkEventRow(event));
            });
            tbody.appendChild(fragment);
        }

        function filteredNetworkEvents() {
            const whitelist = activeNetworkWhitelist();
            const whitelistFiltered = networkEvents.filter(event => networkEventMatchesWhitelist(event, whitelist));
            if (!networkSearchQuery) {
                return whitelistFiltered;
            }
            return whitelistFiltered.filter(event => networkEventSearchText(event).includes(networkSearchQuery));
        }

        function activeNetworkWhitelist() {
            const ips = new Set();
            const ports = new Set();

            networkWhitelistRules.forEach(rule => {
                if (!rule.enabled) return;
                if (rule.type === 'ip') {
                    ips.add(String(rule.value).trim());
                } else if (rule.type === 'port') {
                    const port = Number(rule.value);
                    if (Number.isInteger(port) && port > 0) {
                        ports.add(port);
                    }
                }
            });

            return {
                ips,
                ports,
                hasIP: ips.size > 0,
                hasPort: ports.size > 0
            };
        }

        function hasActiveNetworkWhitelist() {
            const whitelist = activeNetworkWhitelist();
            return whitelist.hasIP || whitelist.hasPort;
        }

        function networkEventMatchesWhitelist(event, whitelist) {
            if (!whitelist.hasIP && !whitelist.hasPort) {
                return true;
            }

            if (whitelist.hasIP && !whitelist.ips.has(String(event.src_ip)) && !whitelist.ips.has(String(event.dst_ip))) {
                return false;
            }

            if (whitelist.hasPort && !whitelist.ports.has(Number(event.src_port)) && !whitelist.ports.has(Number(event.dst_port))) {
                return false;
            }

            return true;
        }

        function networkEventSearchText(event) {
            return [
                event.type,
                event.pid,
                event.protocol,
                event.protocol_id,
                event.direction,
                event.direction_id,
                event.src_ip,
                event.src_port,
                event.dst_ip,
                event.dst_port,
                event.packet_size,
                event.comm
            ].filter(value => value !== undefined && value !== null)
             .join(' ')
             .toLowerCase();
        }

        function createNetworkEventRow(event) {
            const row = document.createElement('tr');
            const time = new Date(event.timestamp).toLocaleTimeString('zh-CN');
            const protocolClass = `badge-${event.protocol.toLowerCase()}`;
            const directionClass = event.direction === 'ingress' ? 'direction-ingress' : 'direction-egress';
            
            row.innerHTML = `
                <td><span class="badge badge-network">network</span></td>
                <td class="time">${time}</td>
                <td class="pid">${event.pid}</td>
                <td><span class="badge ${protocolClass}">${event.protocol}</span></td>
                <td><span class="direction ${directionClass}">${event.direction}</span></td>
                <td class="ip">${event.src_ip}:${event.src_port}</td>
                <td class="ip">${event.dst_ip}:${event.dst_port}</td>
                <td class="packet-size">${formatSize(event.packet_size)}</td>
                <td class="comm">${escapeHtml(event.comm)}</td>
            `;
            return row;
        }

        function renderAlertEvent(event) {
            const tbody = document.getElementById('alertBody');
            const emptyState = document.getElementById('alertEmptyState');

            emptyState.style.display = 'none';

            const row = document.createElement('tr');
            const time = new Date(event.timestamp).toLocaleTimeString('zh-CN');
            const severity = event.severity || 'info';
            const pid = extractAlertPid(event);
            const status = normalizeAlertStatus(event.status);
            const alertId = Number(event.id || 0);
            const action = pid && status === 'active'
                ? `<button class="btn btn-danger btn-small" onclick="killProcess(${pid}, 'PID ${pid}', ${alertId || 'null'})">终止进程</button>`
                : '<span class="time">-</span>';

            if (alertId) {
                row.dataset.alertId = String(alertId);
            }
            row.innerHTML = `
                <td><span class="badge badge-${escapeHtml(severity)}">${escapeHtml(severity)}</span></td>
                <td class="time">${time}</td>
                <td><span class="badge badge-alert">${escapeHtml(event.rule_id || 'alert')}</span></td>
                <td>${escapeHtml(event.source_type || '-')}</td>
                <td>${escapeHtml(event.message || '')}</td>
                <td class="alert-status-cell">${renderAlertStatus(status)}</td>
                <td>${action}</td>
            `;

            tbody.insertBefore(row, tbody.firstChild);
            while (tbody.children.length > 500) tbody.removeChild(tbody.lastChild);
        }

        function loadAlertHistory() {
            fetch('/api/alerts')
                .then(res => {
                    if (!res.ok) {
                        throw new Error('HTTP ' + res.status);
                    }
                    return res.json();
                })
                .then(data => {
                    const tbody = document.getElementById('alertBody');
                    if (!Array.isArray(data) || data.length === 0) {
                        return;
                    }

                    tbody.innerHTML = '';
                    alertEvents = [];
                    data.slice().reverse().forEach(item => {
                        const event = {
                            type: 'alert',
                            timestamp: item.created_at ? new Date(item.created_at).getTime() : Date.now(),
                            rule_id: item.rule_id,
                            severity: item.severity,
                            source_type: item.source_type,
                            message: item.message,
                            details: parseAlertDetails(item.details),
                            id: item.id,
                            status: item.status || 'active'
                        };
                        alertEvents.unshift(event);
                        renderAlertEvent(event);
                    });
                    updateStats();
                })
                .catch(err => console.error('Failed to load alert history:', err));
        }

        function parseAlertDetails(details) {
            if (!details) return {};
            if (typeof details === 'object') return details;
            try {
                return JSON.parse(details);
            } catch (e) {
                return {};
            }
        }

        function extractAlertPid(event) {
            const details = parseAlertDetails(event.details);
            const pid = Number(details.pid || event.pid);
            return Number.isInteger(pid) && pid > 0 ? pid : null;
        }

        function normalizeAlertStatus(status) {
            return status || 'active';
        }

        function renderAlertStatus(status) {
            const labels = {
                active: '未处理',
                terminated: '已终止',
                exited: '已退出',
                failed: '处理失败',
                resolved: '已处理',
                ignored: '已忽略'
            };
            const safeStatus = normalizeAlertStatus(status);
            return `<span class="alert-status alert-status-${escapeHtml(safeStatus)}">${escapeHtml(labels[safeStatus] || safeStatus)}</span>`;
        }
        
        // ========== 进程治理 ==========
        function killProcess(pid, comm, alertId = null) {
            if (!policyState.execveEnabled) {
                alert('进程管理已被策略禁用');
                return;
            }

            showConfirm(`确定要终止进程 "${comm}" (PID: ${pid}) 吗？`, () => {
                fetch(`/api/process/kill/${pid}`, { method: 'POST' })
                    .then(res => res.json())
                    .then(data => {
                        if (data.error) {
                            if (data.code === 'process_not_found') {
                                markAlertStatus(alertId, 'exited');
                                loadProcesses();
                                alert(data.message || '进程已退出');
                                return;
                            }
                            throw new Error(data.error);
                        }
                        markAlertStatus(alertId, 'terminated');
                        loadProcesses();
                        alert(data.message || '操作成功');
                    })
                    .catch(err => {
                        if (alertId) {
                            markAlertStatus(alertId, 'failed');
                        }
                        alert('操作失败: ' + err.message);
                    });
            });
        }

        function markAlertStatus(alertId, status) {
            if (!alertId) return;

            updateAlertStatusInView(alertId, status);
            fetch(`/api/alerts/${alertId}/status`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status })
            })
                .then(res => res.json())
                .then(data => {
                    if (data.error) {
                        throw new Error(data.error);
                    }
                    updateAlertStatusInView(alertId, data.status || status);
                })
                .catch(err => console.error('Failed to update alert status:', err));
        }

        function updateAlertStatusInView(alertId, status) {
            alertEvents = alertEvents.map(event => {
                if (Number(event.id) === Number(alertId)) {
                    return { ...event, status };
                }
                return event;
            });

            const row = document.querySelector(`tr[data-alert-id="${alertId}"]`);
            if (!row) return;

            const statusCell = row.querySelector('.alert-status-cell');
            if (statusCell) {
                statusCell.innerHTML = renderAlertStatus(status);
            }
            if (status !== 'active') {
                const button = row.querySelector('button');
                if (button) {
                    button.remove();
                }
            }
        }
        
        function forceKillProcess(pid, comm) {
            if (!policyState.execveEnabled) {
                alert('进程管理已被策略禁用');
                return;
            }

            showConfirm(`确定要强制终止进程 "${comm}" (PID: ${pid}) 吗？此操作不可恢复。`, () => {
                fetch(`/api/process/kill/${pid}/force`, { method: 'POST' })
                    .then(res => res.json())
                    .then(data => {
                        if (data.error) {
                            throw new Error(data.error);
                        }
                        loadProcesses();
                        alert(data.message || '操作成功');
                    })
                    .catch(err => {
                        alert('操作失败: ' + err.message);
                    });
            });
        }
        
        // ========== btop 进程监控 ==========
        let processes = [];
        let filteredProcesses = [];
        let processSortField = 'cpu_percent';
        let processSortAsc = false;
        let processPollInterval = null;
        let processSearchQuery = '';

        function loadProcesses() {
            if (!policyState.execveEnabled) {
                processes = [];
                applyFilterAndSort();
                return;
            }

            fetch('/api/processes')
                .then(res => res.json())
                .then(data => {
                    if (data.error) {
                        throw new Error(data.error);
                    }
                    if (data.process_management_enabled === false) {
                        policyState.execveEnabled = false;
                        updateProcessPolicyState(false);
                        return;
                    }
                    processes = data.processes || [];
                    applyFilterAndSort();
                })
                .catch(err => console.error('Failed to load processes:', err));
        }

        function filterProcesses(query) {
            processSearchQuery = query.trim().toLowerCase();
            applyFilterAndSort();
        }

        function applyFilterAndSort() {
            if (processSearchQuery) {
                const q = processSearchQuery;
                filteredProcesses = processes.filter(p => {
                    return (p.name && p.name.toLowerCase().includes(q)) ||
                           String(p.pid).includes(q) ||
                           (p.username && p.username.toLowerCase().includes(q)) ||
                           (p.status && p.status.toLowerCase().includes(q)) ||
                           (p.cmdline && p.cmdline.toLowerCase().includes(q));
                });
            } else {
                filteredProcesses = processes.slice();
            }

            filteredProcesses.sort((a, b) => {
                let va = a[processSortField];
                let vb = b[processSortField];
                if (typeof va === 'string') va = va.toLowerCase();
                if (typeof vb === 'string') vb = vb.toLowerCase();
                if (va < vb) return processSortAsc ? -1 : 1;
                if (va > vb) return processSortAsc ? 1 : -1;
                return 0;
            });

            renderProcesses();
        }

        function renderProcesses() {
            const tbody = document.getElementById('execveBody');
            const emptyState = document.getElementById('execveEmptyState');
            const countEl = document.getElementById('processCount');

            if (filteredProcesses.length === 0) {
                tbody.innerHTML = '';
                emptyState.style.display = 'block';
                if (!policyState.execveEnabled) {
                    emptyState.innerHTML = '<div class="empty-state-icon">⚙️</div><p>进程管理已被策略禁用</p>';
                } else {
                    emptyState.innerHTML = processSearchQuery
                        ? '<div class="empty-state-icon">🔍</div><p>未找到匹配的进程</p>'
                        : '<div class="empty-state-icon">⚙️</div><p>加载进程中...</p>';
                }
                countEl.textContent = '0 / ' + processes.length + ' processes';
                return;
            }

            emptyState.style.display = 'none';
            countEl.textContent = filteredProcesses.length + ' / ' + processes.length + ' processes';

            const visibleProcs = filteredProcesses.slice(0, 200);
            const existingRows = new Map();
            tbody.querySelectorAll('tr[data-pid]').forEach(row => {
                existingRows.set(row.getAttribute('data-pid'), row);
            });

            const newPids = new Set();
            const fragment = document.createDocumentFragment();

            visibleProcs.forEach(p => {
                const pidKey = String(p.pid);
                newPids.add(pidKey);
                const existingRow = existingRows.get(pidKey);

                if (existingRow) {
                    updateProcessRow(existingRow, p);
                } else {
                    const newRow = createProcessRow(p);
                    newRow.classList.add('new-row');
                    setTimeout(() => newRow.classList.remove('new-row'), 500);
                    fragment.appendChild(newRow);
                }
            });

            if (fragment.childNodes.length > 0) {
                tbody.appendChild(fragment);
            }

            existingRows.forEach((row, pidKey) => {
                if (!newPids.has(pidKey)) {
                    row.classList.add('removing');
                    setTimeout(() => {
                        if (row.parentNode) row.parentNode.removeChild(row);
                    }, 300);
                }
            });

            const pidOrder = visibleProcs.map(p => String(p.pid));
            let prevRow = null;
            pidOrder.forEach(pidKey => {
                const row = existingRows.get(pidKey) || tbody.querySelector(`tr[data-pid="${pidKey}"]`);
                if (row) {
                    if (prevRow && prevRow.nextElementSibling !== row) {
                        tbody.insertBefore(row, prevRow.nextElementSibling);
                    } else if (!prevRow && tbody.firstElementChild !== row) {
                        tbody.insertBefore(row, tbody.firstElementChild);
                    }
                    prevRow = row;
                }
            });
        }

        function createProcessRow(p) {
            const tr = document.createElement('tr');
            tr.setAttribute('data-pid', p.pid);
            tr.innerHTML = `
                <td class="pid-cell">${p.pid}</td>
                <td>
                    <div class="cpu-bar">
                        <div class="cpu-bar-fill" style="width: ${Math.min(p.cpu_percent || 0, 100)}%; background: ${getCPUColor(p.cpu_percent || 0)}"></div>
                        <div class="bar-text">${(p.cpu_percent || 0).toFixed(1)}%</div>
                    </div>
                </td>
                <td>
                    <div class="mem-bar">
                        <div class="mem-bar-fill" style="width: ${Math.min(p.mem_percent, 100)}%; background: ${getMEMColor(p.mem_percent)}"></div>
                        <div class="bar-text">${p.mem_percent.toFixed(1)}%</div>
                    </div>
                </td>
                <td class="rss-cell">${formatBytes(p.mem_rss)}</td>
                <td class="name-cell" title="${escapeHtml(p.cmdline || p.name)}">${escapeHtml(p.name)}</td>
                <td>
                    <button class="btn btn-danger btn-small" onclick="killProcess(${p.pid}, '${escapeHtml(p.name)}')">终止</button>
                </td>
            `;
            return tr;
        }

        function updateProcessRow(row, p) {
            const cpuFill = row.querySelector('.cpu-bar-fill');
            const cpuText = row.querySelector('.cpu-bar .bar-text');
            const memFill = row.querySelector('.mem-bar-fill');
            const memText = row.querySelector('.mem-bar .bar-text');
            const rssCell = row.querySelector('.rss-cell');
            const nameCell = row.querySelector('.name-cell');

            const cpu = p.cpu_percent || 0;
            if (cpuFill) {
                cpuFill.style.width = Math.min(cpu, 100) + '%';
                cpuFill.style.background = getCPUColor(cpu);
            }
            if (cpuText) cpuText.textContent = cpu.toFixed(1) + '%';
            if (memFill) {
                memFill.style.width = Math.min(p.mem_percent, 100) + '%';
                memFill.style.background = getMEMColor(p.mem_percent);
            }
            if (memText) memText.textContent = p.mem_percent.toFixed(1) + '%';
            if (rssCell) rssCell.textContent = formatBytes(p.mem_rss);
            if (nameCell) {
                nameCell.title = escapeHtml(p.cmdline || p.name);
                nameCell.textContent = escapeHtml(p.name);
            }
        }

        function sortProcesses(field, keepDirection) {
            if (!keepDirection) {
                if (processSortField === field) {
                    processSortAsc = !processSortAsc;
                } else {
                    processSortField = field;
                    processSortAsc = false;
                }
            }

            document.querySelectorAll('.sort-indicator').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.sort-indicator').forEach(el => el.textContent = '');

            const indicator = document.getElementById('sort-' + field);
            if (indicator) {
                indicator.textContent = processSortAsc ? '▲' : '▼';
                indicator.classList.add('active');
            }

            applyFilterAndSort();
        }

        function getCPUColor(percent) {
            if (percent < 10) return '#3b82f6';
            if (percent < 25) return '#60a5fa';
            if (percent < 50) return '#a78bfa';
            if (percent < 75) return '#c084fc';
            return '#e879f9';
        }

        function getMEMColor(percent) {
            if (percent < 5) return '#3b82f6';
            if (percent < 15) return '#60a5fa';
            if (percent < 30) return '#a78bfa';
            if (percent < 50) return '#c084fc';
            return '#e879f9';
        }

        function formatBytes(bytes) {
            if (bytes >= 1024 * 1024 * 1024) return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
            if (bytes >= 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
            if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KB';
            return bytes + ' B';
        }

        function startProcessPolling() {
            if (!policyState.execveEnabled) {
                processes = [];
                applyFilterAndSort();
                return;
            }
            if (processPollInterval) return;
            loadProcesses();
            processPollInterval = setInterval(loadProcesses, 5000);
        }

        function stopProcessPolling() {
            if (processPollInterval) {
                clearInterval(processPollInterval);
                processPollInterval = null;
            }
        }

        // ========== 策略管理 ==========
        function loadPolicyStatus() {
            fetch('/api/policy/status')
                .then(res => res.json())
                .then(data => {
                    policyState.execveEnabled = data.execve_enabled;
                    policyState.networkEnabled = data.network_enabled;
                    updateProcessPolicyState(data.execve_enabled);
                    document.getElementById('networkToggle').checked = data.network_enabled;
                    updateStatusBadge('network', data.network_enabled);
                })
                .catch(err => console.error('Failed to load policy status:', err));
        }

        function loadAlertConfig() {
            fetch('/api/alert/config')
                .then(res => res.json())
                .then(data => {
                    if (data.error) {
                        throw new Error(data.error);
                    }
                    document.getElementById('alertCpuThreshold').value = data.cpu_threshold;
                    document.getElementById('alertMemoryThreshold').value = data.memory_threshold;
                    document.getElementById('alertNetSpeedThreshold').value = data.net_speed_threshold_kb;
                    document.getElementById('alertPacketSizeLimit').value = data.packet_size_limit;
                    document.getElementById('alertCooldownSeconds').value = data.cooldown_seconds;
                    document.getElementById('alertCorrelationWindowSeconds').value = data.correlation_window_seconds;
                    document.getElementById('alertMaxTimeGapSeconds').value = data.max_time_gap_seconds;
                    document.getElementById('alertExfilSizeThresholdBytes').value = data.exfil_size_threshold_bytes;
                    document.getElementById('singleMetricAlertsEnabled').checked = Boolean(data.single_metric_alerts_enabled);
                })
                .catch(err => console.error('Failed to load alert config:', err));
        }

        function loadNetworkWhitelist() {
            fetch('/api/whitelist')
                .then(res => res.json())
                .then(data => {
                    if (data.error) {
                        throw new Error(data.error);
                    }
                    networkWhitelistRules = data
                        .filter(rule => rule.type === 'ip' || rule.type === 'port')
                        .sort((a, b) => {
                            if (a.type === b.type) return String(a.value).localeCompare(String(b.value));
                            return a.type.localeCompare(b.type);
                        });
                    renderNetworkWhitelist();
                    renderNetworkEvents();
                })
                .catch(err => {
                    setNetworkWhitelistStatus('规则加载失败');
                    console.error('Failed to load network whitelist:', err);
                });
        }

        function renderNetworkWhitelist() {
            const tbody = document.getElementById('networkWhitelistBody');
            const summary = document.getElementById('networkWhitelistSummary');
            if (!tbody || !summary) return;

            const enabledRules = networkWhitelistRules.filter(rule => rule.enabled);
            const ipCount = enabledRules.filter(rule => rule.type === 'ip').length;
            const portCount = enabledRules.filter(rule => rule.type === 'port').length;
            summary.textContent = `启用 ${enabledRules.length} 条规则，IP ${ipCount} 条，端口 ${portCount} 条`;

            if (networkWhitelistRules.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" class="empty-cell">暂无网络白名单规则</td></tr>';
                return;
            }

            tbody.innerHTML = networkWhitelistRules.map(rule => {
                const enabled = Boolean(rule.enabled);
                const nextEnabled = enabled ? 'false' : 'true';
                const toggleLabel = enabled ? '停用' : '启用';
                const typeLabel = rule.type === 'ip' ? 'IP' : '端口';
                return `
                    <tr>
                        <td><span class="whitelist-type">${typeLabel}</span></td>
                        <td><span class="whitelist-value">${escapeHtml(rule.value)}</span></td>
                        <td>${renderWhitelistStatus(enabled)}</td>
                        <td>
                            <div class="whitelist-actions">
                                <button class="btn btn-secondary btn-small" onclick="toggleNetworkWhitelistRule(${Number(rule.id)}, ${nextEnabled})">${toggleLabel}</button>
                                <button class="btn btn-danger btn-small" onclick="deleteNetworkWhitelistRule(${Number(rule.id)})">删除</button>
                            </div>
                        </td>
                    </tr>
                `;
            }).join('');
        }

        function renderWhitelistStatus(enabled) {
            return enabled
                ? '<span class="status-badge status-enabled">已启用</span>'
                : '<span class="status-badge status-disabled">已停用</span>';
        }

        function addNetworkWhitelistRule(event) {
            event.preventDefault();

            const type = document.getElementById('networkWhitelistType').value;
            const valueEl = document.getElementById('networkWhitelistValue');
            const value = valueEl.value.trim();
            const enabled = document.getElementById('networkWhitelistEnabled').checked;
            if (!value) return;

            setNetworkWhitelistStatus('添加中...');
            fetch('/api/whitelist', {
                method: 'POST',
                headers: mutationHeaders(true),
                body: JSON.stringify({ type, value, enabled })
            })
                .then(res => res.json())
                .then(data => {
                    if (data.error) {
                        throw new Error(data.error);
                    }
                    valueEl.value = '';
                    setNetworkWhitelistStatus('已添加');
                    loadNetworkWhitelist();
                    setTimeout(() => setNetworkWhitelistStatus(''), 2000);
                })
                .catch(err => {
                    setNetworkWhitelistStatus('添加失败');
                    alert('操作失败: ' + err.message);
                });
        }

        function toggleNetworkWhitelistRule(id, enabled) {
            setNetworkWhitelistStatus('更新中...');
            fetch(`/api/whitelist/${id}`, {
                method: 'PATCH',
                headers: mutationHeaders(true),
                body: JSON.stringify({ enabled })
            })
                .then(res => res.json())
                .then(data => {
                    if (data.error) {
                        throw new Error(data.error);
                    }
                    setNetworkWhitelistStatus('已更新');
                    loadNetworkWhitelist();
                    setTimeout(() => setNetworkWhitelistStatus(''), 2000);
                })
                .catch(err => {
                    setNetworkWhitelistStatus('更新失败');
                    alert('操作失败: ' + err.message);
                });
        }

        function deleteNetworkWhitelistRule(id) {
            setNetworkWhitelistStatus('删除中...');
            fetch(`/api/whitelist/${id}`, {
                method: 'DELETE',
                headers: mutationHeaders(false)
            })
                .then(res => res.json())
                .then(data => {
                    if (data.error) {
                        throw new Error(data.error);
                    }
                    setNetworkWhitelistStatus('已删除');
                    loadNetworkWhitelist();
                    setTimeout(() => setNetworkWhitelistStatus(''), 2000);
                })
                .catch(err => {
                    setNetworkWhitelistStatus('删除失败');
                    alert('操作失败: ' + err.message);
                });
        }

        function updateNetworkWhitelistPlaceholder() {
            const type = document.getElementById('networkWhitelistType').value;
            const input = document.getElementById('networkWhitelistValue');
            if (!input) return;
            input.placeholder = type === 'ip' ? '例如 192.168.1.10' : '例如 25665';
        }

        function setNetworkWhitelistStatus(text) {
            const statusEl = document.getElementById('networkWhitelistStatus');
            if (statusEl) statusEl.textContent = text;
        }

        function openSettingsModal() {
            loadPolicyStatus();
            loadAlertConfig();
            loadNetworkWhitelist();
            document.getElementById('settingsModal').classList.add('active');
        }

        function closeSettingsModal() {
            document.getElementById('settingsModal').classList.remove('active');
        }

        function saveAlertConfig(event) {
            event.preventDefault();
            const statusEl = document.getElementById('alertConfigStatus');
            const payload = {
                cpu_threshold: Number(document.getElementById('alertCpuThreshold').value),
                memory_threshold: Number(document.getElementById('alertMemoryThreshold').value),
                net_speed_threshold_kb: Number(document.getElementById('alertNetSpeedThreshold').value),
                packet_size_limit: Number(document.getElementById('alertPacketSizeLimit').value),
                cooldown_seconds: Number(document.getElementById('alertCooldownSeconds').value),
                correlation_window_seconds: Number(document.getElementById('alertCorrelationWindowSeconds').value),
                max_time_gap_seconds: Number(document.getElementById('alertMaxTimeGapSeconds').value),
                exfil_size_threshold_bytes: Number(document.getElementById('alertExfilSizeThresholdBytes').value),
                single_metric_alerts_enabled: document.getElementById('singleMetricAlertsEnabled').checked
            };

            statusEl.textContent = '保存中...';
            fetch('/api/alert/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
                .then(res => res.json())
                .then(data => {
                    if (data.error) {
                        throw new Error(data.error);
                    }
                    statusEl.textContent = '已保存';
                    setTimeout(() => {
                        if (statusEl.textContent === '已保存') statusEl.textContent = '';
                    }, 2000);
                })
                .catch(err => {
                    statusEl.textContent = '保存失败';
                    alert('操作失败: ' + err.message);
                });
        }
        
        function toggleExecve(enabled) {
            fetch(`/api/policy/execve/${enabled}`, { method: 'POST' })
                .then(res => res.json())
                .then(data => {
                    if (data.error) {
                        throw new Error(data.error);
                    }
                    updateProcessPolicyState(data.execve_enabled);
                })
                .catch(err => {
                    alert('操作失败: ' + err.message);
                    document.getElementById('execveToggle').checked = !enabled;
                });
        }
        
        function toggleNetwork(enabled) {
            fetch(`/api/policy/network/${enabled}`, { method: 'POST' })
                .then(res => res.json())
                .then(data => {
                    if (data.error) {
                        throw new Error(data.error);
                    }
                    policyState.networkEnabled = data.network_enabled;
                    document.getElementById('networkToggle').checked = data.network_enabled;
                    updateStatusBadge('network', data.network_enabled);
                })
                .catch(err => {
                    alert('操作失败: ' + err.message);
                    document.getElementById('networkToggle').checked = !enabled;
                });
        }
        
        function updateStatusBadge(type, enabled) {
            const badge = document.getElementById(`${type}Status`);
            if (enabled) {
                badge.className = 'status-badge status-enabled';
                badge.textContent = '已启用';
            } else {
                badge.className = 'status-badge status-disabled';
                badge.textContent = '已禁用';
            }
        }

        function updateProcessPolicyState(enabled) {
            policyState.execveEnabled = enabled;
            document.getElementById('execveToggle').checked = enabled;
            updateStatusBadge('execve', enabled);

            if (!enabled) {
                stopProcessPolling();
                processes = [];
                filteredProcesses = [];
                renderProcesses();
                return;
            }

            if (currentTab === 'execve') {
                startProcessPolling();
            }
        }
        
        // ========== 工具函数 ==========
        function updateStats() {
            document.getElementById('totalEvents').textContent = allEvents.length;
            document.getElementById('execveEvents').textContent = execveEvents.length;
            document.getElementById('networkEvents').textContent = networkEvents.length;
            document.getElementById('alertEvents').textContent = alertEvents.length;
            
            const uptime = Math.floor((Date.now() - startTime) / 1000);
            const minutes = Math.floor(uptime / 60).toString().padStart(2, '0');
            const seconds = (uptime % 60).toString().padStart(2, '0');
            document.getElementById('uptime').textContent = `${minutes}:${seconds}`;
        }
        
        function updateRate() {
            const now = Date.now();
            const elapsed = (now - lastRateUpdate) / 1000;
            
            if (elapsed >= 1) {
                const rate = Math.round(eventCountLastSecond / elapsed);
                document.getElementById('eventsPerSecond').textContent = rate;
                document.getElementById('rateValue').textContent = `${rate}/s`;
                
                const percentage = Math.min(rate, 100);
                document.getElementById('rateFill').style.width = `${percentage}%`;
                
                eventCountLastSecond = 0;
                lastRateUpdate = now;
            }
        }
        
        function clearEvents() {
            allEvents = [];
            execveEvents = [];
            networkEvents = [];
            alertEvents = [];
            
            document.getElementById('allEventsBody').innerHTML = '';
            document.getElementById('execveBody').innerHTML = '';
            document.getElementById('networkBody').innerHTML = '';
            document.getElementById('alertBody').innerHTML = '';
            
            document.getElementById('allEmptyState').style.display = 'block';
            document.getElementById('execveEmptyState').style.display = 'block';
            document.getElementById('networkEmptyState').style.display = 'block';
            document.getElementById('alertEmptyState').style.display = 'block';
            
            updateStats();
            renderNetworkEvents();
        }
        
        function reconnect() {
            if (ws) ws.close();
            connect();
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function mutationHeaders(jsonBody) {
            const headers = {};
            if (jsonBody) {
                headers['Content-Type'] = 'application/json';
            }
            const token = (document.getElementById('adminTokenInput')?.value || adminToken || '').trim();
            if (token) {
                headers.Authorization = `Bearer ${token}`;
            }
            return headers;
        }

        function saveAdminToken(value) {
            adminToken = value.trim();
            if (adminToken) {
                localStorage.setItem('sentinelAdminToken', adminToken);
            } else {
                localStorage.removeItem('sentinelAdminToken');
            }
        }

        function initializeAdminTokenInput() {
            const input = document.getElementById('adminTokenInput');
            if (input) {
                input.value = adminToken;
            }
            updateNetworkWhitelistPlaceholder();
        }
        
        // ========== 模态框 ==========
        function showConfirm(message, onConfirm) {
            document.getElementById('confirmMessage').textContent = message;
            document.getElementById('confirmBtn').onclick = () => {
                closeModal();
                onConfirm();
            };
            document.getElementById('confirmModal').classList.add('active');
        }
        
        function closeModal() {
            document.getElementById('confirmModal').classList.remove('active');
        }
        
        // 点击模态框外部关闭
        document.getElementById('confirmModal').addEventListener('click', (e) => {
            if (e.target.id === 'confirmModal') {
                closeModal();
            }
        });

        document.getElementById('settingsModal').addEventListener('click', (e) => {
            if (e.target.id === 'settingsModal') {
                closeSettingsModal();
            }
        });

        // ========== 启动 ==========
        initializeAdminTokenInput();
        connect();
        setInterval(updateRate, 100);
        setInterval(updateStats, 1000);
        window.addEventListener('resize', drawNetworkSpeedChart);
        drawNetworkSpeedChart();
        
        // 初始化排序指示器
        setTimeout(() => {
            const indicator = document.getElementById('sort-cpu_percent');
            if (indicator) {
                indicator.textContent = processSortAsc ? '▲' : '▼';
                indicator.classList.add('active');
            }
        }, 100);
