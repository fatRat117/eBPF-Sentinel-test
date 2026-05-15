        // ========== 全局变量 ==========
        let ws = null;
        let allEvents = [];
        let execveEvents = [];
        let networkEvents = [];
        let currentTab = 'all';
        let startTime = Date.now();
        let eventCountLastSecond = 0;
        let lastRateUpdate = Date.now();
        
        // 策略状态（客户端缓存，避免突显已停用的事件）
        let policyState = {
            execveEnabled: true,
            networkEnabled: true
        };

        // 系统指标
        let systemStats = {
            cpuUsage: 0,
            netSpeedIn: 0,
            netSpeedOut: 0
        };

        const networkSpeedHistoryLimit = 60;
        let networkSpeedHistory = [];
        
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
            document.getElementById('policy-panel').classList.toggle('hidden', tab !== 'policy');

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
            const tabs = ['all', 'execve', 'network', 'policy'];
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
                renderNetworkEvent(event);
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
        
        function renderNetworkEvent(event) {
            const tbody = document.getElementById('networkBody');
            const emptyState = document.getElementById('networkEmptyState');
            
            emptyState.style.display = 'none';
            
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
            
            tbody.insertBefore(row, tbody.firstChild);
            while (tbody.children.length > 500) tbody.removeChild(tbody.lastChild);
        }
        
        // ========== 进程治理 ==========
        function killProcess(pid, comm) {
            if (!policyState.execveEnabled) {
                alert('进程管理已被策略禁用');
                return;
            }

            showConfirm(`确定要终止进程 "${comm}" (PID: ${pid}) 吗？`, () => {
                fetch(`/api/process/kill/${pid}`, { method: 'POST' })
                    .then(res => res.json())
                    .then(data => {
                        if (data.error) {
                            throw new Error(data.error);
                        }
                        alert(data.message || '操作成功');
                    })
                    .catch(err => {
                        alert('操作失败: ' + err.message);
                    });
            });
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
            
            document.getElementById('allEventsBody').innerHTML = '';
            document.getElementById('execveBody').innerHTML = '';
            document.getElementById('networkBody').innerHTML = '';
            
            document.getElementById('allEmptyState').style.display = 'block';
            document.getElementById('execveEmptyState').style.display = 'block';
            document.getElementById('networkEmptyState').style.display = 'block';
            
            updateStats();
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

        // ========== 启动 ==========
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
