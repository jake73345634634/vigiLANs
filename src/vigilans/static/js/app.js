(function () {
    'use strict';

    const TOOLS = [
        { slug: 'fortigate', name: 'FortiGate', icon: '\u{1F6E1}', accept: '.conf,.txt', hint: 'FortiGate rules (.conf, .txt)' },
    ];

    const $ = (sel, ctx) => (ctx || document).querySelector(sel);
    const $$ = (sel, ctx) => (ctx || document).querySelectorAll(sel);
    const toolSlug = name => name.toLowerCase().replace(/\s+/g, '');

    const statsBar = $('#statsBar');
    const filterTabs = $('#filterTabs');
    const results = $('#results');
    const importsList = $('#importsList');
    const uploadCards = $('#uploadCards');
    const btnClear = $('#btnClearDb');
    const deviceFilter = $('#deviceFilter');

    let currentFilter = 'all';
    let _allRulesData = null;
    let _allRulesDefaultCols = null;
    let currentDevice = 'all';

    // --- Init ---
    function init() {
        renderUploadCards();
        setupFilterTabs();
        btnClear.addEventListener('click', clearDatabase);
        deviceFilter.addEventListener('change', () => {
            currentDevice = deviceFilter.value;
            applyFilter(currentFilter);
        });
        refresh();
    }

    // --- Upload Cards ---
    function renderUploadCards() {
        uploadCards.innerHTML = TOOLS.map(tool => `
            <div class="sidebar-upload-card" data-slug="${tool.slug}">
                <div class="sidebar-upload-info">
                    <h4>${tool.name}</h4>
                    <p>${tool.hint}</p>
                </div>
                <input type="file" accept="${tool.accept}" style="display:none">
            </div>
        `).join('');

        $$('.sidebar-upload-card', uploadCards).forEach(card => {
            const input = $('input[type="file"]', card);
            const slug = card.dataset.slug;

            card.addEventListener('click', () => input.click());
            card.addEventListener('dragover', e => { e.preventDefault(); card.classList.add('dragover'); });
            card.addEventListener('dragleave', () => card.classList.remove('dragover'));
            card.addEventListener('drop', e => {
                e.preventDefault();
                card.classList.remove('dragover');
                if (e.dataTransfer.files[0]) uploadFile(slug, e.dataTransfer.files[0], card);
            });
            input.addEventListener('change', () => {
                if (input.files[0]) uploadFile(slug, input.files[0], card);
                input.value = '';
            });
        });
    }

    async function uploadFile(slug, file, card, replace) {
        card.classList.add('uploading');
        const form = new FormData();
        form.append('file', file);

        const url = replace ? `/api/import/${slug}?replace=true` : `/api/import/${slug}`;

        try {
            const res = await fetch(url, { method: 'POST', body: form });
            const data = await res.json();
            if (res.status === 409 && data.conflict) {
                card.classList.remove('uploading');
                if (confirm(`${data.tool_name} data for ${data.device_name} already exists, do you want to replace the existing data?`)) {
                    uploadFile(slug, file, card, true);
                }
                return;
            }
            if (!res.ok) {
                showError(data.error || 'Upload failed');
                return;
            }
            await refresh();
        } catch (e) {
            showError('Network error: ' + e.message);
        } finally {
            card.classList.remove('uploading');
        }
    }

    // --- Refresh ---
    async function refresh() {
        try {
            const [importsRes, findingsRes] = await Promise.all([
                fetch('/api/imports'),
                fetch('/api/findings'),
            ]);
            const imports = await importsRes.json();
            const findings = await findingsRes.json();

            renderImports(imports);
            renderFindings(findings);
        } catch (e) {
            showError('Failed to load data: ' + e.message);
        }
    }

    // --- Sidebar Imports ---
    function renderImports(imports) {
        if (imports.length === 0) {
            importsList.innerHTML = '<div class="sidebar-empty">No imports yet</div>';
            return;
        }

        // Group imports by device_name
        const grouped = {};
        imports.forEach(imp => {
            if (!grouped[imp.device_name]) grouped[imp.device_name] = [];
            grouped[imp.device_name].push(imp);
        });

        importsList.innerHTML = Object.entries(grouped).map(([deviceName, imps]) => {
            const toolLines = imps.map(imp => `
                <div class="sidebar-import-tool-line" data-import-id="${imp.id}">
                    <div class="sidebar-import-tags">
                        <span class="sidebar-import-tool" data-tool="${toolSlug(imp.tool_name)}">${esc(imp.tool_name)}</span>
                        ${imp.device_type ? `<span class="sidebar-import-tool device-type-tag">${esc(imp.device_type)}</span>` : ''}
                        <button class="sidebar-tool-delete" title="Delete import">&times;</button>
                    </div>
                    <div class="sidebar-import-date">${esc(imp.report_date)}</div>
                </div>
            `).join('');
            return `
                <div class="sidebar-domain-block" data-device="${esc(deviceName)}">
                    <div class="sidebar-domain-name">${esc(deviceName)}</div>
                    <div class="sidebar-domain-tools">${toolLines}</div>
                </div>
            `;
        }).join('');

        // Delete buttons
        $$('.sidebar-tool-delete', importsList).forEach(btn => {
            btn.addEventListener('click', async () => {
                const line = btn.closest('.sidebar-import-tool-line');
                const id = line.dataset.importId;
                const device = line.closest('.sidebar-domain-block').dataset.device;
                const tool = line.querySelector('.sidebar-import-tool').textContent;
                if (!confirm(`Delete ${tool} data for ${device}?`)) return;
                try {
                    await fetch(`/api/imports/${id}`, { method: 'DELETE' });
                    await refresh();
                } catch (e) {
                    showError('Failed to delete: ' + e.message);
                }
            });
        });
    }

    // --- Findings ---
    function renderFindings(data) {
        const { stats, parsed, unparsed, ignored, allRules, allRulesColumns } = data;

        if (stats.total === 0) {
            statsBar.classList.remove('show');
            filterTabs.classList.remove('show');
            results.innerHTML = '<div class="empty-state">Upload firewall rules to get started</div>';
            return;
        }

        // Stats
        $('#statTotal').textContent = stats.total;
        $('#statParsed').textContent = stats.parsed;
        $('#statUnparsed').textContent = stats.unparsed;
        $('#statIgnored').textContent = stats.ignored;
        statsBar.classList.add('show');
        filterTabs.classList.add('show');

        // Populate device dropdown
        const allDevices = new Set();
        [...parsed, ...unparsed, ...ignored].forEach(f => {
            (f.devices || []).forEach(d => allDevices.add(d));
        });
        deviceFilter.innerHTML = '<option value="all">All Devices</option>' +
            [...allDevices].sort().map(d => `<option value="${esc(d)}">${esc(d)}</option>`).join('');
        deviceFilter.value = currentDevice;

        let html = '';

        if (parsed.length > 0) {
            html += `<div class="findings-section" data-section="parsed">
                <div class="section-header">
                    <div class="section-indicator"></div>
                    <h2 class="section-title">Parsed Findings</h2>
                    <span class="section-count">${parsed.length}</span>
                </div>`;
            parsed.forEach((f, i) => { html += renderParsedCard(f, `parsed-${i}`); });
            html += '</div>';
        }

        _allRulesData = allRules || [];
        _allRulesDefaultCols = allRulesColumns;

        if (_allRulesData.length > 0 || unparsed.length > 0) {
            html += `<div class="findings-section" data-section="unparsed">
                <div class="section-header">
                    <div class="section-indicator"></div>
                    <h2 class="section-title">Unparsed Findings</h2>
                    <span class="section-count">${unparsed.length + (_allRulesData.length > 0 ? 1 : 0)}</span>
                </div>`;
            if (_allRulesData.length > 0) {
                html += renderAllRulesCard(_allRulesData, _allRulesDefaultCols);
            }
            unparsed.forEach((f, i) => { html += renderUnparsedCard(f, `unparsed-${i}`); });
            html += '</div>';
        }

        if (ignored.length > 0) {
            html += `<div class="findings-section" data-section="ignored">
                <div class="section-header">
                    <div class="section-indicator"></div>
                    <h2 class="section-title">Ignored Findings</h2>
                    <span class="section-count">${ignored.length}</span>
                </div>`;
            ignored.forEach((f, i) => { html += renderIgnoredCard(f, `ignored-${i}`); });
            html += '</div>';
        }

        results.innerHTML = html;
        applyFilter(currentFilter);
    }

    function renderDeviceTags(devices) {
        if (!devices || devices.length === 0) return '';
        return `<div class="finding-domains">${devices.map(d => `<span class="domain-tag">${esc(d)}</span>`).join('')}</div>`;
    }

    const COL_DEFS = {
        device:   { label: 'Device',   key: 'device' },
        id:       { label: '#',        key: 'ruleNum',  narrow: true },
        name:     { label: 'Name',     key: 'name' },
        context:  { label: 'Context',  key: 'context' },
        srcZone:  { label: 'Src Zone', key: 'srcZone' },
        dstZone:  { label: 'Dst Zone', key: 'dstZone' },
        srcAddr:  { label: 'Src Addr', key: 'srcAddr',  expandKey: 'srcAddrExp' },
        dstAddr:  { label: 'Dst Addr', key: 'dstAddr',  expandKey: 'dstAddrExp' },
        service:  { label: 'Service',  key: 'service',  expandKey: 'serviceExp' },
        action:   { label: 'Action',   key: 'action',   narrow: true },
        log:      { label: 'Log',      key: 'log',      narrow: true },
        status:   { label: 'Status',   key: 'status',   narrow: true },
        nat:      { label: 'NAT',      key: 'nat',      narrow: true },
        schedule: { label: 'Schedule', key: 'schedule', narrow: true },
        comment:  { label: 'Comment',  key: 'comment' },
    };
    const ALL_COLUMNS = Object.keys(COL_DEFS);

    // Map finding titles to the fields they highlight.
    // Functions return 'bad', 'warn', or falsy.
    const bad = () => 'bad';
    const warn = () => 'warn';
    const anySrc = r => (r.srcAddr.toLowerCase() === 'all' || r.srcAddr.toLowerCase() === 'any') && bad();
    const anyDst = r => (r.dstAddr.toLowerCase() === 'all' || r.dstAddr.toLowerCase() === 'any') && bad();
    const anySvc = r => (r.service.toUpperCase() === 'ALL' || r.service.toUpperCase() === 'ANY') && bad();
    const anySrcZone = r => (!r.srcZone || r.srcZone.toLowerCase() === 'any') && bad();
    const anyDstZone = r => (!r.dstZone || r.dstZone.toLowerCase() === 'any') && bad();
    const insecureSvcs = new Set(['TELNET','FTP','TFTP','HTTP','RSH','RLOGIN','FINGER','TALK','IRC']);
    const questionableSvcs = new Set(['SNMP','NFS','SMB','SAMBA','POP3','IMAP','SMTP']);
    function svcSeverity(name) {
        const u = name.trim().toUpperCase();
        if (insecureSvcs.has(u)) return 'bad';
        if (questionableSvcs.has(u)) return 'warn';
        return '';
    }
    const HIGHLIGHT_MAP = {
        'Overly Permissive Rule (Any Source, Any Destination, Any Service)': { srcAddr: anySrc, dstAddr: anyDst, service: anySvc },
        'Overly Permissive Rule (Any Source, Any Destination)':              { srcAddr: anySrc, dstAddr: anyDst },
        'Overly Permissive Rule (Any Source, Any Service)':                  { srcAddr: anySrc, service: anySvc },
        'Overly Permissive Rule (Any Destination, Any Service)':             { dstAddr: anyDst, service: anySvc },
        'Overly Permissive Rule (Any Source)':                               { srcAddr: anySrc },
        'Overly Permissive Rule (Any Destination)':                          { dstAddr: anyDst },
        'Overly Permissive Rule (Any Service)':                              { service: anySvc },
        'Overly Permissive Rule (Any Source Zone, Any Destination Zone)':    { srcZone: anySrcZone, dstZone: anyDstZone },
        'Overly Permissive Rule (Any Source Zone)':                          { srcZone: anySrcZone },
        'Overly Permissive Rule (Any Destination Zone)':                     { dstZone: anyDstZone },
        'Insecure Service Permitted':                                        { service: r => {
            const parts = r.service.split(',').map(s => s.trim().toUpperCase());
            if (parts.some(s => insecureSvcs.has(s))) return 'bad';
            if (parts.some(s => questionableSvcs.has(s))) return 'warn';
            return '';
        }},
        'Duplicate Rule':                                                    {},
        'Rule without Comment':    { comment: r => !r.comment && 'bad' },
        'Rule without Logging':    { log: r => (!r.log || r.log === 'disable') && 'bad' },
        'Disabled Rule':           { status: r => r.status === 'disable' && 'bad' },
        'Rule without Name':       { name: r => !r.name && 'bad' },
    };

    function renderRulesTable(rules, findingTitle, columns, extraActions) {
        if (!rules || rules.length === 0) return '';
        const cols = (columns || ALL_COLUMNS).filter(c => c in COL_DEFS);
        const hasExpansion = rules.some(r =>
            (r.srcAddrExp && r.srcAddrExp !== r.srcAddr) ||
            (r.dstAddrExp && r.dstAddrExp !== r.dstAddr) ||
            (r.serviceExp && r.serviceExp !== r.service));

        const colgroup = `<colgroup>${cols.map(c => COL_DEFS[c].narrow ? '<col class="col-narrow">' : '<col>').join('')}</colgroup>`;
        const header = `<tr>${cols.map(c => `<th>${COL_DEFS[c].label}</th>`).join('')}</tr>`;
        const highlights = HIGHLIGHT_MAP[findingTitle] || {};
        const highlightAll = findingTitle === '__ALL__';

        const rows = rules.map(r => {
            const cells = cols.map(c => {
                const def = COL_DEFS[c];
                const val = r[def.key];
                let severity = '';
                if (highlightAll) {
                    for (const h of Object.values(HIGHLIGHT_MAP)) {
                        const s = h[c] && h[c](r);
                        if (s === 'bad') { severity = 'bad'; break; }
                        if (s === 'warn') severity = 'warn';
                    }
                } else {
                    severity = (highlights[c] && highlights[c](r)) || '';
                }
                const expandAttr = def.expandKey
                    ? ` data-collapsed="${esc(val || '')}" data-expanded="${esc(r[def.expandKey] || val || '')}"`
                    : '';
                // Per-value coloring for service column
                if (c === 'service' && severity && val && val.includes(',')) {
                    const parts = val.split(',').map(s => {
                        const trimmed = s.trim();
                        const sv = svcSeverity(trimmed);
                        const spanCls = sv === 'bad' ? 'rule-val-bad' : sv === 'warn' ? 'rule-val-warn' : '';
                        return spanCls ? `<span class="${spanCls}">${esc(trimmed)}</span>` : esc(trimmed);
                    });
                    return `<td${expandAttr}>${parts.join(', ')}</td>`;
                }
                const cls = severity === 'bad' ? 'rule-val-bad' : severity === 'warn' ? 'rule-val-warn' : '';
                return `<td class="${cls}"${expandAttr}>${esc(val || '-')}</td>`;
            }).join('');
            const rawEncoded = r.raw ? btoa(unescape(encodeURIComponent(r.raw))) : '';
            return `<tr data-raw="${rawEncoded}" data-device="${esc(r.device || '')}">${cells}</tr>`;
        }).join('');

        return `<div class="data-section">
            <div class="data-label">
                <span>Affected Rules (${rules.length})</span>
                <div class="data-actions">
                    ${highlightAll ? '<button class="data-btn copy-row-btn" style="display:none">Copy Row</button>' : ''}
                    <button class="data-btn copy-config-btn" style="display:none">Copy Config</button>
                    ${extraActions || ''}
                    ${hasExpansion ? '<button class="data-btn expand-groups-btn">Expand Groups</button>' : ''}
                    <button class="data-btn copy-rules-btn">Copy Table</button>
                </div>
            </div>
            <div class="rules-table-wrap">
                <table class="rules-table">${colgroup}${header}${rows}</table>
            </div>
        </div>`;
    }

    function renderAllRulesCard(rules, columns) {
        const cols = (columns || ALL_COLUMNS).filter(c => c in COL_DEFS);
        const id = 'all-rules';
        const devices = [...new Set(rules.map(r => r.device))].sort();

        const tableHtml = renderRulesTable(rules, '__ALL__', cols, buildColFilterHtml(cols));

        return `<div class="finding-card unparsed" data-category="unparsed" data-devices="${esc(devices.join(','))}" id="${id}">
            <div class="finding-header" data-toggle="${id}">
                <div class="finding-status"></div>
                <div class="finding-info">
                    <div class="finding-title">All Rules</div>
                    ${renderDeviceTags(devices)}
                </div>
                <div class="finding-toggle">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 9l6 6 6-6"/></svg>
                </div>
            </div>
            <div class="finding-body">${tableHtml}</div>
        </div>`;
    }

    function renderParsedCard(f, id) {
        let body = '';

        // Affected rules table
        body += renderRulesTable(f.rules, f.findingName, f.columns);

        // Evidence commands
        if (f.evidence.length > 0) {
            const cmds = f.evidence.join('\n');
            body += `<div class="command-section">
                <div class="data-label">
                    <span>Evidence</span>
                    <div class="data-actions">
                        <button class="data-btn copy-btn" data-copy="${btoa(unescape(encodeURIComponent(cmds)))}">Copy</button>
                    </div>
                </div>
                <div class="command-block"><pre><code>${esc(cmds)}</code></pre></div>
            </div>`;
        }

        // Comments
        if (f.comments.length > 0) {
            body += `<div class="command-section">
                <div class="data-label"><span>Comments</span></div>
                <div class="comments-block"><ul>${f.comments.map(c => `<li>${esc(c)}</li>`).join('')}</ul></div>
            </div>`;
        }

        return `<div class="finding-card parsed" data-category="parsed" data-devices="${esc((f.devices || []).join(','))}" id="${id}">
            <div class="finding-header" data-toggle="${id}">
                <div class="finding-status"></div>
                <div class="finding-info">
                    <div class="finding-title">${esc(f.findingName)}</div>
                    ${renderDeviceTags(f.devices)}
                </div>
                <div class="finding-toggle">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 9l6 6 6-6"/></svg>
                </div>
            </div>
            <div class="finding-body">${body}</div>
        </div>`;
    }

    function renderUnparsedCard(f, id) {
        let body = `<div class="data-section">
            <div class="data-label"><span>Parsed</span></div>
            <div class="raw-titles">
                <div class="raw-title-item"><span class="raw-title-tool" data-tool="${toolSlug(f.toolName)}">${esc(f.toolName)}</span> ${esc(f.title)}</div>
            </div>
        </div>`;

        // Affected rules table
        body += renderRulesTable(f.rules, f.title);

        return `<div class="finding-card unparsed" data-category="unparsed" data-devices="${esc((f.devices || []).join(','))}" id="${id}">
            <div class="finding-header" data-toggle="${id}">
                <div class="finding-status"></div>
                <div class="finding-info">
                    <div class="finding-title">${esc(f.title)}</div>
                    ${renderDeviceTags(f.devices)}
                </div>
                <div class="finding-toggle">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 9l6 6 6-6"/></svg>
                </div>
            </div>
            <div class="finding-body">${body}</div>
        </div>`;
    }

    function renderIgnoredCard(f, id) {
        let body = `<div class="data-section">
            <div class="data-label"><span>Parsed</span></div>
            <div class="raw-titles">
                <div class="raw-title-item"><span class="raw-title-tool" data-tool="${toolSlug(f.toolName)}">${esc(f.toolName)}</span> ${esc(f.title)}</div>
            </div>
        </div>`;

        // Affected rules table
        body += renderRulesTable(f.rules, f.title);

        if (f.comments && f.comments.length > 0) {
            body += `<div class="command-section">
                <div class="data-label"><span>Comments</span></div>
                <div class="comments-block"><ul>${f.comments.map(c => `<li>${esc(c)}</li>`).join('')}</ul></div>
            </div>`;
        }

        return `<div class="finding-card ignored" data-category="ignored" data-devices="${esc((f.devices || []).join(','))}" id="${id}">
            <div class="finding-header" data-toggle="${id}">
                <div class="finding-status"></div>
                <div class="finding-info">
                    <div class="finding-title">${esc(f.title)}</div>
                    ${renderDeviceTags(f.devices)}
                </div>
                <div class="finding-toggle">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 9l6 6 6-6"/></svg>
                </div>
            </div>
            <div class="finding-body">${body}</div>
        </div>`;
    }

    // --- Toggle Cards + Copy ---
    document.addEventListener('click', e => {
        const header = e.target.closest('[data-toggle]');
        if (header) {
            const card = document.getElementById(header.dataset.toggle);
            if (card) card.classList.toggle('expanded');
            return;
        }

        if (e.target.classList.contains('copy-btn')) {
            copyText(e.target);
        }

        if (e.target.classList.contains('copy-rules-btn')) {
            copyRulesTable(e.target);
        }

        if (e.target.classList.contains('expand-groups-btn')) {
            toggleExpandGroups(e.target);
        }

        if (e.target.classList.contains('copy-config-btn')) {
            copySelectedConfig(e.target);
        }

        if (e.target.classList.contains('copy-row-btn')) {
            copySelectedRow(e.target);
        }

        // Column filter toggle
        if (e.target.classList.contains('col-filter-toggle')) {
            const dropdown = e.target.nextElementSibling;
            dropdown.style.display = dropdown.style.display === 'none' ? '' : 'none';
            e.stopPropagation();
            return;
        }

        // Close column filter when clicking outside
        if (!e.target.closest('.col-filter-wrap')) {
            document.querySelectorAll('.col-filter-dropdown').forEach(d => d.style.display = 'none');
        }

        // Row selection in rules tables
        const row = e.target.closest('.rules-table tbody tr, .rules-table tr:not(:first-child)');
        if (row && row.dataset.raw !== undefined) {
            const section = row.closest('.data-section');
            const prev = section.querySelector('tr.selected');
            if (prev && prev !== row) prev.classList.remove('selected');
            row.classList.toggle('selected');
            const isSelected = row.classList.contains('selected');
            const copyBtn = section.querySelector('.copy-config-btn');
            if (copyBtn) copyBtn.style.display = isSelected ? '' : 'none';
            const copyRowBtn = section.querySelector('.copy-row-btn');
            if (copyRowBtn) copyRowBtn.style.display = isSelected ? '' : 'none';
        }
    });

    function buildColFilterHtml(activeCols) {
        return `<div class="col-filter-wrap">
            <button class="data-btn col-filter-toggle">Filter Columns</button>
            <div class="col-filter-dropdown" style="display:none">
                ${ALL_COLUMNS.filter(c => c in COL_DEFS).map(c =>
                    `<label class="col-filter-item">
                        <input type="checkbox" value="${c}" ${activeCols.includes(c) ? 'checked' : ''}>
                        <span>${COL_DEFS[c].label}</span>
                    </label>`
                ).join('')}
            </div>
        </div>`;
    }

    // Column filter checkbox changes
    document.addEventListener('change', e => {
        if (!e.target.closest('.col-filter-dropdown')) return;
        const card = document.getElementById('all-rules');
        if (!card || !_allRulesData) return;
        const checked = [...card.querySelectorAll('.col-filter-item input:checked')].map(cb => cb.value);
        const section = card.querySelector('.data-section');
        if (section) {
            const newTable = renderRulesTable(_allRulesData, '__ALL__', checked, buildColFilterHtml(checked));
            section.outerHTML = newTable;
            // Re-open the dropdown after re-render
            const dd = card.querySelector('.col-filter-dropdown');
            if (dd) dd.style.display = '';
        }
    });

    function copySelectedRow(btn) {
        const section = btn.closest('.data-section');
        const row = section.querySelector('tr.selected');
        if (!row) return;
        const cells = row.querySelectorAll('td');
        const text = '| ' + [...cells].map(c => c.textContent.trim()).join(' | ') + ' |';

        function showCopied() {
            btn.classList.add('copied');
            const orig = btn.textContent;
            btn.textContent = 'Copied';
            setTimeout(() => { btn.classList.remove('copied'); btn.textContent = orig; }, 1500);
        }

        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(showCopied).catch(() => fallbackCopy(text, showCopied));
        } else {
            fallbackCopy(text, showCopied);
        }
    }

    function copySelectedConfig(btn) {
        const section = btn.closest('.data-section');
        const row = section.querySelector('tr.selected');
        if (!row || !row.dataset.raw) return;
        const text = decodeURIComponent(escape(atob(row.dataset.raw)));

        function showCopied() {
            btn.classList.add('copied');
            const orig = btn.textContent;
            btn.textContent = 'Copied';
            setTimeout(() => { btn.classList.remove('copied'); btn.textContent = orig; }, 1500);
        }

        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(showCopied).catch(() => fallbackCopy(text, showCopied));
        } else {
            fallbackCopy(text, showCopied);
        }
    }

    function toggleExpandGroups(btn) {
        const section = btn.closest('.data-section');
        const isExpanded = btn.classList.toggle('active');
        btn.textContent = isExpanded ? 'Collapse Groups' : 'Expand Groups';
        section.querySelectorAll('td[data-expanded]').forEach(td => {
            td.textContent = isExpanded ? td.dataset.expanded : td.dataset.collapsed;
        });
    }

    function copyRulesTable(btn) {
        const wrap = btn.closest('.data-section').querySelector('.rules-table');
        if (!wrap) return;
        const rows = wrap.querySelectorAll('tr');
        const lines = [];
        rows.forEach((row, i) => {
            const cells = row.querySelectorAll('th, td');
            const vals = [...cells].map(c => c.textContent.trim());
            const line = '| ' + (i === 0 ? vals.map(v => v.toUpperCase()) : vals).join(' | ') + ' |';
            lines.push(line);
            if (i === 0) {
                lines.push('| ' + [...cells].map(() => '-').join(' | ') + ' |');
            }
        });
        const text = lines.join('\n');

        function showCopied() {
            btn.classList.add('copied');
            const orig = btn.textContent;
            btn.textContent = 'Copied';
            setTimeout(() => { btn.classList.remove('copied'); btn.textContent = orig; }, 1500);
        }

        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(showCopied).catch(() => fallbackCopy(text, showCopied));
        } else {
            fallbackCopy(text, showCopied);
        }
    }

    // --- Filter Tabs ---
    function setupFilterTabs() {
        $$('.filter-tab', filterTabs).forEach(tab => {
            tab.addEventListener('click', () => {
                $$('.filter-tab', filterTabs).forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                currentFilter = tab.dataset.filter;
                applyFilter(currentFilter);
            });
        });
    }

    function applyFilter(filter) {
        let parsed = 0, unparsed = 0, ignored = 0;
        $$('.finding-card', results).forEach(card => {
            const categoryMatch = filter === 'all' || card.dataset.category === filter;
            const devices = card.dataset.devices ? card.dataset.devices.split(',') : [];
            const deviceMatch = currentDevice === 'all' || devices.includes(currentDevice);
            const visible = categoryMatch && deviceMatch;
            card.style.display = visible ? '' : 'none';
            if (deviceMatch) {
                if (card.dataset.category === 'parsed') parsed++;
                else if (card.dataset.category === 'unparsed') unparsed++;
                else if (card.dataset.category === 'ignored') ignored++;
            }
        });
        // Filter table rows by device
        $$('.rules-table tr[data-device]', results).forEach(row => {
            if (currentDevice === 'all') {
                row.style.display = '';
            } else {
                row.style.display = row.dataset.device === currentDevice ? '' : 'none';
            }
        });

        // Update rule counts
        $$('.data-section', results).forEach(section => {
            const total = section.querySelectorAll('.rules-table tr[data-device]').length;
            const visible = [...section.querySelectorAll('.rules-table tr[data-device]')].filter(r => r.style.display !== 'none').length;
            const label = section.querySelector('.data-label span');
            if (label && label.textContent.startsWith('Affected Rules')) {
                label.textContent = currentDevice === 'all'
                    ? `Affected Rules (${total})`
                    : `Affected Rules (${visible}/${total})`;
            }
        });

        $$('.findings-section', results).forEach(section => {
            const categoryMatch = filter === 'all' || section.dataset.section === filter;
            const hasVisible = categoryMatch && [...$$('.finding-card', section)].some(c => c.style.display !== 'none');
            section.classList.toggle('hidden', !hasVisible);
        });
        $('#statTotal').textContent = parsed + unparsed + ignored;
        $('#statParsed').textContent = parsed;
        $('#statUnparsed').textContent = unparsed;
        $('#statIgnored').textContent = ignored;

        $$('.domain-tag', results).forEach(tag => {
            tag.classList.toggle('dimmed', currentDevice !== 'all' && tag.textContent !== currentDevice);
        });
    }

    // --- Copy ---
    function copyText(btn) {
        const encoded = btn.getAttribute('data-copy');
        if (!encoded) return;
        const text = decodeURIComponent(escape(atob(encoded)));

        function showCopied() {
            btn.classList.add('copied');
            const orig = btn.textContent;
            btn.textContent = 'Copied';
            setTimeout(() => { btn.classList.remove('copied'); btn.textContent = orig; }, 1500);
        }

        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(showCopied).catch(() => fallbackCopy(text, showCopied));
        } else {
            fallbackCopy(text, showCopied);
        }
    }

    function fallbackCopy(text, onSuccess) {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); onSuccess(); } catch (_) {}
        document.body.removeChild(ta);
    }

    // --- Clear Database ---
    async function clearDatabase() {
        if (!confirm('Clear all imported data?')) return;
        try {
            await fetch('/api/database', { method: 'DELETE' });
            await refresh();
        } catch (e) {
            showError('Failed to clear: ' + e.message);
        }
    }

    // --- Helpers ---
    function showError(msg) {
        results.innerHTML = `<div class="error-msg">${esc(msg)} <a href="#" class="error-refresh">Refresh</a>.</div>`;
    }

    document.addEventListener('click', e => {
        if (e.target.classList.contains('error-refresh')) {
            e.preventDefault();
            refresh();
        }
    });

    function esc(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // --- Boot ---
    init();
})();
