// Global state to hold fetched data and current filter settings
let rawThreatsData = [];
let activeAttackFilter = 'ALL';
let activeSeverityFilter = 'ALL';
let activeCountryFilter = 'ALL';

const API_BASE_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://localhost:5000'
    : 'https://cyber-threat-dashboad.onrender.com';

document.addEventListener('DOMContentLoaded', async () => {
    // 1. Initialize the 3D Globe
    if (typeof initAttackMap === 'function') {
        initAttackMap();
    }

    // 2. Start navbar live clock
    updateLiveTimestamp();
    setInterval(updateLiveTimestamp, 1000);

    // 3. Attach filter event listeners
    setupFilterListeners();

    // 4. Fetch initial dataset from Flask backend
    await refreshDashboard();
});

// Animation
function animateKpiCards() {
    const cards = document.querySelectorAll('.kpi-card');
    cards.forEach(card => {
        card.classList.remove('updated');
        // Force reflow to restart CSS animation
        void card.offsetWidth; 
        card.classList.add('updated');
    });
}

// Update Navbar UTC Clock
function updateLiveTimestamp() {
    const timeEl = document.getElementById('live-timestamp');
    if (timeEl) {
        const now = new Date();
        timeEl.textContent = now.toUTCString().replace('GMT', 'UTC');
    }
}

// Fetch Threat Data from API
async function refreshDashboard() {
    try {
        // FIXED: Replaced hardcoded 127.0.0.1 with dynamic API_BASE_URL
        const response = await fetch(`${API_BASE_URL}/api/threats`);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        
        rawThreatsData = await response.json();

        // Populate dynamic country dropdown based on available backend data
        populateCountryDropdown(rawThreatsData);

        // Render view with filtered data
        applyFiltersAndRender();

    } catch (err) {
        console.error('Failed to load dashboard threat data:', err);
    }
}

// Setup Event Listeners for Filter Controls
function setupFilterListeners() {
    // Attack Type Filter Buttons
    const filterButtons = document.querySelectorAll('.filter-group .filter-btn');
    filterButtons.forEach(btn => {
        btn.addEventListener('click', (e) => {
            filterButtons.forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            
            activeAttackFilter = e.target.textContent.trim().toUpperCase();
            applyFiltersAndRender();
        });
    });

    // Dropdown Selectors
    const dropdowns = document.querySelectorAll('.filter-dropdowns .dropdown');
    dropdowns.forEach(select => {
        select.addEventListener('change', (e) => {
            const val = e.target.value.toUpperCase();
            
            if (e.target.dataset.filter === 'country') {
                activeCountryFilter = val;
            } else if (e.target.dataset.filter === 'severity') {
                activeSeverityFilter = val;
            }
            applyFiltersAndRender();
        });
    });
}

// Populate Country Dropdown Dynamically
function populateCountryDropdown(threats) {
    const countrySelect = document.querySelector('.filter-dropdowns select[data-filter="country"]');
    if (!countrySelect) return;

    const countries = [...new Set(threats.map(t => t.country))].sort();
    countrySelect.innerHTML = '<option value="ALL">All Countries</option>';
    countries.forEach(c => {
        countrySelect.innerHTML += `<option value="${c}">${c}</option>`;
    });
}

// Filter Dataset & Re-render Visualizations
function applyFiltersAndRender() {
    let filtered = [...rawThreatsData];

    // Filter by Attack Type
    if (activeAttackFilter !== 'ALL' && activeAttackFilter !== 'ALL TYPES') {
        filtered = filtered.filter(t => t.attack_type.toUpperCase().includes(activeAttackFilter));
    }

    // Filter by Country
    if (activeCountryFilter !== 'ALL') {
        filtered = filtered.filter(t => t.country.toUpperCase() === activeCountryFilter);
    }

    // Filter by Severity (calculated based on IOC count thresholds)
    if (activeSeverityFilter !== 'ALL') {
        filtered = filtered.filter(t => {
            let sev = 'LOW';
            if (t.ioc_count > 50) sev = 'HIGH';
            else if (t.ioc_count > 15) sev = 'MEDIUM';
            
            return sev === activeSeverityFilter;
        });
    }
    
    // Update Visualizations with filtered dataset
    if (typeof renderMapMarkers === 'function') renderMapMarkers(filtered);
    updateKPICards(filtered);
    renderAttackDistributionChart(filtered);
    renderTopMalwareChart(filtered);
    renderTrendChart();
    populatePulseTable(filtered);
}

// Update Top KPI Cards
function updateKPICards(threats) {
    const threatsToday = document.getElementById('kpi-threats-today');
    const topAttack = document.getElementById('kpi-top-attack');
    const topOrigin = document.getElementById('kpi-top-origin');

    if (threatsToday) threatsToday.textContent = threats.length.toLocaleString();

    const attackCounts = {};
    const countryCounts = {};

    threats.forEach(t => {
        attackCounts[t.attack_type] = (attackCounts[t.attack_type] || 0) + 1;
        countryCounts[t.country] = (countryCounts[t.country] || 0) + 1;
    });

    const sortedAttacks = Object.keys(attackCounts).sort((a, b) => attackCounts[b] - attackCounts[a]);
    const sortedCountries = Object.keys(countryCounts).sort((a, b) => countryCounts[b] - countryCounts[a]);

    if (topAttack) topAttack.textContent = sortedAttacks.length ? sortedAttacks[0] : '--';
    if (topOrigin) topOrigin.textContent = sortedCountries.length ? sortedCountries[0] : '--';
}

// Render Donut Chart (Attack Types)
function renderAttackDistributionChart(threats) {
    const ctx = document.getElementById('attackDistributionChart')?.getContext('2d');
    if (!ctx) return;

    if (window.attackChartInstance) {
        window.attackChartInstance.destroy();
    }

    const counts = {};
    threats.forEach(t => counts[t.attack_type] = (counts[t.attack_type] || 0) + 1);

    window.attackChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(counts).length ? Object.keys(counts) : ['No Data'],
            datasets: [{
                data: Object.values(counts).length ? Object.values(counts) : [1],
                backgroundColor: ['#E63946', '#F4A261', '#9D4EDD', '#00B4D8', '#2A9D8F', '#E76F51'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { position: 'right', labels: { color: '#8F9BBA' } } }
        }
    });
}

// Render Horizontal Bar Chart (Top Malware)
function renderTopMalwareChart(threats) {
    const ctx = document.getElementById('topMalwareChart')?.getContext('2d');
    if (!ctx) return;

    if (window.malwareChartInstance) {
        window.malwareChartInstance.destroy();
    }

    window.malwareChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Emotet', 'LockBit 3.0', 'Qakbot', 'AgentTesla', 'Formbook'],
            datasets: [{
                label: 'Detections',
                data: [287, 194, 142, 98, 76],
                backgroundColor: '#9D4EDD',
                borderRadius: 4
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: '#8F9BBA' }, grid: { color: '#1B254B' } },
                y: { ticks: { color: '#8F9BBA' }, grid: { display: false } }
            }
        }
    });
}

// Render 30-Day Trend Line Chart
function renderTrendChart() {
    const ctx = document.getElementById('trendChart')?.getContext('2d');
    if (!ctx) return;

    if (window.trendChartInstance) {
        window.trendChartInstance.destroy();
    }

    window.trendChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: Array.from({length: 15}, (_, i) => `Day ${i + 1}`),
            datasets: [{
                label: 'Threat Volume',
                data: [650, 720, 800, 1200, 950, 1100, 847, 900, 1300, 1842, 1400, 1100, 950, 870, 920],
                borderColor: '#00B4D8',
                backgroundColor: 'rgba(0, 180, 216, 0.1)',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: '#8F9BBA' }, grid: { color: '#1B254B' } },
                y: { ticks: { color: '#8F9BBA' }, grid: { color: '#1B254B' } }
            }
        }
    });
}

// Populate Latest Threat Pulses Table
function populatePulseTable(threats) {
    const tbody = document.getElementById('pulse-table-body');
    if (!tbody) return;

    tbody.innerHTML = '';

    if (threats.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;">No matching threats found.</td></tr>';
        return;
    }

    threats.slice(0, 5).forEach(t => {
        let sevClass = 'low';
        let sevLabel = 'Low';

        if (t.ioc_count > 50) { sevClass = 'high'; sevLabel = 'High'; }
        else if (t.ioc_count > 15) { sevClass = 'med'; sevLabel = 'Med'; }

        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${t.title || 'Unknown Threat'}</td>
            <td>${t.attack_type || 'N/A'}</td>
            <td>${t.country || 'N/A'}</td>
            <td><span class="sev-badge ${sevClass}">${sevLabel}</span></td>
        `;
        tbody.appendChild(row);
    });
}

// --- 1. POLLING MECHANISM (Assigned: Samuel & Demaih) ---
function initRealTimePolling() {
    async function fetchLatestData() {
        try {
            const response = await fetch(`${API_BASE_URL}/api/threats`);
            if (!response.ok) throw new Error('API request failed');
            const result = await response.json();
            const threats = result.data || result;

            // Update Header Timestamp
            const now = new Date();
            const timeString = now.toTimeString().split(' ')[0]; // HH:MM:SS
            const dateString = now.toDateString().split(' ').slice(1, 3).join(' '); // Month Day
            
            const timestampElem = document.getElementById('live-timestamp');
            if (timestampElem) {
                timestampElem.textContent = `${dateString} ${now.getFullYear()} ${timeString}`;
            }

            // Silent UI refresh
            if (typeof loadMalwareChart === 'function') loadMalwareChart();
            console.log(`[${timeString}] 🔄 Live data polled successfully.`);
        } catch (err) {
            console.warn('⚠️ Polling error (backend offline):', err.message);
        }
    }
    // Run every 60 seconds
    setInterval(fetchLatestData, 60000);
}

// --- 2. DRILL-DOWN MODAL (Assigned: Demaih, Khen & Shambeline) ---
function attachChartDrillDown(chartInstance) {
    const canvas = chartInstance.canvas;
    
    canvas.addEventListener('click', (evt) => {
        const points = chartInstance.getElementsAtEventForMode(evt, 'nearest', { intersect: true }, true);
        if (!points.length) return;

        const index = points[0].index;
        const selectedType = chartInstance.data.labels[index];
        openDrillDownModal(selectedType);
    });
}

async function openDrillDownModal(attackType) {
    // Remove existing modal if open
    const existingModal = document.getElementById('drilldown-modal');
    if (existingModal) existingModal.remove();

    // Create Modal Elements
    const modal = document.createElement('div');
    modal.id = 'drilldown-modal';
    modal.style.cssText = `
        position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
        background: rgba(5, 10, 19, 0.85); backdrop-filter: blur(4px);
        display: flex; align-items: center; justify-content: center; z-index: 9999;
    `;

    // Fetch threats for this specific attack type
    let threatRows = '';
    try {
        const res = await fetch(`/api/threats?type=${encodeURIComponent(attackType)}`);
        const json = await res.json();
        const items = json.data || [];

        threatRows = items.map(item => `
            <tr style="border-bottom: 1px solid #1E293B;">
                <td style="padding: 10px; color: #F1F5F9;">${item.name || item.title || 'Unknown Threat'}</td>
                <td style="padding: 10px; color: #94A3B8;">${item.country || item.origin || 'Global'}</td>
                <td style="padding: 10px; color: #94A3B8;">${item.date || 'Today'}</td>
                <td style="padding: 10px;"><span class="sev-badge ${item.severity?.toLowerCase()}">${item.severity}</span></td>
                <td style="padding: 10px; font-family: monospace; color: #38BDF8;">${item.ioc || item.ip || '192.168.1.1'}</td>
            </tr>
        `).join('');
    } catch (err) {
        // Fallback sample row if API endpoint is static
        threatRows = `
            <tr style="border-bottom: 1px solid #1E293B;">
                <td style="padding: 10px; color: #F1F5F9;">${attackType} Campaign Alpha</td>
                <td style="padding: 10px; color: #94A3B8;">RU</td>
                <td style="padding: 10px; color: #94A3B8;">2026-08-27</td>
                <td style="padding: 10px;"><span class="sev-badge high">High</span></td>
                <td style="padding: 10px; font-family: monospace; color: #38BDF8;">185.220.101.5</td>
            </tr>
        `;
    }

    modal.innerHTML = `
        <div style="background: #0B132B; border: 1px solid #7C3AED; border-radius: 10px; width: 90%; max-width: 700px; padding: 20px; box-shadow: 0 10px 30px rgba(0,0,0,0.5);">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                <h3 style="color: #A78BFA; margin: 0;">🔍 Drill-Down: ${attackType}</h3>
                <button onclick="document.getElementById('drilldown-modal').remove()" style="background: none; border: none; color: #94A3B8; font-size: 20px; cursor: pointer;">✕</button>
            </div>
            <div style="max-height: 350px; overflow-y: auto;">
                <table style="width: 100%; text-align: left; border-collapse: collapse; font-size: 13px;">
                    <thead>
                        <tr style="color: #64748B; border-bottom: 1px solid #1E293B;">
                            <th style="padding: 8px;">NAME</th>
                            <th style="padding: 8px;">ORIGIN</th>
                            <th style="padding: 8px;">DATE</th>
                            <th style="padding: 8px;">SEVERITY</th>
                            <th style="padding: 8px;">IOC / IP</th>
                        </tr>
                    </thead>
                    <tbody>${threatRows}</tbody>
                </table>
            </div>
        </div>
    `;

    document.body.appendChild(modal);
}

// Start listeners on window load
window.addEventListener('load', () => {
    initRealTimePolling();
    
    // Attach drill-down modal click to donut chart if initialized
    if (typeof attackChart !== 'undefined') {
        attachChartDrillDown(attackChart);
    }
});

// --- UI POLISH: LOADING SPINNERS & API ERROR STATES ---

// Render Spinner
function showLoadingState(elementId) {
    const el = document.getElementById(elementId);
    if (el) {
        el.innerHTML = `
            <div class="loading-spinner-container" style="display:flex; justify-content:center; align-items:center; height:100%; min-height:120px;">
                <div class="spinner" style="border: 3px solid rgba(124,58,237,0.1); border-left-color: #7C3AED; border-radius: 50%; width: 24px; height: 24px; animation: spin 0.8s linear infinite;"></div>
            </div>
        `;
    }
}

// Render Error State
function showErrorState(elementId, errorMessage = 'Failed to load telemetry data') {
    const el = document.getElementById(elementId);
    if (el) {
        el.innerHTML = `
            <div class="error-banner" style="background: rgba(239,68,68,0.1); border: 0.5px solid #EF4444; color: #FCA5A5; border-radius: 6px; padding: 12px; font-size: 12px; text-align: center;">
                ⚠️ ${errorMessage}
            </div>
        `;
    }
}

// Add CSS keyframe for spinner
const style = document.createElement('style');
style.textContent = `
    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }
`;
document.head.appendChild(style);

 function startRealTimePolling() {
        // Poll every 60 sec
        setInterval(async () => {
            try {
                // 1. Fetch live telemetry from backend
                const response = await fetch(`${API_BASE_URL}/api/threats`);
                if (!response.ok) throw new Error('Network response failed');
                const data = await response.json();

                // 2. Update Header Timestamp
                const now = new Date();
                const timestampStr = now.toLocaleTimeString();
                const timestampElem = document.getElementById('live-timestamp');
                if (timestampElem) {
                    timestampElem.textContent = `Last Updated: ${timestampStr}`;
                }

                // 3. Silently update dynamic dashboard feeds
                if (typeof loadMalwareChart === 'function') loadMalwareChart();
                
                console.log(`[${timestampStr}] Dashboard silently refreshed.`);
            } catch (err) {
                console.warn('Polling attempt failed, retaining cached view:', err);
            }
        }, 60000);
    }

    // Start polling on page load
    window.addEventListener('load', startRealTimePolling);