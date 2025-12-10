import express from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';

const app = express();
const PORT = process.env.EXPLORER_PORT || 3000;
const NODE_API = process.env.NODE_API_URL || 'http://localhost:3001';
const BIND_ADDRESS = '127.0.0.1'; // Only bind to localhost

// Security: Helmet adds various HTTP headers for security
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://unpkg.com"],
            scriptSrcAttr: ["'unsafe-inline'"], // This allows onclick handlers
            imgSrc: ["'self'", "data:"],
        }
    }
}));

// Security: Rate limiting to prevent abuse
const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 60, // 60 requests per minute per IP
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

// Apply rate limiting to all API routes
app.use('/api/', apiLimiter);

// Security: Disable x-powered-by header
app.disable('x-powered-by');

// Serve static files (if needed)
app.use(express.static('public'));

// Input validation helper
function validateHeight(height) {
    const num = parseInt(height);
    if (isNaN(num) || num < 0 || num > Number.MAX_SAFE_INTEGER) {
        throw new Error('Invalid block height');
    }
    return num;
}

function validateHash(hash) {
    if (typeof hash !== 'string' || !/^[a-f0-9]+$/i.test(hash) || hash.length > 128) {
        throw new Error('Invalid hash format');
    }
    return hash;
}

function validateCount(count) {
    const num = parseInt(count);
    if (isNaN(num) || num < 1 || num > 100) {
        return 20; // Default
    }
    return num;
}

// API proxy endpoints with validation
app.get('/api/stats', async (req, res) => {
    try {
        const response = await fetch(`${NODE_API}/api/stats`);
        const data = await response.json();
        res.json(data);
    } catch (e) {
        res.status(500).json({ error: 'Failed to connect to node' });
    }
});

app.get('/api/mempool', async (req, res) => {
    try {
        const response = await fetch(`${NODE_API}/api/mempool`);
        const data = await response.json();
        res.json(data);
    } catch (e) {
        res.status(500).json({ error: 'Failed to load mempool' });
    }
});

app.get('/api/blocks/recent', async (req, res) => {
    try {
        const count = validateCount(req.query.count);
        const response = await fetch(`${NODE_API}/api/blocks/recent?count=${count}`);
        const data = await response.json();
        res.json(data);
    } catch (e) {
        res.status(500).json({ error: e.message || 'Failed to load blocks' });
    }
});

app.get('/api/block/:height', async (req, res) => {
    try {
        const height = validateHeight(req.params.height);
        const response = await fetch(`${NODE_API}/api/block/${height}`);
        const data = await response.json();
        res.json(data);
    } catch (e) {
        res.status(500).json({ error: e.message || 'Failed to load block' });
    }
});

app.get('/api/block/hash/:hash', async (req, res) => {
    try {
        const hash = validateHash(req.params.hash);
        const response = await fetch(`${NODE_API}/api/block/hash/${hash}`);
        const data = await response.json();
        res.json(data);
    } catch (e) {
        res.status(404).json({ error: e.message || 'Block not found' });
    }
});

app.get('/api/metrics/difficulty', async (req, res) => {
    try {
        const response = await fetch(`${NODE_API}/api/metrics/difficulty`);
        const data = await response.json();
        res.json(data);
    } catch (e) {
        res.status(500).json({ error: 'Failed to load difficulty metrics' });
    }
});

app.get('/api/metrics/rewards', async (req, res) => {
    try {
        const response = await fetch(`${NODE_API}/api/metrics/rewards`);
        const data = await response.json();
        res.json(data);
    } catch (e) {
        res.status(500).json({ error: 'Failed to load reward metrics' });
    }
});

app.get('/api/metrics/supply', async (req, res) => {
    try {
        const response = await fetch(`${NODE_API}/api/metrics/supply`);
        const data = await response.json();
        res.json(data);
    } catch (e) {
        res.status(500).json({ error: 'Failed to load supply metrics' });
    }
});

app.get('/', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>pluriƀit Explorer</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --bg: #0a0a0f;
            --surface: #15151f;
            --surface-hover: #1a1a28;
            --border: #252530;
            --text: #e8e8f0;
            --text-dim: #9090a8;
            --accent: #4ECDC4;
            --accent-hover: #3dbdb5;
            --accent-dim: #2a9d96;
            --accent-red: #FF6B6B;
            --accent-orange: #f59e0b;
            --success: #22c55e;
        }

        [data-theme="light"] {
            --bg: #F0F4F8;
            --surface: #FFFFFF;
            --surface-hover: #e8ecf0;
            --border: #D3D9E2;
            --text: #293241;
            --text-dim: #6c757d;
            --accent: #4ECDC4;
            --accent-hover: #3dbdb5;
            --accent-dim: #2a9d96;
            --accent-red: #FF6B6B;
            --accent-orange: #f59e0b;
            --success: #22c55e;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            transition: background 0.3s, color 0.3s;
        }

        .header {
            background: var(--surface);
            border-bottom: 1px solid var(--border);
            padding: 1rem 0;
            position: sticky;
            top: 0;
            z-index: 100;
            backdrop-filter: blur(10px);
        }

        .nav {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 1.5rem;
            display: flex;
            align-items: center;
            gap: 2rem;
        }

        .logo {
            font-size: 1.25rem;
            font-weight: 700;
            color: var(--accent);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .nav-tabs {
            display: flex;
            gap: 0.5rem;
        }

        .nav-tab {
            padding: 0.5rem 1rem;
            background: none;
            border: 1px solid transparent;
            border-radius: 6px;
            color: var(--text-dim);
            cursor: pointer;
            font-size: 0.875rem;
            font-weight: 600;
            transition: all 0.2s;
        }

        .nav-tab:hover {
            color: var(--text);
            border-color: var(--border);
        }

        .nav-tab.active {
            background: var(--accent);
            color: #fff;
            border-color: var(--accent);
        }

        .search-box {
            flex: 1;
            max-width: 500px;
            position: relative;
        }

        .search-input {
            width: 100%;
            padding: 0.625rem 2.5rem 0.625rem 1rem;
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text);
            font-size: 0.875rem;
            font-family: 'Inter', sans-serif;
            transition: all 0.2s;
        }

        .search-input:focus {
            outline: none;
            border-color: var(--accent);
        }

        .search-input::placeholder {
            color: var(--text-dim);
        }

        .search-btn {
            position: absolute;
            right: 0.5rem;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            color: var(--text-dim);
            cursor: pointer;
            padding: 0.25rem 0.5rem;
        }

        .nav-actions {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .theme-toggle {
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 0.5rem 0.75rem;
            cursor: pointer;
            color: var(--text);
            font-size: 1.125rem;
            transition: all 0.2s;
        }

        .theme-toggle:hover {
            border-color: var(--accent);
        }

        .status-badge {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 0.875rem;
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            font-size: 0.875rem;
            font-weight: 600;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--success);
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem 1.5rem;
        }

        .view {
            display: none;
        }

        .view.active {
            display: block;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.25rem;
            transition: border-color 0.2s;
        }

        .stat-card:hover {
            border-color: var(--accent-dim);
        }

        .stat-label {
            color: var(--text-dim);
            font-size: 0.8125rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .stat-value {
            font-size: 1.75rem;
            font-weight: 700;
            color: var(--accent);
            font-variant-numeric: tabular-nums;
        }

        .mempool-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }

        .mempool-title {
            font-size: 1.125rem;
            font-weight: 700;
        }

        .mempool-stats {
            display: flex;
            gap: 1.5rem;
            font-size: 0.875rem;
            color: var(--text-dim);
        }

        .mempool-stat {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .mempool-stat-value {
            color: var(--accent);
            font-weight: 600;
        }

        .tx-list {
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }

        .tx-item {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem;
            cursor: pointer;
            transition: all 0.2s;
        }

        .tx-item:hover {
            border-color: var(--accent);
            transform: translateX(2px);
        }

        .tx-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.75rem;
        }

        .tx-hash {
            font-family: 'Courier New', monospace;
            font-size: 0.875rem;
            color: var(--accent);
            font-weight: 600;
        }

        .tx-fee {
            font-size: 0.875rem;
            color: var(--accent-orange);
            font-weight: 600;
        }

        .tx-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 1rem;
        }

        .tx-detail-item {
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }

        .tx-detail-label {
            color: var(--text-dim);
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .tx-detail-value {
            font-family: 'Courier New', monospace;
            font-size: 0.8125rem;
            color: var(--text);
        }

        .block-train-section {
            margin-bottom: 2rem;
            overflow: hidden;
            position: relative;
        }

        .block-train-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }

        .train-title {
            font-size: 1rem;
            font-weight: 700;
            color: var(--text);
        }

        .block-train-container {
            position: relative;
            height: 120px;
            overflow: hidden;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem;
        }

        .block-train {
            display: flex;
            gap: 1rem;
            position: absolute;
            left: 0;
            transition: transform 0.5s ease-out;
        }

        .train-block {
            flex-shrink: 0;
            width: 200px;
            background: var(--bg);
            border: 2px solid var(--accent);
            border-radius: 6px;
            padding: 0.75rem;
            cursor: pointer;
            transition: all 0.3s;
            animation: slideIn 0.5s ease-out;
        }

        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateX(-50px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }

        .train-block:hover {
            border-color: var(--accent-hover);
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(78, 205, 196, 0.3);
        }

        .train-block.new {
            animation: newBlock 0.6s ease-out;
            border-color: var(--success);
        }

        @keyframes newBlock {
            0% {
                transform: scale(1.1);
                border-color: var(--success);
            }
            100% {
                transform: scale(1);
                border-color: var(--accent);
            }
        }

        .train-block-height {
            font-size: 1.125rem;
            font-weight: 700;
            color: var(--accent);
            margin-bottom: 0.25rem;
        }

        .train-block-time {
            font-size: 0.75rem;
            color: var(--text-dim);
            margin-bottom: 0.5rem;
        }

        .train-block-txs {
            font-size: 0.75rem;
            color: var(--text-dim);
            display: flex;
            align-items: center;
            gap: 0.25rem;
        }

        .chart-container {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }

        .chart-header {
            margin-bottom: 1.5rem;
        }

        .chart-title {
            font-size: 1rem;
            font-weight: 700;
            color: var(--text);
        }



        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }

        .section-title {
            font-size: 1.125rem;
            font-weight: 700;
        }

        .blocks-container {
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }

        .block-row {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem;
            cursor: pointer;
            transition: all 0.2s;
        }

        .block-row:hover {
            border-color: var(--accent);
            transform: translateX(2px);
        }

        .block-main {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.75rem;
        }

        .block-height {
            font-size: 1.125rem;
            font-weight: 700;
            color: var(--accent);
        }

        .block-time {
            color: var(--text-dim);
            font-size: 0.8125rem;
        }

        .block-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
        }

        .info-item {
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }

        .info-label {
            color: var(--text-dim);
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .info-value {
            font-family: 'Courier New', monospace;
            font-size: 0.8125rem;
            color: var(--text);
            word-break: break-all;
        }

        .tx-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.375rem;
            padding: 0.25rem 0.625rem;
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            color: var(--text-dim);
        }

        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            backdrop-filter: blur(4px);
            z-index: 1000;
            padding: 2rem;
            overflow-y: auto;
        }

        .modal.active {
            display: flex;
            align-items: start;
            justify-content: center;
            padding-top: 4rem;
        }

        .modal-content {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            max-width: 900px;
            width: 100%;
            max-height: calc(100vh - 8rem);
            overflow-y: auto;
        }

        .modal-header {
            padding: 1.5rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            background: var(--surface);
            z-index: 1;
        }

        .modal-title {
            font-size: 1.25rem;
            font-weight: 700;
        }

        .close-btn {
            background: none;
            border: none;
            color: var(--text-dim);
            font-size: 1.5rem;
            cursor: pointer;
            padding: 0;
            width: 32px;
            height: 32px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 4px;
            transition: all 0.2s;
        }

        .close-btn:hover {
            background: var(--bg);
            color: var(--accent-red);
        }

        .modal-body {
            padding: 1.5rem;
        }

        .detail-section {
            margin-bottom: 1.5rem;
        }

        .detail-section:last-child {
            margin-bottom: 0;
        }

        .detail-section-title {
            font-weight: 700;
            margin-bottom: 0.75rem;
            color: var(--accent);
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .detail-grid {
            display: grid;
            gap: 0.75rem;
        }

        .detail-row {
            display: grid;
            grid-template-columns: 160px 1fr;
            gap: 1rem;
        }

        .detail-key {
            color: var(--text-dim);
            font-size: 0.8125rem;
            font-weight: 600;
        }

        .detail-val {
            font-family: 'Courier New', monospace;
            font-size: 0.8125rem;
            word-break: break-all;
        }

        .tx-section {
            margin-top: 1rem;
            padding: 1rem;
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 6px;
        }

        .tx-section-header {
            font-weight: 600;
            margin-bottom: 0.75rem;
            color: var(--accent);
            font-size: 0.875rem;
        }

        .io-grid {
            display: grid;
            gap: 0.5rem;
        }

        .io-item {
            padding: 0.5rem;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.75rem;
        }

        .code-block {
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 1rem;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.75rem;
            line-height: 1.5;
            color: var(--text-dim);
            max-height: 400px;
        }

        .loading {
            text-align: center;
            padding: 3rem;
            color: var(--text-dim);
        }

        .spinner {
            width: 40px;
            height: 40px;
            border: 3px solid var(--border);
            border-top-color: var(--accent);
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin: 0 auto 1rem;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .empty-state {
            text-align: center;
            padding: 3rem;
            color: var(--text-dim);
        }

        .empty-state-icon {
            font-size: 3rem;
            margin-bottom: 1rem;
            opacity: 0.5;
        }

        @media (max-width: 768px) {
            .nav {
                flex-wrap: wrap;
                gap: 1rem;
            }

            .search-box {
                order: 3;
                max-width: 100%;
                flex-basis: 100%;
            }

            .stats-grid {
                grid-template-columns: 1fr;
            }

            .detail-row {
                grid-template-columns: 1fr;
                gap: 0.25rem;
            }

            .train-block {
                width: 160px;
            }
        }
    </style>
</head>
<body>
    <header class="header">
        <nav class="nav">
            <div class="logo">
                pluriƀit Explorer
            </div>
            <div class="nav-tabs">
                <button class="nav-tab active" onclick="switchView('blockchain')">Blockchain</button>
                <button class="nav-tab" onclick="switchView('mempool')">Mempool</button>
            </div>
            <div class="search-box">
                <input 
                    type="text" 
                    class="search-input" 
                    id="searchInput"
                    placeholder="Search by block height or hash..."
                />
                <button class="search-btn" onclick="performSearch()">🔍</button>
            </div>
            <div class="nav-actions">
                <button class="theme-toggle" onclick="toggleTheme()" id="themeToggle">
                    🌙
                </button>
                <div class="status-badge">
                    <div class="status-dot"></div>
                    <span>Live</span>
                </div>
            </div>
        </nav>
    </header>

    <main class="container">
        <div id="blockchainView" class="view active">
            <section class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">Height</div>
                    <div class="stat-value" id="height">-</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Total Work</div>
                    <div class="stat-value" id="work">-</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">UTXO Set</div>
                    <div class="stat-value" id="utxo">-</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Block Time</div>
                    <div class="stat-value" id="blockTime">-</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Last Reward</div>
                    <div class="stat-value" id="lastReward">-</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Total Supply</div>
                    <div class="stat-value" id="totalSupply">-</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Stock-to-Flow</div>
                    <div class="stat-value" id="stockToFlow">-</div>
                </div>
            </section>

            <section class="block-train-section">
                <div class="block-train-header">
                    <h2 class="train-title">Latest Blocks</h2>
                </div>
                <div class="block-train-container">
                    <div class="block-train" id="blockTrain"></div>
                </div>
            </section>

            <section class="chart-container">
                <div class="chart-header">
                    <h2 class="chart-title">Mining Difficulty (VRF Threshold & VDF Iterations)</h2>
                </div>
                <canvas id="difficultyChart" height="80"></canvas>
            </section>

            <section>
                <div class="section-header">
                    <h2 class="section-title">Recent Blocks</h2>
                </div>
                <div class="blocks-container" id="blocksContainer">
                    <div class="loading">
                        <div class="spinner"></div>
                        <p>Loading blocks...</p>
                    </div>
                </div>
            </section>
        </div>

        <div id="mempoolView" class="view">
            <section class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">Pending Transactions</div>
                    <div class="stat-value" id="mempoolCount">-</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Total Fees</div>
                    <div class="stat-value" id="mempoolFees">-</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Avg Fee</div>
                    <div class="stat-value" id="mempoolAvgFee">-</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Memory Usage</div>
                    <div class="stat-value" id="mempoolSize">-</div>
                </div>
            </section>

            <section>
                <div class="mempool-header">
                    <h2 class="mempool-title">Pending Transactions</h2>
                    <div class="mempool-stats">
                        <div class="mempool-stat">
                            <span>Auto-refresh:</span>
                            <span class="mempool-stat-value">5s</span>
                        </div>
                    </div>
                </div>
                <div class="tx-list" id="txList">
                    <div class="loading">
                        <div class="spinner"></div>
                        <p>Loading mempool...</p>
                    </div>
                </div>
            </section>
        </div>
    </main>

    <div class="modal" id="blockModal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 class="modal-title" id="modalTitle">Block Details</h2>
                <button class="close-btn" onclick="closeModal()">×</button>
            </div>
            <div class="modal-body" id="modalBody"></div>
        </div>
    </div>

    <script>
        let state = {
            blocks: [],
            mempool: { pending: [], fee_total: 0, pending_count: 0 },
            stats: {},
            charts: {},
            lastBlockHeight: 0,
            currentView: 'blockchain'
        };
        
        function customReviver(key, value) {
            if (value && typeof value === 'object' && value.__type) {
                // Handle BigInt
                if (value.__type === 'BigInt') {
                    return BigInt(value.value);
                }
                // Handle Uint8Array (from Base64)
                if (value.__type === 'Uint8Array') {
                    try {
                        // This is the logic your bridge expects
                        return Uint8Array.from(atob(value.value), c => c.charCodeAt(0));
                    } catch (e) {
                        console.error('Failed to parse Uint8Array from base64', e);
                        return null;
                    }
                }
            }
            return value;
        }
        
function parseUint8Array(data) {
    if (!data) return new Uint8Array(0);
    if (data instanceof Uint8Array) return data;
    
    // ADDED: Handle plain hex strings (as in JSON data)
    if (typeof data === 'string' && /^[a-f0-9]+$/i.test(data) && data.length % 2 === 0) {
        const bytes = new Uint8Array(data.length / 2);
        for (let i = 0; i < data.length; i += 2) {
            bytes[i / 2] = parseInt(data.substring(i, i + 2), 16);
        }
        return bytes;
    }
    
    if (data.type === 'Buffer' && typeof data.data === 'string') {
        const hex = data.data;
        if (hex.length === 0) return new Uint8Array(0);
       
        // Ensure it's valid hex
        if (!/^[a-f0-9]+$/i.test(hex) || hex.length % 2 !== 0) {
            console.error('Invalid hex string in Buffer data:', hex);
            return new Uint8Array(0);
        }
       
        // Convert hex string to a byte array
        try {
            const bytes = new Uint8Array(hex.length / 2);
            for (let i = 0; i < hex.length; i += 2) {
                bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
            }
            return bytes;
        } catch (e) {
            console.error('Failed to parse hex string:', e);
            return new Uint8Array(0);
        }
    }
    // Fallback for object-like arrays {"0": 1, "1": 2, ...}
    if (typeof data === 'object' && data !== null && !Array.isArray(data) && data['0'] !== undefined) {
        try {
            const arr = Object.keys(data)
                .filter(k => /^\d+$/.test(k)) // Only take numeric keys
                .sort((a, b) => parseInt(a, 10) - parseInt(b, 10)) // Sort them
                .map(key => data[key]); // Get the values
            return new Uint8Array(arr);
        } catch (e) {
            console.error('Failed to parse object-like Uint8Array:', e);
            return new Uint8Array(0);
        }
    }
   
    // Fallback for simple arrays
    if (Array.isArray(data)) return new Uint8Array(data);
    console.warn('Unrecognized Uint8Array format:', data);
    return new Uint8Array(0);
}
        
        function switchView(view) {
            state.currentView = view;
            document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
            document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
            
            if (view === 'blockchain') {
                document.getElementById('blockchainView').classList.add('active');
                document.querySelector('.nav-tab:first-child').classList.add('active');
            } else if (view === 'mempool') {
                document.getElementById('mempoolView').classList.add('active');
                document.querySelector('.nav-tab:nth-child(2)').classList.add('active');
                loadMempool();
            }
        }
        
        function toggleTheme() {
            const html = document.documentElement;
            const currentTheme = html.getAttribute('data-theme') || 'dark';
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            html.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            document.getElementById('themeToggle').textContent = newTheme === 'dark' ? '🌙' : '☀️';
            
            if (state.charts.difficulty) updateDifficultyChartTheme(newTheme);
        }

        function initTheme() {
            const savedTheme = localStorage.getItem('theme') || 'dark';
            document.documentElement.setAttribute('data-theme', savedTheme);
            document.getElementById('themeToggle').textContent = savedTheme === 'dark' ? '🌙' : '☀️';
        }

        function getChartColors(theme) {
            return {
                gridColor: theme === 'dark' ? '#252530' : '#D3D9E2',
                textColor: theme === 'dark' ? '#9090a8' : '#6c757d',
                accentColor: '#4ECDC4'
            };
        }

        function updateDifficultyChartTheme(theme) {
            const colors = getChartColors(theme);
            
            state.charts.difficulty.options.scales.y.ticks.color = colors.textColor;
            state.charts.difficulty.options.scales.y.grid.color = colors.gridColor;
            state.charts.difficulty.options.scales.y1.ticks.color = colors.textColor;
            state.charts.difficulty.options.scales.y1.grid.color = colors.gridColor;
            state.charts.difficulty.options.scales.x.ticks.color = colors.textColor;
            state.charts.difficulty.options.scales.x.grid.color = colors.gridColor;
            state.charts.difficulty.options.plugins.legend.labels.color = colors.textColor;
            state.charts.difficulty.update('none');
        }

        async function init() {
            initTheme();
            await loadStats();
            await loadBlocks();
            await loadDifficultyMetrics();
            loadSupply();
            startAutoRefresh();
        }
        function JSONStringifyWithBigInt(obj) {
            return JSON.stringify(obj, (key, value) =>
                typeof value === 'bigint'
                    ? value.toString() // Convert BigInt to string for serialization
                    : value // return everything else unchanged
            , 2); // The '2' adds pretty-printing (indentation)
        }

        async function loadStats() {
            try {
                const res = await fetch('/api/stats');
                const stats = await res.json(); // <-- FIX: Use .json(), remove customReviver
                
                // FIX: Explicitly convert strings to BigInt for math and display
                const height = BigInt(stats.height);
                const totalWork = BigInt(stats.totalWork);

                document.getElementById('height').textContent = height.toLocaleString();
                document.getElementById('work').textContent = formatNumber(totalWork);
                document.getElementById('utxo').textContent = stats.utxoCount.toLocaleString();
                
                // Replicate worker's reward logic
                const INITIAL_BASE_REWARD = 409600n; //50kb
                const HALVING_INTERVAL = 525600n;
                const REWARD_RESET_INTERVAL = 5256000n;
                
                const h = height; // <-- FIX: Use the BigInt version
                let reward = 0n;
                
                if (h > 0n) {
                    const height_in_era = h % REWARD_RESET_INTERVAL;
                    const num_halvings = height_in_era / HALVING_INTERVAL;
                    reward = num_halvings >= 64n ? 0n : INITIAL_BASE_REWARD >> num_halvings;
                }
                
                document.getElementById('lastReward').textContent = formatBits(reward);
                
                state.stats = stats;
            } catch (e) {
                console.error('Failed to load stats:', e);
            }
        }

        async function loadMempool() {
            try {
                const res = await fetch('/api/mempool');
                const data = await res.json();
                
                state.mempool = data;
                
                document.getElementById('mempoolCount').textContent = data.pending_count.toLocaleString();
                document.getElementById('mempoolFees').textContent = formatBits(data.fee_total);
                
                const avgFee = data.pending_count > 0 ? data.fee_total / data.pending_count : 0;
                document.getElementById('mempoolAvgFee').textContent = formatBits(avgFee);
                
                // Rough memory estimate
                const memSize = data.pending_count * 2048; // ~2KB per tx
                document.getElementById('mempoolSize').textContent = formatBytes(memSize);
                
                renderMempool(data.transactions || []);
            } catch (e) {
                console.error('Failed to load mempool:', e);
                document.getElementById('txList').innerHTML = 
                    '<div class="loading"><p style="color: var(--text-dim);">Failed to load mempool</p></div>';
            }
        }

        function renderMempool(transactions) {
            const container = document.getElementById('txList');
            
            if (!transactions || transactions.length === 0) {
                container.innerHTML = '<div class="empty-state">' +
                    '<div class="empty-state-icon">📭</div>' +
                    '<p>No pending transactions</p>' +
                    '</div>';
                return;
            }
            
            // Sort by fee (highest first)
            const sorted = [...transactions].sort(function(a, b) {
                const feeA = a.kernels ? a.kernels.reduce(function(sum, k) { 
                    return sum + (Number(k.fee) || 0); 
                }, 0) : 0;
                const feeB = b.kernels ? b.kernels.reduce(function(sum, k) { 
                    return sum + (Number(k.fee) || 0); 
                }, 0) : 0;
                return feeB - feeA;
            });
            
            const items = [];
            for (let i = 0; i < sorted.length; i++) {
                const tx = sorted[i];
                const fee = tx.kernels ? tx.kernels.reduce(function(sum, k) { 
                    return sum + (Number(k.fee) || 0); 
                }, 0) : 0;
                const inputs = tx.inputs ? tx.inputs.length : 0;
                const outputs = tx.outputs ? tx.outputs.length : 0;
                const kernels = tx.kernels ? tx.kernels.length : 0;
                
                let hash = 'unknown';
                if (tx.kernels && tx.kernels[0] && tx.kernels[0].excess) {
                    try {
                        const excessData = parseUint8Array(tx.kernels[0].excess);
                        const excessBytes = Array.from(excessData).slice(0, 8);
                        hash = excessBytes.map(function(b) {
                            return b.toString(16).padStart(2, '0'); 
                        }).join('') + '...';
                    } catch (e) {
                        console.error('Error processing hash:', e);
                    }
                }
                
                // Store transaction in a global variable for onclick
                const txIndex = window.mempoolTransactions ? window.mempoolTransactions.length : 0;
                if (!window.mempoolTransactions) window.mempoolTransactions = [];
                window.mempoolTransactions[txIndex] = tx;
                
                items.push(
                    '<div class="tx-item" onclick="viewTransaction(window.mempoolTransactions[' + txIndex + '])">' +
                        '<div class="tx-header">' +
                            '<div class="tx-hash">' + hash + '</div>' +
                            '<div class="tx-fee">' + formatBits(fee) + ' fee</div>' +
                        '</div>' +
                        '<div class="tx-details">' +
                            '<div class="tx-detail-item">' +
                                '<div class="tx-detail-label">Inputs</div>' +
                                '<div class="tx-detail-value">' + inputs + '</div>' +
                            '</div>' +
                            '<div class="tx-detail-item">' +
                                '<div class="tx-detail-label">Outputs</div>' +
                                '<div class="tx-detail-value">' + outputs + '</div>' +
                            '</div>' +
                            '<div class="tx-detail-item">' +
                                '<div class="tx-detail-label">Kernels</div>' +
                                '<div class="tx-detail-value">' + kernels + '</div>' +
                            '</div>' +
                        '</div>' +
                    '</div>'
                );
            }
            
            container.innerHTML = items.join('');
        }

        function viewTransaction(tx) {
            const modal = document.getElementById('blockModal');
            const modalTitle = document.getElementById('modalTitle');
            const modalBody = document.getElementById('modalBody');
            
            let hash = 'unknown';
            if (tx.kernels && tx.kernels[0] && tx.kernels[0].excess) {
                try {
                    const excessData = parseUint8Array(tx.kernels[0].excess);
                    const excessBytes = Array.from(excessData);
                    hash = excessBytes.map(function(b) { 
                        return b.toString(16).padStart(2, '0'); 
                    }).join('');
                } catch (e) {
                    console.error('Error processing transaction hash:', e);
                }
            }
            
            modalTitle.textContent = 'Transaction Details';
            
            const fee = tx.kernels ? tx.kernels.reduce(function(sum, k) { 
                return sum + (Number(k.fee) || 0); 
            }, 0) : 0;
            
            let inputsHtml = '<div class="io-grid">';
            if (tx.inputs && tx.inputs.length > 0) {
                for (let i = 0; i < tx.inputs.length; i++) {
                    const input = tx.inputs[i];
                    try {
                        const commitmentData = parseUint8Array(input.commitment);
                        const commitmentHex = Array.from(commitmentData).map(b => b.toString(16).padStart(2, '0')).join('');
                        inputsHtml += '<div class="io-item">' +
                            '<strong>Input ' + (i + 1) + ':</strong> ' + truncateHash(commitmentHex) +
                            '</div>';
                    } catch (e) {
                        inputsHtml += '<div class="io-item">Input ' + (i + 1) + ': [error parsing]</div>';
                    }
                }
            } else {
                inputsHtml += '<div class="io-item">Coinbase (no inputs)</div>';
            }
            inputsHtml += '</div>';
            
            let outputsHtml = '<div class="io-grid">';
            if (tx.outputs && tx.outputs.length > 0) {
                for (let i = 0; i < tx.outputs.length; i++) {
                    const output = tx.outputs[i];
                    try {                       
                        const commitmentData = parseUint8Array(output.commitment);
                        const commitmentHex = Array.from(commitmentData).map(b => b.toString(16).padStart(2, '0')).join('');
                        outputsHtml += '<div class="io-item">' +
                            '<strong>Output ' + (i + 1) + ':</strong> ' + truncateHash(commitmentHex) +
                            '</div>';
                    } catch (e) {
                        outputsHtml += '<div class="io-item">Output ' + (i + 1) + ': [error parsing]</div>';
                    }
                }
            }
            outputsHtml += '</div>';
            
            let kernelsHtml = '<div class="io-grid">';
            if (tx.kernels && tx.kernels.length > 0) {
                for (let i = 0; i < tx.kernels.length; i++) {
                    const kernel = tx.kernels[i];
                    try {
                        const excessData = parseUint8Array(kernel.excess);
                        const excessHex = Array.from(excessData).map(b => b.toString(16).padStart(2, '0')).join('');
                        kernelsHtml += '<div class="io-item">' +
                            '<strong>Kernel ' + (i + 1) + ':</strong><br>' +
                            'Excess: ' + truncateHash(excessHex) + '<br>' +
                            'Fee: ' + formatBits(Number(kernel.fee) || 0) +
                            '</div>';
                    } catch (e) {
                        kernelsHtml += '<div class="io-item">Kernel ' + (i + 1) + ': [error parsing]</div>';
                    }
                }
            }
            kernelsHtml += '</div>';
            
            modalBody.innerHTML = '<div class="detail-section">' +
                '<div class="detail-section-title">Transaction Information</div>' +
                '<div class="detail-grid">' +
                    '<div class="detail-row">' +
                        '<div class="detail-key">Hash</div>' +
                        '<div class="detail-val">' + hash + '</div>' +
                    '</div>' +
                    '<div class="detail-row">' +
                        '<div class="detail-key">Total Fee</div>' +
                        '<div class="detail-val">' + formatBits(fee) + '</div>' +
                    '</div>' +
                    '<div class="detail-row">' +
                        '<div class="detail-key">Inputs</div>' +
                        '<div class="detail-val">' + (tx.inputs ? tx.inputs.length : 0) + '</div>' +
                    '</div>' +
                    '<div class="detail-row">' +
                        '<div class="detail-key">Outputs</div>' +
                        '<div class="detail-val">' + (tx.outputs ? tx.outputs.length : 0) + '</div>' +
                    '</div>' +
                    '<div class="detail-row">' +
                        '<div class="detail-key">Kernels</div>' +
                        '<div class="detail-val">' + (tx.kernels ? tx.kernels.length : 0) + '</div>' +
                    '</div>' +
                '</div>' +
                '</div>' +
                '<div class="detail-section">' +
                    '<div class="detail-section-title">Inputs</div>' +
                    inputsHtml +
                '</div>' +
                '<div class="detail-section">' +
                    '<div class="detail-section-title">Outputs</div>' +
                    outputsHtml +
                '</div>' +
                '<div class="detail-section">' +
                    '<div class="detail-section-title">Kernels</div>' +
                    kernelsHtml +
                '</div>' +
                '<div class="detail-section">' +
                    '<div class="detail-section-title">Raw Data</div>' +
                    '<div class="code-block">' + JSON.stringify(tx, null, 2) + '</div>' +
                '</div>';
            
            modal.classList.add('active');
        }

        async function loadBlocks() {
            try {
                const res = await fetch('/api/blocks/recent?count=20');
                const blocks = await res.json(); // <-- FIX: Use .json(), remove customReviver

                const train = document.getElementById('blockTrain'); // Get train element

                if (blocks.length > 0 && Number(blocks[0].height) > state.lastBlockHeight) {
                    state.lastBlockHeight = Number(blocks[0].height);
                    if (state.blocks.length > 0) {
                        updateBlockTrain(blocks[0], true); // Add new block
                    }
                }

                state.blocks = blocks;
                renderBlocks(blocks);
                // updateChart(); // This was removed
                updateBlockTime(blocks);

                // Only do a full render if the train is empty (initial load)
                if (train.children.length === 0) {
                    updateBlockTrain(null, false);
                }
            } catch (e) {
                console.error('Failed to load blocks:', e);
                document.getElementById('blocksContainer').innerHTML = 
                    '<div class="loading"><p style="color: var(--text-dim);">Failed to load blocks</p></div>';
            }
        }

        function updateBlockTime(blocks) {
            if (blocks.length < 2) {
                document.getElementById('blockTime').textContent = '~30s'; // Use target block time
                return;
            }

            const recentBlocks = blocks.slice(0, Math.min(10, blocks.length));
            // Initialize as BigInt
            let totalTimeDiff = 0n; 
            let count = 0;

            for (let i = 0; i < recentBlocks.length - 1; i++) {
                // Ensure both timestamps are BigInts before subtracting
                const ts1 = BigInt(recentBlocks[i].timestamp);
                const ts2 = BigInt(recentBlocks[i + 1].timestamp);
                const timeDiff = ts1 - ts2; // BigInt - BigInt = BigInt
                totalTimeDiff += timeDiff; // BigInt + BigInt = BigInt
                count++;
            }

            if (count > 0) {
                // Convert totalTimeDiff to Number *before* dividing by count (a Number)
                const avgTimeMs = Number(totalTimeDiff) / count; 
                const avgTimeSec = Math.round(avgTimeMs / 1000);

                if (avgTimeSec < 60) {
                    document.getElementById('blockTime').textContent = Math.max(0, avgTimeSec) + 's'; // Ensure non-negative
                } else {
                    const minutes = Math.floor(avgTimeSec / 60);
                    const seconds = avgTimeSec % 60;
                    document.getElementById('blockTime').textContent =
                        seconds > 0 ? (minutes + 'm ' + seconds + 's') : (minutes + 'm');
                }
            } else {
                 document.getElementById('blockTime').textContent = '~30s'; // Fallback if calculation fails
            }
        }

        function updateBlockTrain(newBlock, isNew) {
            const train = document.getElementById('blockTrain');
            
            if (isNew && newBlock) {
                const blockEl = createTrainBlock(newBlock, true);
                train.insertBefore(blockEl, train.firstChild);
                
                while (train.children.length > 10) {
                    train.removeChild(train.lastChild);
                }
                
                setTimeout(() => {
                    blockEl.classList.remove('new');
                }, 600);
            } else {
                train.innerHTML = '';
                const blocksToShow = state.blocks.slice(0, 10);
                blocksToShow.forEach(block => {
                    train.appendChild(createTrainBlock(block, false));
                });
            }
        }

        function createTrainBlock(block, isNew) {
            const div = document.createElement('div');
            div.className = 'train-block' + (isNew ? ' new' : '');
            div.onclick = () => viewBlock(block.height);
            div.innerHTML =
                '<div class="train-block-height">#' + Number(block.height).toLocaleString() + '</div>' +
                '<div class="train-block-time">' + formatTime(block.timestamp) + '</div>' +
                '<div class="train-block-txs">' + block.txCount + ' tx</div>';
            return div;
        }

        async function loadDifficultyMetrics() {
            try {
                const res = await fetch('/api/metrics/difficulty');
                const metrics = await res.json();
                
                const ctx = document.getElementById('difficultyChart');
                const theme = document.documentElement.getAttribute('data-theme') || 'dark';
                const colors = getChartColors(theme);
                
                const vrfData = metrics.map(m => {
                    const bytes = parseUint8Array(m.vrfThreshold);
                    return parseInt(Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 8), 16);
                });
                
                // Convert BigInt VDF iterations to Numbers
                const vdfIterationsData = metrics.map(m => Number(m.vdfIterations)); 
                
                state.charts.difficulty = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: metrics.map(m => '#' + m.height),
                        datasets: [
                            {
                                label: 'VRF Threshold (Lower = Harder)',
                                data: vrfData,
                                borderColor: '#22c55e',
                                backgroundColor: 'rgba(34, 197, 94, 0.1)',
                                yAxisID: 'y',
                                tension: 0.3,
                                fill: true,
                                pointRadius: 0,
                                borderWidth: 2
                            },
                            {
                                label: 'VDF Iterations',
                                data: vdfIterationsData,
                                borderColor: '#f59e0b',
                                backgroundColor: 'rgba(245, 158, 11, 0.1)',
                                yAxisID: 'y1',
                                tension: 0.3,
                                fill: true,
                                pointRadius: 0,
                                borderWidth: 2
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: true,
                        interaction: {
                            mode: 'index',
                            intersect: false,
                        },
                        plugins: {
                            legend: { 
                                display: true,
                                labels: {
                                    color: colors.textColor,
                                    font: {
                                        family: 'Inter',
                                        weight: 600
                                    }
                                }
                            }
                        },
                        scales: {
                            y: {
                                type: 'linear',
                                display: true,
                                position: 'left',
                                ticks: { color: colors.textColor },
                                grid: { color: colors.gridColor },
                                title: {
                                    display: true,
                                    text: 'VRF Threshold',
                                    color: colors.textColor,
                                    font: {
                                        family: 'Inter',
                                        weight: 600
                                    }
                                }
                            },
                            y1: {
                                type: 'linear',
                                display: true,
                                position: 'right',
                                ticks: { color: colors.textColor },
                                grid: { drawOnChartArea: false },
                                title: {
                                    display: true,
                                    text: 'VDF Iterations',
                                    color: colors.textColor,
                                    font: {
                                        family: 'Inter',
                                        weight: 600
                                    }
                                }
                            },
                            x: {
                                ticks: { 
                                    color: colors.textColor,
                                    maxRotation: 45,
                                    minRotation: 45
                                },
                                grid: { color: colors.gridColor }
                            }
                        }
                    }
                });
            } catch (e) {
                console.error('Failed to load difficulty metrics:', e);
            }
        }

        async function loadSupply() {
            try {
                const res = await fetch('/api/metrics/supply');
                const supply = await res.json();
        
                document.getElementById('totalSupply').textContent = formatBits(supply.totalSupply);
                document.getElementById('stockToFlow').textContent = Number(supply.stockToFlow).toFixed(2);
            } catch (e) {
                console.error('Failed to load supply:', e);
                document.getElementById('totalSupply').textContent = 'Error';
                document.getElementById('stockToFlow').textContent = 'Error';
            }
        }

        function renderBlocks(blocks) {
            const container = document.getElementById('blocksContainer');
            
            if (blocks.length === 0) {
                container.innerHTML = '<div class="loading"><p>No blocks found</p></div>';
                return;
            }
            
            container.innerHTML = blocks.map(function(block) {
                // Parse miner display
                let minerDisplay = 'N/A';
                if (block.miner) {
                    minerDisplay = block.miner;
                } else if (block.minerPubkey) {
                    try {
                        const minerData = parseUint8Array(block.minerPubkey);
                        if (minerData.length > 0) {
                            const minerBytes = Array.from(minerData);
                            minerDisplay = minerBytes.map(function(b) { 
                                return b.toString(16).padStart(2, '0'); 
                            }).join('').slice(0, 16) + '...';
                        }
                    } catch (e) {
                        minerDisplay = 'N/A';
                    }
                }
                
                return '<div class="block-row" onclick="viewBlock(' + block.height + ')">' +
                    '<div class="block-main">' +
                        '<div>' +
                            '<div class="block-height">#' + Number(block.height).toLocaleString() + '</div>' +
                            '<div class="block-time">' + formatTime(block.timestamp) + '</div>' +
                        '</div>' +
                        '<div class="tx-badge">' +
                            block.txCount + ' tx' +
                        '</div>' +
                    '</div>' +
                    '<div class="block-info">' +
                        '<div class="info-item">' +
                            '<div class="info-label">Hash</div>' +
                            '<div class="info-value">' + truncateHash(block.hash) + '</div>' +
                        '</div>' +
                        '<div class="info-item">' +
                            '<div class="info-label">Miner</div>' +
                            '<div class="info-value">' + minerDisplay + '</div>' +
                        '</div>' +
                    '</div>' +
                '</div>';
            }).join('');
        }
        // Helper to prevent potential XSS if error messages contain HTML
        function escapeHtml(unsafe) {
            if (!unsafe) return '';
            return unsafe
                 .replace(/&/g, "&amp;")
                 .replace(/</g, "&lt;")
                 .replace(/>/g, "&gt;")
                 .replace(/"/g, "&quot;")
                 .replace(/'/g, "&#039;");
        }
        async function viewBlock(height) {
            const modal = document.getElementById('blockModal');
            const modalTitle = document.getElementById('modalTitle');
            const modalBody = document.getElementById('modalBody');
            
            modalTitle.textContent = 'Block #' + height;
            modalBody.innerHTML = '<div class="loading"><div class="spinner"></div><p>Loading...</p></div>';
            modal.classList.add('active');
            
            try {
                const res = await fetch('/api/block/' + height);
                if (!res.ok) throw new Error('Block not found');
                const block = await res.json();
                
                let txListHtml = '';
                if (block.transactions && block.transactions.length > 0) {
                    const txSections = [];
                    for (let i = 0; i < block.transactions.length; i++) {
                        const tx = block.transactions[i];
                        const isCoinbase = !tx.inputs || tx.inputs.length === 0;
                        const fee = tx.kernels ? tx.kernels.reduce(function(sum, k) { 
                            return sum + (Number(k.fee) || 0); 
                        }, 0) : 0;
                        
                        let section = '<div class="tx-section">' +
                            '<div class="tx-section-header">' +
                                'Transaction ' + (i + 1) + (isCoinbase ? ' (Coinbase)' : '') +
                            '</div>' +
                            '<div class="detail-grid">' +
                                '<div class="detail-row">' +
                                    '<div class="detail-key">Inputs</div>' +
                                    '<div class="detail-val">' + (tx.inputs ? tx.inputs.length : 0) + '</div>' +
                                '</div>' +
                                '<div class="detail-row">' +
                                    '<div class="detail-key">Outputs</div>' +
                                    '<div class="detail-val">' + (tx.outputs ? tx.outputs.length : 0) + '</div>' +
                                '</div>' +
                                '<div class="detail-row">' +
                                    '<div class="detail-key">Kernels</div>' +
                                    '<div class="detail-val">' + (tx.kernels ? tx.kernels.length : 0) + '</div>' +
                                '</div>' +
                                '<div class="detail-row">' +
                                    '<div class="detail-key">Fee</div>' +
                                    '<div class="detail-val">' + formatBits(fee) + '</div>' +
                                '</div>' +
                            '</div>';
                        
                        if (tx.inputs && tx.inputs.length > 0) {
                            section += '<div style="margin-top: 0.75rem;">' +
                                '<div class="tx-section-header">Inputs</div>' +
                                '<div class="io-grid">';
                            for (let idx = 0; idx < tx.inputs.length; idx++) {
                                const inp = tx.inputs[idx];
                                try {
                                    const commitmentData = parseUint8Array(inp.commitment);
                                    const commitmentBytes = Array.from(commitmentData);
                                    const commitmentHex = commitmentBytes.map(function(b) { 
                                        return b.toString(16).padStart(2, '0'); 
                                    }).join('');
                                    section += '<div class="io-item">' +
                                        'Input ' + (idx + 1) + ': ' + truncateHash(commitmentHex) +
                                        '<br><small>Source Height: ' + (inp.sourceHeight || 'N/A') + '</small>' +
                                        '</div>';
                                } catch (e) {
                                    section += '<div class="io-item">Input ' + (idx + 1) + ': [error parsing]</div>';
                                }
                            }
                            section += '</div></div>';
                        }
                        
                        if (tx.outputs && tx.outputs.length > 0) {
                            section += '<div style="margin-top: 0.75rem;">' +
                                '<div class="tx-section-header">Outputs</div>' +
                                '<div class="io-grid">';
                            for (let idx = 0; idx < tx.outputs.length; idx++) {
                                const out = tx.outputs[idx];
                                try {
                                    const commitmentData = parseUint8Array(out.commitment);
                                    const commitmentBytes = Array.from(commitmentData);
                                    const commitmentHex = commitmentBytes.map(function(b) { 
                                        return b.toString(16).padStart(2, '0'); 
                                    }).join('');
                                    
                                const hasEphemeralKey = parseUint8Array(out.ephemeralKey).length > 0;
                                const hasStealthPayload = parseUint8Array(out.stealthPayload).length > 0;
                                    
                                    section += '<div class="io-item">' +
                                        'Output ' + (idx + 1) + ': ' + truncateHash(commitmentHex) +
                                        '<br><small>Stealth: ' + (hasEphemeralKey && hasStealthPayload ? 'Yes' : 'No') + '</small>' +
                                        '</div>';
                                } catch (e) {
                                    section += '<div class="io-item">Output ' + (idx + 1) + ': [error parsing]</div>';
                                }
                            }
                            section += '</div></div>';
                        }
                        
                        if (tx.kernels && tx.kernels.length > 0) {
                            section += '<div style="margin-top: 0.75rem;">' +
                                '<div class="tx-section-header">Kernels</div>' +
                                '<div class="io-grid">';
                            for (let idx = 0; idx < tx.kernels.length; idx++) {
                                const kernel = tx.kernels[idx];
                                try {
                                    const excessData = parseUint8Array(kernel.excess);
                                    const excessBytes = Array.from(excessData);
                                    const excessHex = excessBytes.map(function(b) { 
                                        return b.toString(16).padStart(2, '0'); 
                                    }).join('');
                                    section += '<div class="io-item">' +
                                        '<strong>Kernel ' + (idx + 1) + '</strong><br>' +
                                        'Excess: ' + truncateHash(excessHex) + '<br>' +
                                        'Fee: ' + formatBits(Number(kernel.fee) || 0) + '<br>' +
                                        '<small>Min Height: ' + (kernel.minHeight || 0) + '</small>' +
                                        '</div>';
                                } catch (e) {
                                    section += '<div class="io-item">Kernel ' + (idx + 1) + ': [error parsing]</div>';
                                }
                            }
                            section += '</div></div>';
                        }
                        
                        section += '</div>';
                        txSections.push(section);
                    }
                    txListHtml = txSections.join('');
                }
                
                // Parse miner pubkey
                let minerDisplay = 'N/A';
                try {
                    const minerData = parseUint8Array(block.minerPubkey);
                    if (minerData.length > 0) {
                        // Check if it's all zeros (likely genesis)
                        if (minerData.every(b => b === 0)) {
                            minerDisplay = 'Genesis Miner';
                        } else {
                            const minerHex = Array.from(minerData).map(function(b) { 
                                return b.toString(16).padStart(2, '0'); 
                            }).join('');
                            minerDisplay = truncateHash(minerHex); // Use existing helper
                        }
                    }
                } catch (e) {
                    console.error('Error parsing miner pubkey:', e);
                }
                
                // Parse VRF threshold
                let vrfDisplay = 'N/A';
                try {
                    const vrfData = parseUint8Array(block.vrfThreshold);
                    if (vrfData.length > 0) {
                        const vrfBytes = Array.from(vrfData).slice(0, 8);
                        vrfDisplay = vrfBytes.map(function(b) { 
                            return b.toString(16).padStart(2, '0'); 
                        }).join('') + '...';
                    }
                } catch (e) {
                    console.error('Error parsing VRF threshold:', e);
                }
                
                modalBody.innerHTML = '<div class="detail-section">' +
                    '<div class="detail-section-title">Block Information</div>' +
                    '<div class="detail-grid">' +
                        '<div class="detail-row">' +
                            '<div class="detail-key">Height</div>' +
                            '<div class="detail-val">' + (typeof block.height === 'bigint' ? block.height.toString() : block.height) + '</div>' +
                        '</div>' +
                        '<div class="detail-row">' +
                            '<div class="detail-key">Hash</div>' +
                            '<div class="detail-val">' + (block.hash || 'N/A') + '</div>' +
                        '</div>' +
                        '<div class="detail-row">' +
                            '<div class="detail-key">Previous Hash</div>' +
                            '<div class="detail-val">' + (block.prevHash || 'N/A') + '</div>' +
                        '</div>' +
                        '<div class="detail-row">' +
                            '<div class="detail-key">Timestamp</div>' +
                            '<div class="detail-val">' + new Date(Number(block.timestamp)).toLocaleString() + '</div>' +
                        '</div>' +
                        '<div class="detail-row">' +
                            '<div class="detail-key">Transactions</div>' +
                            '<div class="detail-val">' + (block.transactions ? block.transactions.length : 0) + '</div>' +
                        '</div>' +
                        '<div class="detail-row">' +
                            '<div class="detail-key">Miner</div>' +
                            '<div class="detail-val">' + minerDisplay + '</div>' +
                        '</div>' +
                    '</div>' +
                    '</div>' +
                    '<div class="detail-section">' +
                        '<div class="detail-section-title">Consensus Data</div>' +
                        '<div class="detail-grid">' +
                            '<div class="detail-row">' +
                                '<div class="detail-key">VDF Iterations</div>' +
                                '<div class="detail-val">' + (block.vdfIterations ? Number(block.vdfIterations).toLocaleString() : 'N/A') + '</div>' +
                            '</div>' +
                            '<div class="detail-row">' +
                                '<div class="detail-key">VRF Threshold</div>' +
                                '<div class="detail-val">' + vrfDisplay + '</div>' +
                            '</div>' +
                            '<div class="detail-row">' +
                                '<div class="detail-key">Lottery Nonce</div>' +
                                '<div class="detail-val">' + (block.lotteryNonce ? Number(block.lotteryNonce) : 'N/A') + '</div>' +
                            '</div>' +
                            '<div class="detail-row">' +
                                '<div class="detail-key">Total Work</div>' +
                                '<div class="detail-val">' + (block.totalWork ? formatNumber(block.totalWork) : 'N/A') + '</div>' +
                            '</div>' +
                        '</div>' +
                    '</div>' +
                    (txListHtml ? '<div class="detail-section"><div class="detail-section-title">Transactions</div>' + txListHtml + '</div>' : '') +
                    '<div class="detail-section">' +
                        '<div class="detail-section-title">Transaction Graph</div>' +
                        '<div id="txGraph" style="height: 400px; border: 1px solid var(--border); border-radius: 6px; background: var(--bg);"></div>' +
                    '</div>' +                    
                    '<div class="detail-section">' +
                        '<div class="detail-section-title">Raw Data</div>' +
                        // Use the new stringifier here
                        '<div class="code-block">' + JSONStringifyWithBigInt(block) + '</div>' + // <-- FIX HERE
                    '</div>';
                    drawTxGraph(block.transactions);
            } catch (e) {
                // Ensure error message is displayed safely
                const errorMessage = e instanceof Error ? e.message : String(e);
                modalBody.innerHTML = '<div class="loading"><p style="color: var(--text-dim);">Failed to load block: ' + escapeHtml(errorMessage) + '</p></div>';
            }
        }

        // Function to render transaction graph using vis.js
function drawTxGraph(transactions) {
    if (!transactions || transactions.length === 0) {
        document.getElementById('txGraph').innerHTML = '<div class="empty-state"><p>No transactions to display.</p></div>';
        return;
    }

    // Detect theme and set hex colors (vis.js doesn't handle CSS vars well)
    const theme = document.documentElement.getAttribute('data-theme') || 'dark';
    const isDark = theme === 'dark';
    const colors = {
        txBg: isDark ? '#f59e0b' : '#f59e0b', // Orange for tx box
        inputBg: isDark ? '#4ECDC4' : '#4ECDC4', // Teal/accent for inputs
        outputBg: isDark ? '#22c55e' : '#22c55e', // Green/success for outputs
        prevOutputBg: isDark ? '#9090a8' : '#6c757d', // Dim for previous outputs
        border: isDark ? '#252530' : '#D3D9E2',
        font: isDark ? '#e8e8f0' : '#293241', // Text color
        arrow: isDark ? '#9090a8' : '#6c757d' // Dim text for arrows
    };

    const nodes = new vis.DataSet();
    const edges = new vis.DataSet();

    transactions.forEach((tx, txIndex) => {
        const txNodeId = 'tx' + txIndex;
        nodes.add({
            id: txNodeId,
            label: 'Tx ' + (txIndex + 1) + (tx.kernels && tx.kernels.length > 0 && tx.inputs.length === 0 ? ' (Coinbase)' : ''),
            shape: 'box',
            color: { background: colors.txBg, border: colors.border },
            font: { color: colors.font },
            type: 'tx' // ADDED: Node type for identification
        });

        (tx.inputs || []).forEach((inp, inpIndex) => {
            let commHex = 'Invalid';
            let fullCommHex = ''; // ADDED: Store full hex for matching
            try {
                const commData = parseUint8Array(inp.commitment);
                fullCommHex = Array.from(commData).map(b => b.toString(16).padStart(2, '0')).join('');
                commHex = fullCommHex.slice(0, 12) + '...' + fullCommHex.slice(-8);
            } catch {}
            const inpId = 'in' + txIndex + '-' + inpIndex;
            nodes.add({
                id: inpId,
                label: 'Input: ' + commHex,
                shape: 'ellipse',
                color: { background: colors.inputBg, border: colors.border },
                font: { color: colors.font },
                type: 'input', // ADDED: Node type
                commitment: fullCommHex, // ADDED: Full commitment for lookup
                sourceHeight: inp.sourceHeight // ADDED: For fetching source block
            });
            edges.add({
                from: inpId,
                to: txNodeId,
                arrows: 'to',
                color: { color: colors.arrow }
            });
        });

        (tx.outputs || []).forEach((out, outIndex) => {
            let commHex = 'Invalid';
            try {
                const commData = parseUint8Array(out.commitment);
                commHex = Array.from(commData).map(b => b.toString(16).padStart(2, '0')).join('');
                commHex = commHex.slice(0, 12) + '...' + commHex.slice(-8);
            } catch {}
            const outId = 'out' + txIndex + '-' + outIndex;
            nodes.add({
                id: outId,
                label: 'Output: ' + commHex,
                shape: 'ellipse',
                color: { background: colors.outputBg, border: colors.border },
                font: { color: colors.font },
                type: 'output' // ADDED: Node type
            });
            edges.add({
                from: txNodeId,
                to: outId,
                arrows: 'to',
                color: { color: colors.arrow }
            });
        });
    });

    const container = document.getElementById('txGraph');
    const data = { nodes: nodes, edges: edges };
    const options = {
        layout: {
            hierarchical: {
                direction: 'LR',
                sortMethod: 'directed',
                nodeSpacing: 200,
                levelSeparation: 200
            }
        },
        edges: {
            smooth: { type: 'continuous' },
            arrows: { to: { scaleFactor: 0.5 } }
        },
        physics: false,
        interaction: { zoomView: true, dragView: true },
        // ADDED: Manipulation to allow redrawing
        manipulation: { enabled: false }
    };

    const network = new vis.Network(container, data, options);

    // ADDED: Click handler to expand inputs backward
    network.on('click', async function(params) {
        if (params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            const node = nodes.get(nodeId);
            if (node.type === 'input' && node.sourceHeight && node.commitment) {
                try {
                    // Fetch source block
                    const res = await fetch('/api/block/' + node.sourceHeight);
                    if (!res.ok) throw new Error('Source block not found');
                    const sourceBlock = await res.json();

                    // Find matching output in source block's transactions
                    let foundOutput = null;
                    for (const tx of sourceBlock.transactions || []) {
                        for (const out of tx.outputs || []) {
                            const outCommData = parseUint8Array(out.commitment);
                            const outCommHex = Array.from(outCommData).map(b => b.toString(16).padStart(2, '0')).join('');
                            if (outCommHex === node.commitment) {
                                foundOutput = out;
                                break;
                            }
                        }
                        if (foundOutput) break;
                    }

                    if (foundOutput) {
                        // Add previous output node
                        const prevOutId = 'prevOut-' + nodeId; // Unique ID
                        let prevCommHex = node.commitment.slice(0, 12) + '...' + node.commitment.slice(-8);
                        nodes.add({
                            id: prevOutId,
                            label: 'Prev Output: ' + prevCommHex,
                            shape: 'ellipse',
                            color: { background: colors.prevOutputBg, border: colors.border },
                            font: { color: colors.font },
                            type: 'prevOutput'
                        });
                        edges.add({
                            from: prevOutId,
                            to: nodeId,
                            arrows: 'to',
                            color: { color: colors.arrow }
                        });

                        // Redraw the network
                        network.setData({ nodes: nodes, edges: edges });
                    } else {
                        console.warn('No matching output found in source block ' + node.sourceHeight);
                    }
                } catch (e) {
                    console.error('Failed to expand input:', e);
                }
            }
        }
    });
}

        function closeModal() {
            document.getElementById('blockModal').classList.remove('active');
        }

        async function performSearch() {
            const query = document.getElementById('searchInput').value.trim();
            if (!query) return;
            
            if (/^\d+$/.test(query)) {
                viewBlock(parseInt(query));
                return;
            }
            
            try {
                const res = await fetch('/api/block/hash/' + query);
                if (res.ok) {
                    const block = await res.json();
                    viewBlock(block.height);
                } else {
                    alert('Block not found');
                }
            } catch (e) {
                alert('Search failed: ' + e.message);
            }
        }

        function startAutoRefresh() {
            setInterval(async () => {
                await loadStats();
                await loadBlocks();
                await loadSupply();
                if (state.currentView === 'mempool') {
                    await loadMempool();
                }
            }, 5000); // 5 seconds
        }

        function formatNumber(num) {
            // Convert BigInt to Number if needed
            if (typeof num === 'bigint') {
                num = Number(num);
            }
            
            const billion = 1e9;
            const million = 1e6;
            const thousand = 1e3;

            if (num >= billion) return (num / billion).toFixed(2) + 'B';
            if (num >= million) return (num / million).toFixed(2) + 'M';
            if (num >= thousand) return (num / thousand).toFixed(2) + 'K';
            return num.toLocaleString();
        }

        function formatBits(val) {
            // 1. Handle BigInt or String inputs safely
            const bits = Number(val);
            
            if (isNaN(bits)) return '0 ƀits';
            if (bits === 0) return '0 ƀits';

            // 2. Base Unit: < 1 ƀyte (8 bits)
            if (bits < 8) {
                return bits + ' ƀits';
            }

            // 3. Convert to ƀytes (Base 2^3)
            let value = bits / 8;
            const units = ['ƀytes', 'Kƀ', 'Mƀ', 'Gƀ', 'Tƀ'];
            let unitIndex = 0;

            // 4. Scale up by 1024 (2^10) steps
            while (value >= 1024 && unitIndex < units.length - 1) {
                value /= 1024;
                unitIndex++;
            }

            // 5. Formatting
            // If it's exact (integer), don't show decimals. Otherwise max 2 decimals.
            const formattedValue = value.toLocaleString('en-US', {
                minimumFractionDigits: 0,
                maximumFractionDigits: 2
            });

            return formattedValue + ' ' + units[unitIndex];
        }

        function formatBytes(bytes) {
            if (bytes >= 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
            if (bytes >= 1024) return (bytes / 1024).toFixed(2) + ' KB';
            return bytes + ' B';
        }

        function truncateHash(hash) {
            if (!hash) return 'N/A';
            if (hash.length < 20) return hash;
            return hash.substring(0, 12) + '...' + hash.substring(hash.length - 8);
        }

        function formatTime(timestamp) {
            const now = Date.now();
            // Convert BigInt timestamp to Number for subtraction
            const diff = now - Number(timestamp); 
            const seconds = Math.floor(diff / 1000);
            const minutes = Math.floor(seconds / 60);
            const hours = Math.floor(minutes / 60);

            if (hours > 0) return hours + 'h ago';
            if (minutes > 0) return minutes + 'm ago';
            // Handle potential negative diff if clocks are slightly skewed
            return Math.max(0, seconds) + 's ago'; // <-- Added Math.max(0, ...)
        }

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') closeModal();
        });

        document.getElementById('blockModal').addEventListener('click', (e) => {
            if (e.target.id === 'blockModal') closeModal();
        });

        document.getElementById('searchInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') performSearch();
        });

        init();
    </script>
</body>
</html>
    `);
});

// Security: Only bind to localhost
app.listen(PORT, BIND_ADDRESS, () => {
    console.log(`🔒 Pluriƀit Block Explorer running securely on http://${BIND_ADDRESS}:${PORT}`);
    console.log(`📡 Connected to node at ${NODE_API}`);
    console.log(`⚠️  Only accessible from localhost for security`);
});
