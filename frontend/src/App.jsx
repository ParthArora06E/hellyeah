import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import DashboardPage from './pages/DashboardPage';
import ScanRunnerPage from './pages/ScanRunnerPage';
import ScanDiffPage from './pages/ScanDiffPage';
import AssetsPage from './pages/AssetsPage';
import FindingsPage from './pages/FindingsPage';
import AIPlaybookPage from './pages/AIPlaybookPage';
import CostAnalyticsPage from './pages/CostAnalyticsPage';
import MonitoringPage from './pages/MonitoringPage';
import CompliancePage from './pages/CompliancePage';
import ReportsPage from './pages/ReportsPage';
import SettingsPage from './pages/SettingsPage';
import AttackGraph from './components/AttackGraph';
import AICISOCopilot from './components/AICISOCopilot';

export default function App() {
  const [currentTab, setCurrentTab] = useState('dashboard');
  const [scans, setScans] = useState([]);
  const [activeScan, setActiveScan] = useState(null);

  // Authentication State
  const [user, setUser] = useState({
    id: 1,
    email: 'pro@hackingly.io',
    full_name: 'Pro Security Engineer',
    role: 'pro'
  });
  const [token, setToken] = useState(localStorage.getItem('auditor_auth_token') || '');

  // Initialize or verify authentication on load
  const initAuth = async () => {
    try {
      const res = await fetch('/api/auth/switch-account', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role: user?.role || 'pro' })
      });
      if (res.ok) {
        const data = await res.json();
        setUser(data.user);
        setToken(data.access_token);
        localStorage.setItem('auditor_auth_token', data.access_token);
      }
    } catch (e) {
      console.error('Auth initialization error:', e);
    }
  };

  const handleSwitchUser = async (targetRole) => {
    try {
      const res = await fetch('/api/auth/switch-account', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role: targetRole })
      });
      if (res.ok) {
        const data = await res.json();
        setUser(data.user);
        setToken(data.access_token);
        localStorage.setItem('auditor_auth_token', data.access_token);
      }
    } catch (e) {
      console.error('Account switch error:', e);
    }
  };

  const handleUpgradeUser = async () => {
    try {
      const res = await fetch('/api/auth/upgrade', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      if (res.ok) {
        const data = await res.json();
        setUser(prev => ({ ...prev, role: 'pro' }));
        if (data.access_token) {
          setToken(data.access_token);
          localStorage.setItem('auditor_auth_token', data.access_token);
        }
      }
    } catch (e) {
      console.error('Upgrade error:', e);
    }
  };

  const handleSelectScan = (scan) => {
    if (scan) {
      setActiveScan(scan);
      localStorage.setItem('auditor_active_scan_id', scan.id);
    }
  };

  const fetchScans = () => {
    fetch('/api/scans')
      .then(r => r.json())
      .then(data => {
        if (Array.isArray(data) && data.length > 0) {
          setScans(data);
          setActiveScan(prev => {
            const savedId = localStorage.getItem('auditor_active_scan_id');
            const targetId = prev?.id || savedId;
            if (targetId) {
              const matched = data.find(s => s.id === targetId);
              if (matched) return matched;
            }
            if (!prev) {
              localStorage.setItem('auditor_active_scan_id', data[0].id);
              return data[0];
            }
            return prev;
          });
        }
      })
      .catch(console.error);
  };

  const runningScan = scans.find(s => s.status === 'running' || s.status === 'queued');

  useEffect(() => {
    initAuth();
    fetchScans();
  }, []);

  useEffect(() => {
    // Poll more frequently if a scan is running, or periodically otherwise
    const intervalTime = runningScan ? 2000 : 8000;
    const interval = setInterval(fetchScans, intervalTime);
    return () => clearInterval(interval);
  }, [runningScan?.id, runningScan?.progress, runningScan?.status]);

  const handleScanCompleted = (scanId) => {
    fetch('/api/scans')
      .then(r => r.json())
      .then(data => {
        if (Array.isArray(data) && data.length > 0) {
          setScans(data);
          const found = data.find(s => s.id === scanId) || data[0];
          handleSelectScan(found);
          setCurrentTab('dashboard');
        }
      });
  };

  return (
    <div className="flex flex-col min-h-screen bg-slate-950 text-slate-100">
      <Navbar
        activeScan={activeScan}
        scans={scans}
        runningScan={runningScan}
        onSelectScan={handleSelectScan}
        onNewScanClick={() => setCurrentTab('runner')}
        onNavigateTab={setCurrentTab}
        user={user}
        onSwitchUser={handleSwitchUser}
        onUpgradeUser={handleUpgradeUser}
      />

      <div className="flex flex-1 overflow-hidden">
        <Sidebar
          currentTab={currentTab}
          onSelectTab={setCurrentTab}
          runningScan={runningScan}
          counts={{
            assets: activeScan?.total_assets,
            findings: activeScan?.total_findings
          }}
        />

        <main className="flex-1 overflow-y-auto p-6 md:p-8 max-w-7xl mx-auto w-full">
          {currentTab === 'dashboard' && (
            <DashboardPage
              scan={activeScan}
              onNavigateTab={setCurrentTab}
              onSelectScan={handleSelectScan}
              onScanStarted={fetchScans}
            />
          )}
          {currentTab === 'graph' && (
            <AttackGraph scan={activeScan} findings={activeScan?.findings} onNavigateTab={setCurrentTab} />
          )}
          {currentTab === 'runner' && (
            <ScanRunnerPage
              onScanCompleted={handleScanCompleted}
              onScanStarted={() => fetchScans()}
              activeScan={activeScan}
              scans={scans}
              runningScan={runningScan}
              onSelectScan={(s) => {
                setActiveScan(s);
                setCurrentTab('dashboard');
              }}
            />
          )}
          {currentTab === 'diff' && (
            <ScanDiffPage
              scan={activeScan}
              onSelectScan={handleSelectScan}
              onScanStarted={fetchScans}
              onNavigateTab={setCurrentTab}
            />
          )}
          {currentTab === 'assets' && (
            <AssetsPage scan={activeScan} />
          )}
          {currentTab === 'findings' && (
            <FindingsPage scan={activeScan} onNavigateTab={setCurrentTab} />
          )}
          {currentTab === 'playbook' && (
            <AIPlaybookPage
              scan={activeScan}
              user={user}
              token={token}
              onSwitchToPro={() => handleSwitchUser('pro')}
              onUpgradeToPro={handleUpgradeUser}
            />
          )}
          {currentTab === 'compliance' && (
            <CompliancePage scan={activeScan} />
          )}
          {currentTab === 'cost' && (
            <CostAnalyticsPage scan={activeScan} />
          )}
          {currentTab === 'monitoring' && (
            <MonitoringPage />
          )}
          {currentTab === 'reports' && (
            <ReportsPage scan={activeScan} user={user} token={token} />
          )}
          {currentTab === 'settings' && (
            <SettingsPage />
          )}
        </main>
      </div>

      {/* Footer Legal & Consent Notice */}
      <footer className="h-9 border-t border-slate-900 bg-slate-950/80 px-6 flex items-center justify-between text-[11px] text-slate-500">
        <div>
          <span>Auditor ASM Platform &bull; Open Innovation Hackathon Edition</span>
        </div>
        <div>
          <span>Legal: Safe, non-destructive external scanning. For authorized targets and security evaluations only.</span>
        </div>
      </footer>

      {/* Floating Global AI CISO Copilot Assistant */}
      <AICISOCopilot scan={activeScan} onNavigateTab={setCurrentTab} />
    </div>
  );
}
