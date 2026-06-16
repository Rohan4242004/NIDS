import { useEffect, useState } from 'react';
import { CheckCircle, ToggleLeft, ToggleRight, Sparkles, Award, Cpu } from 'lucide-react';
import { modelsService } from '../services/api';

const ModelControl = () => {
  const [models, setModels] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeModel, setActiveModel] = useState(null);

  const fetchModels = async () => {
    setLoading(true);
    try {
      const data = await modelsService.getModels();
      setModels(data);
      const active = data.find(m => m.is_active);
      setActiveModel(active || null);
    } catch (err) {
      console.error('Failed to load ML models: ', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    Promise.resolve().then(() => {
      fetchModels();
    });
  }, []);

  const handleActivateModel = async (id) => {
    if (!confirm('Are you sure you want to switch the active machine learning model for live network classification?')) return;
    
    try {
      const updated = await modelsService.activateModel(id);
      setModels(prev => prev.map(m => ({
        ...m,
        is_active: m.id === updated.id
      })));
      setActiveModel(updated);
    } catch (err) {
      alert('Failed to switch model: ' + (err.response?.data?.detail || err.message));
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '30px' }}>
      
      {/* Active model summary spotlight */}
      {activeModel && (
        <div className="glass-panel cyan-glow" style={{
          display: 'grid',
          gridTemplateColumns: '8fr 4fr',
          gap: '30px',
          alignItems: 'center',
          background: 'linear-gradient(135deg, rgba(17, 24, 39, 0.9) 0%, rgba(6, 182, 212, 0.04) 100%)'
        }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--primary)', marginBottom: '12px' }}>
              <Sparkles size={16} />
              <span style={{ fontSize: '0.75rem', fontWeight: 700, letterSpacing: '1px', textTransform: 'uppercase' }}>Active Classifier Live</span>
            </div>
            <h3 style={{ fontSize: '1.5rem', fontWeight: 800, marginBottom: '6px' }}>{activeModel.model_name}</h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '20px' }}>
              Currently processing Scapy network packet flow feature arrays and predicting cyber threats in real-time.
            </p>
            <div style={{ display: 'flex', gap: '24px' }}>
              <div>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>VERSION</span>
                <p style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: '1rem' }} className="text-mono">{activeModel.version}</p>
              </div>
              <div>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>DEPLOYED ON</span>
                <p style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: '1rem' }} className="text-mono">
                  {new Date(activeModel.deployed_at).toLocaleDateString()}
                </p>
              </div>
              <div>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>SERIALIZED PATH</span>
                <p style={{ fontWeight: 600, color: 'var(--text-secondary)', fontSize: '0.85rem' }} className="text-mono">{activeModel.filepath}</p>
              </div>
            </div>
          </div>

          {/* Model metrics widgets */}
          <div style={{
            display: 'flex',
            gap: '16px',
            backgroundColor: 'var(--bg-primary)',
            padding: '20px',
            borderRadius: 'var(--radius)',
            border: '1px solid var(--border-color)',
            justifyContent: 'space-around'
          }}>
            <div style={{ textAlign: 'center' }}>
              <Award size={20} color="var(--primary)" style={{ marginBottom: '6px' }} />
              <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', display: 'block' }}>ACCURACY</span>
              <span style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--primary)' }} className="text-mono">
                {(activeModel.accuracy * 100).toFixed(1)}%
              </span>
            </div>
            <div style={{ width: '1px', backgroundColor: 'var(--border-color)' }}></div>
            <div style={{ textAlign: 'center' }}>
              <Cpu size={20} color="var(--color-benign)" style={{ marginBottom: '6px' }} />
              <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', display: 'block' }}>WEIGHTED F1</span>
              <span style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--color-benign)' }} className="text-mono">
                {(activeModel.f1_score * 100).toFixed(1)}%
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Model inventory table */}
      <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        <div>
          <h4 style={{ fontSize: '1.1rem', fontWeight: 800 }}>Model Version Registries</h4>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Toggle active model weight assets on the fly.</span>
        </div>

        <div style={{ overflowX: 'auto', border: '1px solid var(--border-color)', borderRadius: '8px' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
            <thead>
              <tr style={{ backgroundColor: 'rgba(255, 255, 255, 0.02)', borderBottom: '1px solid var(--border-color)' }}>
                <th style={{ padding: '14px 16px', color: 'var(--text-muted)' }}>VERSION</th>
                <th style={{ padding: '14px 16px', color: 'var(--text-muted)' }}>MODEL TYPE NAME</th>
                <th style={{ padding: '14px 16px', color: 'var(--text-muted)' }}>TEST ACCURACY</th>
                <th style={{ padding: '14px 16px', color: 'var(--text-muted)' }}>F1-SCORE</th>
                <th style={{ padding: '14px 16px', color: 'var(--text-muted)' }}>STATUS</th>
                <th style={{ padding: '14px 16px', color: 'var(--text-muted)', textAlign: 'right' }}>TOGGLE LIVE</th>
              </tr>
            </thead>
            <tbody>
              {!loading && models.length > 0 ? models.map((model) => (
                <tr 
                  key={model.id} 
                  style={{ 
                    borderBottom: '1px solid var(--border-color)', 
                    backgroundColor: model.is_active ? 'rgba(6, 182, 212, 0.01)' : 'transparent' 
                  }}
                >
                  <td style={{ padding: '14px 16px', fontWeight: 600 }} className="text-mono">{model.version}</td>
                  <td style={{ padding: '14px 16px', fontWeight: 700 }}>{model.model_name}</td>
                  <td style={{ padding: '14px 16px' }} className="text-mono">{(model.accuracy * 100).toFixed(2)}%</td>
                  <td style={{ padding: '14px 16px' }} className="text-mono">{(model.f1_score * 100).toFixed(2)}%</td>
                  <td style={{ padding: '14px 16px' }}>
                    {model.is_active ? (
                      <span className="badge badge-benign" style={{ gap: '4px' }}>
                        <CheckCircle size={12} />
                        ACTIVE
                      </span>
                    ) : (
                      <span className="badge" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
                        STANDBY
                      </span>
                    )}
                  </td>
                  <td style={{ padding: '14px 16px', textAlign: 'right' }}>
                    {!model.is_active ? (
                      <button 
                        onClick={() => handleActivateModel(model.id)}
                        style={{
                          background: 'none',
                          border: 'none',
                          color: 'var(--text-muted)',
                          cursor: 'pointer',
                          display: 'inline-flex',
                          alignItems: 'center',
                          padding: '4px'
                        }}
                        title="Click to activate model"
                      >
                        <ToggleLeft size={28} />
                      </button>
                    ) : (
                      <span style={{ color: 'var(--primary)', padding: '4px', display: 'inline-flex', alignItems: 'center' }}>
                        <ToggleRight size={28} />
                      </span>
                    )}
                  </td>
                </tr>
              )) : (
                <tr>
                  <td colSpan="6" style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
                    {loading ? 'Querying ML model registry...' : 'No models registered in system databases.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default ModelControl;
