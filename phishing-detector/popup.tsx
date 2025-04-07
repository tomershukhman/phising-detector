import { useEffect, useState } from "react"
import { UrlAnalyzer } from "./src/utils/urlAnalysis"

function IndexPopup() {
  const [currentUrl, setCurrentUrl] = useState("")
  const [analysisResult, setAnalysisResult] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // Get the current tab URL when the popup opens
    const getCurrentTabUrl = async () => {
      setLoading(true)
      try {
        // Query for the active tab in the current window
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true })
        const url = tabs[0]?.url || ""
        setCurrentUrl(url)
        
        // Analyze the URL
        if (url) {
          const analyzer = new UrlAnalyzer()
          const result = analyzer.analyzeUrl(url)
          setAnalysisResult(result)
        }
      } catch (error) {
        console.error("Error getting tab URL:", error)
      } finally {
        setLoading(false)
      }
    }

    getCurrentTabUrl()
  }, [])

  // Helper function to get icon and color based on risk level
  const getRiskDisplay = () => {
    if (!analysisResult) return { icon: "⏳", color: "#888", text: "Unknown" }

    const analyzer = new UrlAnalyzer()
    const riskLevel = analyzer.getRiskLevel(analysisResult.risk)

    switch (riskLevel) {
      case "Low":
        return { 
          icon: "✅", 
          color: "#4CAF50", 
          text: "Low Risk",
          description: "This URL appears to be safe."
        }
      case "Medium":
        return { 
          icon: "⚠️", 
          color: "#FF9800", 
          text: "Medium Risk",
          description: "This URL has some suspicious characteristics."
        }
      case "High":
        return { 
          icon: "❌", 
          color: "#F44336", 
          text: "High Risk - Potential Phishing",
          description: "This URL has multiple phishing indicators."
        }
      default:
        return { 
          icon: "⏳", 
          color: "#888", 
          text: "Unknown",
          description: "Could not analyze this URL."
        }
    }
  }

  const riskDisplay = getRiskDisplay()

  // Function to render flags as badges
  const renderFlags = () => {
    if (!analysisResult?.flags?.length) return null
    
    return (
      <div className="flags-container">
        <h3>Detected Issues:</h3>
        <div className="flags-list">
          {analysisResult.flags.map((flag, index) => (
            <span key={index} className="flag-badge">
              {flag.replace(/_/g, " ")}
            </span>
          ))}
        </div>
      </div>
    )
  }

  // Function to render suspicious patterns
  const renderSuspiciousPatterns = () => {
    if (!analysisResult?.suspiciousPatterns?.length) return null
    
    return (
      <div className="patterns-container">
        <h3>Suspicious Keywords:</h3>
        <div className="patterns-list">
          {analysisResult.suspiciousPatterns.map((pattern, index) => (
            <span key={index} className="pattern-badge">
              {pattern}
            </span>
          ))}
        </div>
      </div>
    )
  }

  // Function to render brand impersonation info
  const renderBrandInfo = () => {
    if (!analysisResult?.brandMatches) return null
    
    return (
      <div className="brand-warning">
        <strong>Warning:</strong> This URL may be impersonating{" "}
        <strong>{analysisResult.typosquatting}</strong>
      </div>
    )
  }

  return (
    <div 
      style={{
        padding: 16,
        width: "350px",
        fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif",
        color: "#333"
      }}
    >
      <style>
        {`
          body {
            margin: 0;
            padding: 0;
          }
          h2 {
            margin-top: 0;
            margin-bottom: 10px;
          }
          .result-container {
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
          }
          .risk-icon {
            font-size: 24px;
            margin-right: 12px;
          }
          .domain-display {
            background: #f5f5f5;
            padding: 8px 10px;
            border-radius: 6px;
            font-family: monospace;
            word-break: break-all;
            margin-bottom: 15px;
            font-size: 14px;
            border: 1px solid #ddd;
          }
          .flags-container, .patterns-container {
            margin-top: 16px;
          }
          .flags-list, .patterns-list {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            margin-top: 8px;
          }
          .flag-badge {
            background: #f0f0f0;
            border: 1px solid #ddd;
            border-radius: 12px;
            padding: 3px 8px;
            font-size: 12px;
          }
          .pattern-badge {
            background: #fff3e0;
            border: 1px solid #ffe0b2;
            border-radius: 12px;
            padding: 3px 8px;
            font-size: 12px;
          }
          .brand-warning {
            background: #ffebee;
            border-left: 3px solid #f44336;
            padding: 10px;
            margin-top: 15px;
            font-size: 14px;
          }
          .risk-percentage {
            margin: 8px 0;
            height: 6px;
            border-radius: 3px;
            background: #eee;
            overflow: hidden;
            position: relative;
          }
          .risk-percentage-fill {
            height: 100%;
            background: linear-gradient(to right, #4CAF50, #FF9800, #F44336);
            width: ${analysisResult?.risk ? Math.round(analysisResult.risk * 100) : 0}%;
          }
          .risk-text {
            display: flex;
            justify-content: space-between;
            font-size: 12px;
            margin-top: 4px;
            color: #666;
          }
          .loading-spinner {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100px;
          }
          @keyframes spin {
            to { transform: rotate(360deg); }
          }
          .spinner {
            width: 30px;
            height: 30px;
            border: 3px solid rgba(0,0,0,0.1);
            border-radius: 50%;
            border-top-color: #888;
            animation: spin 1s linear infinite;
          }
        `}
      </style>

      <h2>Phishing Detector</h2>

      {loading ? (
        <div className="loading-spinner">
          <div className="spinner"></div>
        </div>
      ) : (
        <>
          <div className="domain-display" title={currentUrl}>
            {currentUrl ? new URL(currentUrl).hostname : "Unknown URL"}
          </div>
          
          <div className="result-container" style={{ backgroundColor: riskDisplay.color + '15' }}>
            <div className="risk-icon">{riskDisplay.icon}</div>
            <div>
              <strong style={{ color: riskDisplay.color }}>{riskDisplay.text}</strong>
              <div style={{ fontSize: '14px' }}>{riskDisplay.description}</div>
            </div>
          </div>
          
          {analysisResult && (
            <>
              <div className="risk-meter">
                <div className="risk-percentage">
                  <div className="risk-percentage-fill"></div>
                </div>
                <div className="risk-text">
                  <span>Risk score: {Math.round(analysisResult.risk * 100)}%</span>
                </div>
              </div>
              
              {renderBrandInfo()}
              {renderFlags()}
              {renderSuspiciousPatterns()}
            </>
          )}
        </>
      )}
      
      <div style={{ fontSize: "11px", marginTop: "15px", textAlign: "center", color: "#888" }}>
        Powered by URL Analyzer • {new Date().toLocaleDateString()}
      </div>
    </div>
  )
}

export default IndexPopup
