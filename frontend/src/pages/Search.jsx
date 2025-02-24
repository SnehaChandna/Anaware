import { useState } from 'react';
import { Appbar } from "../components/Appbar";

const SecurityVendorRow = ({ vendor, result }) => {
  const isClean = result?.category === "harmless" && result?.result === "clean";
  const status = result?.category || "undetected";
  
  return (
    <div className="flex items-center justify-between py-3 px-4 border-b border-gray-100 dark:border-gray-700">
      <div className="text-sm text-gray-900 dark:text-gray-100">{vendor}</div>
      <div className="flex items-center gap-2">
        <svg 
          className={`w-4 h-4 ${isClean ? 'text-green-500' : 'text-gray-400'}`} 
          viewBox="0 0 20 20" 
          fill="currentColor"
        >
          <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
        </svg>
        <span className="text-sm text-gray-600 dark:text-gray-400">
          {status.charAt(0).toUpperCase() + status.slice(1)}
        </span>
      </div>
    </div>
  );
};

export const Search = ({ scanData }) => {
  const [activeTab, setActiveTab] = useState('DETECTION');
  
  // Handle both URL and search response formats
  const attributes = scanData?.data?.[0]?.attributes || {};
  const analysisResults = attributes?.last_analysis_results || {};
  const stats = attributes?.last_analysis_stats || {};
  
  // Determine the type of data and identifier based on response
  const getDataType = () => {
    if (attributes.url) return 'URL';
    if (attributes.type) return attributes.type;
    return 'Unknown';
  };

  const getIdentifier = () => {
    if (attributes.url) return attributes.url;
    if (attributes.id) return attributes.id;
    return 'N/A';
  };

  const type = getDataType();
  const identifier = getIdentifier();
  const lastAnalysisDate = attributes.last_analysis_date;

  const formatDate = (timestamp) => {
    if (!timestamp) return '';
    return new Date(timestamp * 1000).toLocaleString();
  };

  const vendorEntries = Object.entries(analysisResults);
  const score = stats.malicious || 0;
  const totalVendors = Object.values(stats).reduce((a, b) => a + b, 0);

  return (
    <div className="bg-gray-50 dark:bg-gray-900 min-h-screen flex flex-col">
      <Appbar />
      
      <div className="max-w-[1400px] mx-auto w-full px-4 py-6">
        <div className="flex flex-col lg:flex-row gap-6">
          {/* Score Circle */}
          <div className="bg-white dark:bg-darkBg p-4 rounded-lg shadow-sm w-full sm:w-32 mx-auto lg:mx-0">
            <div className="relative">
              <div className={`w-16 h-16 mx-auto rounded-full border-4 ${score > 0 ? 'border-red-500' : 'border-green-500'} flex items-center justify-center`}>
                <span className="text-2xl dark:text-gray-200 font-semibold">{score}</span>
              </div>
              <div className="text-center mt-2 text-xs text-gray-600 dark:text-gray-400">
                Detection<br />Score
                <span className="text-xs text-gray-400">/{totalVendors}</span>
              </div>
            </div>
          </div>

          {/* Main Content */}
          <div className="flex-1 bg-white dark:bg-gray-800 rounded-lg shadow-sm">
            <div className="p-3 bg-gray-50 dark:bg-gray-900 rounded-t-lg flex flex-wrap gap-2 justify-between">
              <div className={`flex items-center gap-2 ${score > 0 ? 'text-red-600' : 'text-green-600'} dark:text-green-500`}>
                <svg className="w-5 h-5" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                </svg>
                <span>
                  {score === 0 
                    ? `No security vendors flagged this ${type} as malicious`
                    : `${score} security vendors flagged this ${type} as malicious`}
                </span>
              </div>
            </div>

            <div className="p-3">
              <div className="text-sm font-mono text-gray-600 dark:text-gray-400 break-all">
                {identifier}
              </div>
              <div className="mt-1 text-sm text-gray-500">
                Last analyzed: {formatDate(lastAnalysisDate)}
              </div>
              {attributes.reputation !== undefined && (
                <div className="mt-1 text-sm text-gray-500">
                  Reputation Score: {attributes.reputation}
                </div>
              )}
            </div>

            <div className="border-t dark:border-gray-700">
              <div className="flex border-b dark:border-gray-700">
                {['DETECTION', 'DETAILS'].map((tab) => (
                  <button
                    key={tab}
                    className={`px-6 py-2 text-sm font-medium ${
                      activeTab === tab
                        ? 'border-b-2 border-blue-500 text-blue-600 dark:text-blue-400'
                        : 'text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300'
                    }`}
                    onClick={() => setActiveTab(tab)}
                  >
                    {tab}
                  </button>
                ))}
              </div>

              <div className="p-4">
                {activeTab === 'DETECTION' && (
                  <div className="overflow-x-auto">
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="text-sm dark:text-white font-medium flex items-center gap-2">
                        Security vendors' analysis
                      </h3>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      {vendorEntries.map(([vendor, result], index) => (
                        <SecurityVendorRow 
                          key={index}
                          vendor={vendor}
                          result={result}
                        />
                      ))}
                    </div>
                  </div>
                )}
                
                {activeTab === 'DETAILS' && (
                  <div className="text-sm dark:bg-gray-900 dark:text-gray-200 p-4 rounded-lg">
                    <h3 className="font-medium mb-4">Analysis Statistics</h3>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      {Object.entries(stats).map(([key, value]) => (
                        <div key={key}>
                          <div className="text-gray-500 dark:text-gray-400 capitalize">{key}</div>
                          <div className="dark:text-gray-300">{value}</div>
                        </div>
                      ))}
                    </div>
                    {attributes.categories && (
                      <div className="mt-6">
                        <h3 className="font-medium mb-2">Categories</h3>
                        <div className="flex flex-wrap gap-2">
                          {Object.entries(attributes.categories).map(([provider, category]) => (
                            <div key={provider} className="bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded text-xs">
                              {category}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};