import { useState } from "react";
import { Appbar } from "../components/Appbar";
import URLImg from "../assets/worldwide.png";
import Searching from "../assets/searching.png";
import { Search } from "./Search";

export const Dashboard = () => {
    const [selected, setSelected] = useState("FILE");
    const [file, setFile] = useState(null);
    const [dragActive, setDragActive] = useState(false);
    const [input, setInput] = useState("");
    const [loading, setLoading] = useState(false);
    const [scanData, setScanData] = useState(null);

    const handleDrag = (e) => {
        e.preventDefault();
        e.stopPropagation();
        setDragActive(e.type === "dragenter" || e.type === "dragover");
    };

    const handleDrop = (e) => {
        e.preventDefault();
        e.stopPropagation();
        setDragActive(false);
        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            setFile(e.dataTransfer.files[0]);
        }
    };

    const handleFileChange = (e) => {
        setFile(e.target.files[0]);
    };

    const handleSubmit = async () => {
        if ((!input && (selected === "URL" || selected === "SEARCH")) || 
            (!file && selected === "FILE")) return;
            
        setLoading(true);
        setScanData(null);

        try {
            let response;
            if (selected === "FILE") {
                const formData = new FormData();
                formData.append("file", file);
                response = await fetch("http://localhost:8787/api/scan-file", {
                  method: "POST",
                  body: formData
                });
              }else if (selected === "URL") {
                response = await fetch(`http://localhost:8787/api/search?query=${input}`);
            } else if (selected === "SEARCH") {
                response = await fetch(`http://localhost:8787/api/search?query=${input}`);
            }

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Analysis failed');
            }

            const data = await response.json();
            setScanData(data);
            console.log('Analysis results:', data);
            
        } catch (error) {
            console.error("Error:", error);
            setScanData({ 
            error: error.message || "Failed to analyze file",
            details: error.toString() 
            });
        } finally {
            setLoading(false);
        }
    };

    // If we have scan data and we're in URL, SEARCH, or FILE mode, show the Search component
    if (scanData && (selected === "URL" || selected === "SEARCH" || selected === "FILE")) {
        return <Search scanData={scanData} />;
    }

    return (
        <div className="bg-lightBg dark:bg-darkBg min-h-screen flex flex-col">
            <Appbar />
            
            <div className="flex flex-col items-center justify-center flex-grow text-center px-6">
                <h1 className="text-5xl md:text-6xl font-extrabold text-lightText dark:text-darkText" onClick={() => navigate("/")}>
                    Anaware
                </h1>

                <p className="mt-4 max-w-2xl text-xl md:text-lg text-gray-700 dark:text-gray-300">
                    Analyse suspicious files, domains, IPs, and URLs to detect malware and other breaches, 
                    automatically share them with the security community.
                </p>

                {/* Selection Tabs */}
                <div className="flex justify-center space-x-8 bg-[#F9FAFB] dark:bg-[#111827] p-3 mt-8 rounded-lg w-full max-w-md">
                    {["FILE", "URL", "SEARCH"].map((option) => (
                        <div
                            key={option}
                            className={`cursor-pointer text-md font-semibold px-4 py-2 transition-all ${
                                selected === option
                                    ? "text-blue-600 dark:text-blue-400 border-b-2 border-blue-600 dark:border-blue-400"
                                    : "text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200"
                            }`}
                            onClick={() => {
                                setSelected(option);
                                setInput("");
                                setFile(null);
                                setScanData(null);
                            }}>
                            {option}
                        </div>
                    ))}
                </div>

                {/* Content Section */}
                <div className="mt-6 w-full max-w-lg">
                    {selected === "FILE" && (
                        <div 
                            className={`flex flex-col items-center p-6 border-2 border-dashed rounded-lg ${dragActive ? "border-blue-600" : "border-gray-400 dark:border-gray-600"}`} 
                            onDragEnter={handleDrag} 
                            onDragOver={handleDrag} 
                            onDragLeave={handleDrag} 
                            onDrop={handleDrop}
                        >
                            <p className="text-gray-600 dark:text-gray-300 mb-4">
                                {file ? `Selected File: ${file.name}` : "Drag & drop your file here or click to upload"}
                            </p>
                            <input
                                type="file"
                                className="hidden"
                                id="fileInput"
                                onChange={handleFileChange}
                            />
                            <label 
                                htmlFor="fileInput" 
                                className="cursor-pointer bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700">
                                Choose a file
                            </label>
                            {file && (
                                <button 
                                    onClick={handleSubmit}
                                    className="mt-4 bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700">
                                    Analyze File
                                </button>
                            )}
                        </div>
                    )}

                    {selected === "URL" && (
                        <div className="flex flex-col items-center">
                            <img src={URLImg} alt="URL Icon" className="w-20 h-20 mb-4" />
                            <input
                                type="text"
                                placeholder="Enter a URL to scan (e.g., example.com)"
                                className="bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-white p-2 rounded-lg border border-gray-400 dark:border-gray-600 w-full"
                                value={input}
                                onChange={(e) => setInput(e.target.value)}
                            />
                            <button 
                                onClick={handleSubmit}
                                disabled={!input} 
                                className={`mt-3 px-4 py-2 rounded-lg w-full ${
                                    input 
                                        ? "bg-blue-600 hover:bg-blue-700 text-white" 
                                        : "bg-gray-300 cursor-not-allowed text-gray-500"
                                }`}>
                                Scan URL
                            </button>
                        </div>
                    )}

                    {selected === "SEARCH" && (
                        <div className="flex flex-col items-center">
                            <img src={Searching} alt="Search Icon" className="w-20 h-20 mb-5" />
                            <input
                                type="text"
                                placeholder="Enter URL, IP, domain, or file hash"
                                className="bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-white p-2 rounded-lg border border-gray-400 dark:border-gray-600 w-full"
                                value={input}
                                onChange={(e) => setInput(e.target.value)}
                            />
                            <button 
                                onClick={handleSubmit}
                                disabled={!input}
                                className={`mt-3 px-4 py-2 rounded-lg w-full ${
                                    input 
                                        ? "bg-blue-600 hover:bg-blue-700 text-white" 
                                        : "bg-gray-300 cursor-not-allowed text-gray-500"
                                }`}>
                                Search
                            </button>
                        </div>
                    )}

                    {loading && <p className="mt-4 text-blue-600 text-center">Analyzing...</p>}
                </div>
            </div>

            <div className="text-center mt-6 px-6 pb-5 text-xs text-gray-600 dark:text-gray-400 max-w-2xl mx-auto">
                By submitting data above, you are agreeing to our <a href="#" className="text-blue-600 dark:text-blue-400 underline">Terms of Service</a> and <a href="#" className="text-blue-600 dark:text-blue-400 underline">Privacy Notice</a>, and to the sharing of your Sample submission with the security community. Please do not submit any personal information; we are not responsible for the contents of your submission. <a href="#" className="text-blue-600 dark:text-blue-400 underline">Learn more.</a>
            </div>
        </div>
    );
};