import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Appbar } from "../components/Appbar";
import URLImg from "../assets/worldwide.png";
import Searching from "../assets/searching.png";
import { motion } from "framer-motion";

export const Dashboard = () => {
    const navigate = useNavigate();
    const [selected, setSelected] = useState("FILE");
    const [file, setFile] = useState(null);
    const [dragActive, setDragActive] = useState(false);
    const [input, setInput] = useState("");
    const [loading, setLoading] = useState(false);
    const [errorMessage, setErrorMessage] = useState("");
    
    // New state to control showing the login prompt (modal/popup)
    const [showLoginPrompt, setShowLoginPrompt] = useState(false);

    // Retrieve token from localStorage (or sessionStorage, depending on your setup)
    const token = localStorage.getItem("token"); 
    const isLoggedIn = !!token; // Simple check: if there's a token, user is logged in

    // Variants for overall container animation
    const containerVariants = {
        hidden: { opacity: 0, y: 20 },
        visible: { opacity: 1, y: 0, transition: { duration: 0.5, ease: "easeOut" } },
        exit: { opacity: 0, y: -20, transition: { duration: 0.3 } },
    };

    // A simple fade-in variant for inner sections
    const fadeInVariants = {
        hidden: { opacity: 0 },
        visible: { opacity: 1, transition: { duration: 0.5 } },
    };

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
            setErrorMessage(""); // Clear any previous errors when a new file is dropped
        }
    };

    const handleFileChange = (e) => {
        setFile(e.target.files[0]);
        setErrorMessage("");
    };

    const handleSubmit = async () => {
        // If user is not logged in, show prompt and return early
        if (!isLoggedIn) {
            setShowLoginPrompt(true);
            return;
        }

        // If user is logged in, proceed as normal
        if (
            (!input && (selected === "URL" || selected === "SEARCH")) ||
            (!file && selected === "FILE")
        ) {
            return;
        }

        setLoading(true);
        setErrorMessage("");

        try {
            let response;
            // Add headers with authentication token
            const headers = {};
            if (token) {
                headers['Authorization'] = `Bearer ${token}`;
            }

            if (selected === "FILE") {
                const formData = new FormData();
                formData.append("file", file);
                
                response = await fetch("https://my-app.b22023.workers.dev/api/scan-file", {
                    method: "POST",
                    headers,
                    body: formData,
                });
            } else if (selected === "URL" || selected === "SEARCH") {
                // Now including the headers with auth token for URL and SEARCH requests
                response = await fetch(`https://my-app.b22023.workers.dev/api/search?query=${input}`, {
                    method: "GET",
                    headers
                });
            }

            const data = await response.json();

            if (!response.ok) {
                if (data.error === "Unsupported file type") {
                    setErrorMessage(
                        "Unsupported file type. Please upload exe, dll, bin files for binary scanning or png, jpg, jpeg for image analysis."
                    );
                } else {
                    setErrorMessage(data.error || "Analysis failed");
                }
                setLoading(false);
                return;
            }

            // Save analysis data to session storage
            sessionStorage.setItem("scanData", JSON.stringify(data));
            
            // Also save file name or search/URL query in session storage
            if (selected === "FILE" && file) {
                sessionStorage.setItem("scanFileName", file.name);
            } else if ((selected === "URL" || selected === "SEARCH") && input) {
                // Store with identifier prefix for better clarity in history view
                sessionStorage.setItem("scanFileName", `${selected}: ${input}`);
            }
    
            navigate("/search");
        } catch (error) {
            console.error("Error:", error);
            setErrorMessage(error.message || "Failed to analyze file");
            setLoading(false);
        }
    };

    return (
        <motion.div
            variants={containerVariants}
            initial="hidden"
            animate="visible"
            exit="exit"
            className="bg-lightBg dark:bg-darkBg min-h-screen flex flex-col"
        >
            <Appbar />

            <motion.div
                variants={fadeInVariants}
                initial="hidden"
                animate="visible"
                className="flex flex-col items-center justify-center flex-grow text-center px-6"
            >
                <motion.h1
                    className="text-5xl md:text-6xl font-extrabold text-lightText dark:text-darkText cursor-pointer"
                    whileHover={{ scale: 1.05 }}
                    onClick={() => navigate("/")}
                >
                    Anaware
                </motion.h1>

                <motion.p
                    className="mt-4 max-w-2xl text-xl md:text-lg text-gray-700 dark:text-gray-300"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1, transition: { delay: 0.3, duration: 0.5 } }}
                >
                    Analyse suspicious files, domains, IPs, and URLs to detect malware and other breaches,
                    automatically share them with the security community.
                </motion.p>

                {/* Selection Tabs */}
                <div className="flex justify-center space-x-8 bg-[#F9FAFB] dark:bg-[#111827] p-3 mt-8 rounded-lg w-full max-w-md">
                    {["FILE", "URL", "SEARCH"].map((option) => (
                        <motion.div
                            key={option}
                            whileHover={{ scale: 1.05 }}
                            className={`cursor-pointer text-md font-semibold px-4 py-2 transition-all ${
                                selected === option
                                    ? "text-blue-600 dark:text-blue-400 border-b-2 border-blue-600 dark:border-blue-400"
                                    : "text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200"
                            }`}
                            onClick={() => {
                                setSelected(option);
                                setInput("");
                                setFile(null);
                                setErrorMessage("");
                            }}
                        >
                            {option}
                        </motion.div>
                    ))}
                </div>

                {/* Error Message Display */}
                {errorMessage && (
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        className="mt-4 w-full max-w-lg bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded-lg dark:bg-red-900 dark:text-red-200 dark:border-red-800"
                    >
                        <div className="flex items-start">
                            <svg className="w-5 h-5 mr-2 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                                <path
                                    fillRule="evenodd"
                                    d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z"
                                    clipRule="evenodd"
                                ></path>
                            </svg>
                            <p>{errorMessage}</p>
                        </div>
                    </motion.div>
                )}

                {/* Content Section */}
                <motion.div
                    className="mt-6 w-full max-w-lg"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1, transition: { delay: 0.5, duration: 0.5 } }}
                >
                    {selected === "FILE" && (
                        <div
                            className={`flex flex-col items-center p-6 border-2 border-dashed rounded-lg ${
                                dragActive
                                    ? "border-blue-600"
                                    : errorMessage
                                    ? "border-red-400 dark:border-red-800"
                                    : "border-gray-400 dark:border-gray-600"
                            }`}
                            onDragEnter={handleDrag}
                            onDragOver={handleDrag}
                            onDragLeave={handleDrag}
                            onDrop={handleDrop}
                        >
                            <p className="text-gray-600 dark:text-gray-300 mb-4">
                                {file ? `Selected File: ${file.name}` : "Drag & drop your file here or click to upload"}
                            </p>
                            <p className="text-gray-500 dark:text-gray-400 text-xs mb-4">
                                Supported formats: .exe, .dll, .bin (for binary analysis) and .png, .jpg, .jpeg (for image analysis)
                            </p>
                            <input
                                type="file"
                                className="hidden"
                                id="fileInput"
                                onChange={handleFileChange}
                            />
                            <label
                                htmlFor="fileInput"
                                className="cursor-pointer bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700"
                            >
                                Choose a file
                            </label>
                            {file && (
                                <motion.button
                                    onClick={handleSubmit}
                                    whileTap={{ scale: 0.95 }}
                                    className="mt-4 bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700"
                                >
                                    Analyze File
                                </motion.button>
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
                            <motion.button
                                onClick={handleSubmit}
                                whileTap={{ scale: 0.95 }}
                                disabled={!input}
                                className={`mt-3 px-4 py-2 rounded-lg w-full ${
                                    input
                                        ? "bg-blue-600 hover:bg-blue-700 text-white"
                                        : "bg-gray-300 cursor-not-allowed text-gray-500"
                                }`}
                            >
                                Scan URL
                            </motion.button>
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
                            <motion.button
                                onClick={handleSubmit}
                                whileTap={{ scale: 0.95 }}
                                disabled={!input}
                                className={`mt-3 px-4 py-2 rounded-lg w-full ${
                                    input
                                        ? "bg-blue-600 hover:bg-blue-700 text-white"
                                        : "bg-gray-300 cursor-not-allowed text-gray-500"
                                }`}
                            >
                                Search
                            </motion.button>
                        </div>
                    )}

                    {loading && (
                        <motion.p
                            className="mt-4 text-blue-600 text-center"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                        >
                            Analyzing...
                        </motion.p>
                    )}
                </motion.div>
            </motion.div>

            {/* 
                Simple modal / popup to prompt login.
                You can style this however you like.
            */}
            {showLoginPrompt && (
                <div className="fixed inset-0 flex items-center justify-center bg-black bg-opacity-50 z-50">
                    <div className="bg-white dark:bg-gray-800 p-6 rounded shadow-lg max-w-sm w-full mx-4">
                        <h2 className="text-xl font-semibold text-gray-800 dark:text-white mb-4">
                            Please Sign In
                        </h2>
                        <p className="text-gray-700 dark:text-gray-200 mb-4">
                            You must be logged in to submit files or scan URLs.
                        </p>
                        <div className="flex justify-end space-x-2">
                            <button
                                onClick={() => navigate("/signin")} // or wherever your login route is
                                className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700"
                            >
                                Sign In
                            </button>
                            <button
                                onClick={() => setShowLoginPrompt(false)}
                                className="bg-gray-300 dark:bg-gray-700 text-gray-800 dark:text-gray-100 px-4 py-2 rounded hover:bg-gray-400 dark:hover:bg-gray-600"
                            >
                                Cancel
                            </button>
                        </div>
                    </div>
                </div>
            )}

            <motion.div
                className="text-center mt-6 px-6 pb-5 text-xs text-gray-600 dark:text-gray-400 max-w-2xl mx-auto"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1, transition: { delay: 0.7, duration: 0.5 } }}
            >
                By submitting data above, you are agreeing to our{" "}
                <a href="#" className="text-blue-600 dark:text-blue-400 underline">
                    Terms of Service
                </a>{" "}
                and{" "}
                <a href="#" className="text-blue-600 dark:text-blue-400 underline">
                    Privacy Notice
                </a>
                , and to the sharing of your Sample submission with the security community. Please do
                not submit any personal information; we are not responsible for the contents of your
                submission.{" "}
                <a href="#" className="text-blue-600 dark:text-blue-400 underline">
                    Learn more.
                </a>
            </motion.div>
        </motion.div>
    );
};