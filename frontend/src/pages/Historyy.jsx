import { useState } from "react";
import { Appbar } from "../components/Appbar";
import { Grid, List } from "lucide-react";

export const Historyy = () => {
  const [view, setView] = useState("grid");
  const [search, setSearch] = useState("");

  const historyData = [
    { id: 1, name: "malware.exe", percentage: 75, date: "2025-02-20" },
    { id: 2, name: "phishing-url.com", percentage: 90, date: "2025-02-18" },
    { id: 3, name: "safe-file.zip", percentage: 10, date: "2025-02-15" },
  ];

  const filteredData = historyData.filter((item) =>
    item.name.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="bg-lightBg dark:bg-darkBg min-h-screen flex flex-col">
      <Appbar />
      <div className="p-6">
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-2xl font-bold text-lightText dark:text-darkText">
            History
          </h2>
          <span className="text-sm text-gray-600 dark:text-gray-400">
            Total Elements in History: {filteredData.length}
          </span>
        </div>

        <div className="flex items-center justify-between mb-6">
          <input
            type="text"
            placeholder="Search history..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="px-4 py-2 dark:text-white w-full md:w-1/3 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          <div className="flex space-x-4">
            <button
              onClick={() => setView("grid")}
              className={`p-2 rounded-lg shadow-md transition ${
                view === "grid"
                  ? "bg-blue-600 text-white"
                  : "bg-gray-200 dark:bg-gray-400"
              }`}>
              <Grid size={20} />
            </button>
            <button
              onClick={() => setView("list")}
              className={`p-2 rounded-lg shadow-md transition ${
                view === "list"
                  ? "bg-blue-600 text-white"
                  : "bg-gray-200 dark:bg-gray-400"
              }`}>
              <List size={20} />
            </button>
          </div>
        </div>

        {view === "grid" ? (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {filteredData.map((item) => (
              <div
                key={item.id}
                className="p-6 bg-white dark:bg-gray-800 shadow-lg rounded-lg cursor-pointer hover:shadow-xl transition"
                onClick={() => console.log("Navigate to", item.name)}
              >
                <h3 className="text-lg font-semibold text-lightText dark:text-darkText">
                  {item.name}
                </h3>
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-2">
                  Malicious: {item.percentage}%
                </p>
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-2">
                  Date: {item.date}
                </p>
              </div>
            ))}
          </div>
        ) : (
          <table className="w-full text-left border-collapse">
            <thead>
              <tr>
                <th className="p-3 bg-white dark:bg-gray-800 text-lightText dark:text-darkText">
                  File/URL
                </th>
                <th className="p-3 bg-white dark:bg-gray-800 text-lightText dark:text-darkText">
                  Malicious %
                </th>
                <th className="p-3 bg-white dark:bg-gray-800 text-lightText dark:text-darkText">
                  Date
                </th>
              </tr>
            </thead>
            <tbody>
              {filteredData.map((item) => (
                <tr
                  key={item.id}
                  className="cursor-pointer bg-white dark:bg-gray-800 hover:bg-gray-100 dark:hover:bg-gray-700 shadow-lg rounded-lg transition"
                  onClick={() => console.log("Navigate to", item.name)}
                >
                  <td className="p-3 text-lightText dark:text-gray-400">{item.name}</td>
                  <td className="p-3 text-lightText dark:text-gray-400">{item.percentage}%</td>
                  <td className="p-3 text-lightText dark:text-gray-400">{item.date}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};