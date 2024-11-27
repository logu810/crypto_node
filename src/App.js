import './App.css';
import React, { useState, useEffect } from "react";
import axios from "axios";

function App() {
  const [publicKey, setPublicKey] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [file, setFile] = useState("");
  const [availableFiles, setAvailableFiles] = useState([]);
  const [encryptedData, setEncryptedData] = useState(null);
  const [decryptedData, setDecryptedData] = useState(null);
  const [decryptedFileName, setDecryptedFileName] = useState(null); // To hold the filename for download
  const [activeSection, setActiveSection] = useState("upload");

  // Fetch available files from the server
  const fetchAvailableFiles = async (folder) => {
    try {
      const response = await axios.get(`http://localhost:8080/files/${folder}`);
      setAvailableFiles(response.data);
    } catch (error) {
      console.error("Error fetching files:", error);
    }
  };

  // Generate BFV keys
  const generateKeys = async () => {
    const response = await axios.post("http://localhost:8080/generate-key");
    setPublicKey(response.data.public_key);
    setSecretKey(response.data.secret_key);
  };

  // Handle file upload
  const handleFileUpload = (e) => {
    setFile(e.target.files[0]);
  };

  const uploadAndEncrypt = async () => {
    if (!file) {
      alert("Please select a file first.");
      return;
    }

    const formData = new FormData();
    formData.append("file", file);
    formData.append("public_key", JSON.stringify(publicKey));
    formData.append("secret_key", JSON.stringify(secretKey));

    try {
      await axios.post("http://localhost:8080/upload-file", formData);
      alert("File uploaded and encrypted successfully.");
    } catch (error) {
      console.error("Error during encryption:", error);
    }
  };

  // Analyze encrypted data with the selected file name
  const analyzeFile = async () => {
    if (!file) {
      alert("Please select a file first.");
      return;
    }

    try {
      const response = await axios.post(`http://localhost:8080/analyze/${file}`);
      setEncryptedData(response.data);
      alert("Analysis completed successfully.");
    } catch (error) {
      console.error("Error during analysis:", error);
    }
  };

  // Decrypt analysis results
  const decryptData = async () => {
    if (!file) {
      alert("Please select a file first.");
      return;
    }

    try {
      const response = await axios.post(`http://localhost:8080/decrypt/${file}`, { secret_key: secretKey });
      setDecryptedData(response.data); // Assuming response contains decrypted data
      setDecryptedFileName(`${file}`); // Set filename for download
      alert("Decryption completed successfully.");
    } catch (error) {
      console.error("Error during decryption:", error);
    }
  };

  // Effect to fetch files when section changes
  useEffect(() => {
    if (activeSection === "analyze") {
      fetchAvailableFiles("data");
    } else if (activeSection === "decrypt") {
      fetchAvailableFiles("analysis");
    }
  }, [activeSection]);

  return (
    <div className="App">
      <h1>CKKS-based Data Analysis</h1>

      {/* Navigation */}
      <nav>
        <button onClick={() => setActiveSection("upload")}>Upload and Encrypt</button>
        <button onClick={() => setActiveSection("analyze")}>Analyze</button>
        <button onClick={() => setActiveSection("decrypt")}>Decrypt</button>
      </nav>

      {/* Upload and Encrypt Section */}
      {activeSection === "upload" && (
        <div>
          <h2>Upload and Encrypt</h2>
          <button onClick={generateKeys}>Generate Keys</button>
          <div>
            <h3>Public Key:</h3>
            <center>
          <div style={{ maxWidth: '500px', maxHeight: '200px', overflow: 'auto', border: '1px solid #ccc', padding: '5px' }}>
            <pre style={{ whiteSpace: 'pre-wrap', wordWrap: 'break-word' }}>p0: {publicKey.p0}</pre>
            <pre style={{ whiteSpace: 'pre-wrap', wordWrap: 'break-word' }}>p1: {publicKey.p1}</pre>
        </div></center>
            <h3>Secret Key:</h3>
            <pre>{secretKey}</pre>
          </div>

          <input type="file" onChange={handleFileUpload} />
          <button onClick={uploadAndEncrypt}>Upload and Encrypt</button>
        </div>
      )}

      {/* Analyze Section */}
      {activeSection === "analyze" && (
        <div>
          <h2>Analyze Encrypted Data</h2>
          <select onChange={(e) => setFile(e.target.value)}>
            <option value="">Select a file</option>
            {availableFiles.map((filename, index) => (
              <option key={index} value={filename}>{filename}</option>
            ))}
          </select>
          <button onClick={analyzeFile}>Analyze File</button>
          <h3>Encrypted Coefficients:</h3>
          <pre>{JSON.stringify(encryptedData, null, 2)}</pre>
        </div>
      )}

      {/* Decrypt Section */}
      {activeSection === "decrypt" && (
        <div>
          <h2>Decrypt Analysis Result</h2>
          <select onChange={(e) => setFile(e.target.value)}>
            <option value="">Select a file</option>
            {availableFiles.map((filename, index) => (
              <option key={index} value={filename}>{filename}</option>
            ))}
          </select>
          <input 
            type="text" 
            placeholder="Enter Secret Key" 
            value={secretKey} 
            onChange={(e) => setSecretKey(e.target.value)} 
          />
          <button onClick={decryptData}>Decrypt Results</button>

          {/* Download Link for Decrypted Data */}
          {decryptedData && (
            <>
              <h3>Decrypted Analysis Result:</h3>
              <pre>{JSON.stringify(decryptedData, null, 2)}</pre>

              {/* Provide download option */}
              {/* Assuming decrypted data is saved in the backend */}
              <a href={`http://localhost:8080/download/${decryptedFileName}`} download>
                Download Decrypted Data
              </a>
            </>
          )}
        </div>
      )}
    </div>
  );
}

export default App;