import './App.css';
import React, { useState } from "react";
import axios from "axios";

function App() {
  const [publicKey, setPublicKey] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [file, setFile] = useState(null);
  const [encryptedData, setEncryptedData] = useState(null);
  const [decryptedData, setDecryptedData] = useState(null);

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

  // Analyze encrypted data
  const analyzeFile = async () => {
    try {
      const response = await axios.post(`http://localhost:8080/analyze/${file.name}`, { secret_key: secretKey });
    } catch (error) {
      console.error("Error during analysis:", error);
    }
  };

  // Decrypt analysis results
  const decryptData = async () => {
    try {
      const response = await axios.post(`http://localhost:8080/decrypt/${file.name}`, { secret_key: secretKey });
    } catch (error) {
      console.error("Error during decryption:", error);
    }
  };

  return (
    <div className="App">
      <h1>CKKS-based Linear Regression</h1>

      {/* Key Generation */}
      <button onClick={generateKeys}>Generate Keys</button>
      <div>
        <h3>Public Key:</h3>
        <pre>p0: {publicKey.p0}</pre>
        <pre>p1: {publicKey.p1}</pre>
        <h3>Secret Key:</h3>
        <pre>{secretKey}</pre>
      </div>

      {/* File Upload */}
      <input type="file" onChange={handleFileUpload} />
      <button onClick={uploadAndEncrypt}>Upload and Encrypt</button>

      {/* Analysis */}
      <button onClick={analyzeFile}>Analyze Encrypted Data</button>
      <h3>Encrypted Coefficients:</h3>
      <pre>{JSON.stringify(encryptedData, null, 2)}</pre>

      {/* Decryption */}
      <button onClick={decryptData}>Decrypt Results</button>
      <h3>Decrypted Analysis Result:</h3>
      <pre>{JSON.stringify(decryptedData, null, 2)}</pre>
    </div>
  );
}

export default App;
