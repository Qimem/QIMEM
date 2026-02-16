import { useState } from "react";

export default function Dashboard() {
  const [health, setHealth] = useState("unknown");
  const [msg, setMsg] = useState("");
  const [key, setKey] = useState("");
  const [encrypted, setEncrypted] = useState("");
  const [decrypted, setDecrypted] = useState("");

  const checkHealth = async () => {
    const res = await fetch("/health");
    setHealth(await res.text());
  };

  const encrypt = async () => {
    const res = await fetch("/encrypt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: msg, key })
    });
    const data = await res.json();
    setEncrypted(data.encrypted ?? "");
  };

  const decrypt = async () => {
    const res = await fetch("/decrypt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: encrypted, key })
    });
    const data = await res.json();
    setDecrypted(data.decrypted ?? "");
  };

  return (
    <div className="bg-black text-white min-h-screen p-6 font-mono">
      <h1 className="text-3xl font-bold mb-4">QIMEM Dashboard</h1>
      <button onClick={checkHealth} className="mb-2 px-4 py-2 bg-gray-900 hover:bg-gray-700">
        Check Health
      </button>
      <p>Health: {health}</p>
      <input
        placeholder="Message"
        value={msg}
        onChange={(e) => setMsg(e.target.value)}
        className="my-2 p-2 bg-gray-800 block w-full max-w-xl"
      />
      <input
        placeholder="Key"
        value={key}
        onChange={(e) => setKey(e.target.value)}
        className="my-2 p-2 bg-gray-800 block w-full max-w-xl"
      />
      <button onClick={encrypt} className="px-4 py-2 bg-gray-900 hover:bg-gray-700 mr-2">
        Encrypt
      </button>
      <button onClick={decrypt} className="px-4 py-2 bg-gray-900 hover:bg-gray-700">
        Decrypt
      </button>
      <p className="mt-3 break-all">Encrypted: {encrypted}</p>
      <p className="mt-1">Decrypted: {decrypted}</p>
    </div>
  );
}
