import { invoke } from "@tauri-apps/api/core";
import { FormEvent, useState } from "react";

function App() {
  const [name, setName] = useState("");
  const [message, setMessage] = useState("");

  async function greet(event: FormEvent) {
    event.preventDefault();
    setMessage(await invoke<string>("greet", { name }));
  }

  return (
    <main className="container">
      <h1>Dental Clinic DMS</h1>
      <form className="row" onSubmit={greet}>
        <input
          value={name}
          onChange={(event) => setName(event.target.value)}
          placeholder="Enter a name..."
        />
        <button type="submit">Greet</button>
      </form>
      <p>{message}</p>
    </main>
  );
}

export default App;
