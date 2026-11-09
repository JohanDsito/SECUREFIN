import { useState } from "react";

// Códigos de recuperación (T080; R6; FR-028). Se muestran UNA sola vez: viven solo en la memoria del
// componente, nunca en localStorage, sessionStorage, cookies ni la URL. La descarga .txt la genera el
// propio navegador con un Blob; no pasa por el servidor.
const format = (code) => code.match(/.{1,4}/g).join("-");

export default function RecoveryCodes({ codes, onDone }) {
  const [saved, setSaved] = useState(false);
  const [message, setMessage] = useState(null);
  const text = codes.map(format).join("\n");

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setMessage("Códigos copiados al portapapeles.");
    } catch {
      setMessage("No se pudo copiar; selecciónalos y cópialos manualmente.");
    }
  }

  function download() {
    const header = "SecureFin Gateway — códigos de recuperación (cada uno sirve una sola vez)\n\n";
    const url = URL.createObjectURL(new Blob([header + text + "\n"], { type: "text/plain;charset=utf-8" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = "securefin-codigos-recuperacion.txt";
    link.click();
    URL.revokeObjectURL(url);
  }

  return (
    <section aria-labelledby="recovery-title">
      <h2 id="recovery-title">Tus códigos de recuperación</h2>
      <p>
        Guárdalos en un lugar seguro, por ejemplo tu gestor de contraseñas. Cada código sirve una sola vez si pierdes
        tu aplicación autenticadora. <strong>No se volverán a mostrar.</strong>
      </p>
      <ol className="recovery-codes">
        {codes.map((code) => (
          <li key={code}>
            <code>{format(code)}</code>
          </li>
        ))}
      </ol>
      <p>
        <button type="button" onClick={copy}>Copiar</button>{" "}
        <button type="button" onClick={download}>Descargar .txt</button>
      </p>
      {message && <p role="status">{message}</p>}
      <label>
        <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} /> He guardado mis códigos
      </label>
      <p>
        <button type="button" disabled={!saved} onClick={onDone}>Continuar</button>
      </p>
    </section>
  );
}
