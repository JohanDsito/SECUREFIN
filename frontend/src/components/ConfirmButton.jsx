import { useState } from "react";

// Confirmación en dos pasos, en línea y accesible (T093). Sustituye a window.confirm: no bloquea la
// página y el texto de la pregunta queda asociado al grupo de botones. Es solo ayuda de interfaz:
// la autorización y las reglas de negocio las aplica el servidor.
export default function ConfirmButton({
  label,
  question,
  confirmLabel = "Confirmar",
  dismissLabel = "Cancelar",
  onConfirm,
  disabled = false,
}) {
  const [asking, setAsking] = useState(false);

  if (!asking) {
    return (
      <button type="button" disabled={disabled} onClick={() => setAsking(true)}>
        {label}
      </button>
    );
  }
  return (
    <span role="group" aria-label={question}>
      <span>{question} </span>
      <button
        type="button"
        disabled={disabled}
        onClick={async () => {
          setAsking(false);
          await onConfirm();
        }}
      >
        {confirmLabel}
      </button>{" "}
      <button type="button" onClick={() => setAsking(false)}>
        {dismissLabel}
      </button>
    </span>
  );
}
