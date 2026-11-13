import { useState } from "react";
import { Link, useNavigate } from "react-router";
import { ApiError, api } from "../../api/client.js";

export default function OpenAccount() {
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function onSubmit(event) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true);
    setError("");
    try {
      await api("/finance/accounts", {
        method: "POST",
        body: { type: form.get("type"), currency: form.get("currency") },
      });
      navigate("/finance");
    } catch (requestError) {
      setError(
        requestError instanceof ApiError && requestError.status === 401
          ? "Tu sesión ya no está activa. Inicia sesión nuevamente."
          : requestError instanceof ApiError && requestError.status === 403
            ? "Tu rol no puede abrir cuentas: solo los Clientes operan dinero (separación de funciones)."
            : "No se pudo abrir la cuenta. Revisa los datos e inténtalo otra vez.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="finance-page finance-open-account">
      <Link to="/finance" className="finance-back-link">← Volver al panel</Link>
      <p className="finance-eyebrow">Cuentas de demostración</p>
      <h1>Abrir una cuenta</h1>
      <p>Elige una moneda y un tipo. La cuenta se crea activa con saldo inicial cero.</p>
      <div className="finance-notice" role="note">
        <strong>Solo simulación</strong>
        <span>No se conecta a bancos ni permite ingresar dinero real.</span>
      </div>
      <form className="finance-account-form" onSubmit={onSubmit}>
        <label htmlFor="account-currency">Moneda</label>
        <select id="account-currency" name="currency" defaultValue="COP">
          <option value="COP">COP · Peso colombiano</option>
          <option value="USD">USD · Dólar estadounidense</option>
        </select>
        <label htmlFor="account-type">Tipo de cuenta</label>
        <select id="account-type" name="type" defaultValue="savings">
          <option value="savings">Ahorros</option>
          <option value="checking">Corriente</option>
        </select>
        <p className="finance-form-hint">Saldo inicial: 0. No se puede modificar desde el formulario.</p>
        {error && <p role="alert">{error}</p>}
        <button type="submit" disabled={busy}>{busy ? "Abriendo…" : "Abrir cuenta de demostración"}</button>
      </form>
    </section>
  );
}
