import { Link } from "react-router";

// Se muestra cuando la API financiera responde 403: el usuario SÍ tiene sesión, pero su rol
// (Administrador o Auditor) no opera cuentas. Es separación de funciones, no un fallo de sesión.
export default function ClientOnly() {
  return (
    <section className="finance-page">
      <p className="finance-eyebrow">Separación de funciones · 403</p>
      <h1>Esta sección es solo para Clientes</h1>
      <div className="finance-notice" role="note">
        <strong>Tu sesión sigue activa.</strong>
        <span>
          Los Administradores y Auditores no tienen cuentas ni pueden mover dinero: así quien aprueba una
          transferencia nunca puede ser quien la crea (control antifraude). El servidor lo bloquea con HTTP 403 y lo
          registra en la auditoría.
        </span>
      </div>
      <p>Lo que sí puedes hacer con tu rol:</p>
      <div className="hub__grid">
        <Link className="hub__tile" to="/admin/finance/approvals">
          <span aria-hidden="true">✅</span>
          <strong>Aprobaciones</strong>
          <small>Transferencias retenidas</small>
        </Link>
        <Link className="hub__tile" to="/">
          <span aria-hidden="true">🏠</span>
          <strong>Volver al inicio</strong>
          <small>Tu panel de control</small>
        </Link>
      </div>
    </section>
  );
}
