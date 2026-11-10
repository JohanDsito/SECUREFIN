import { Link, Route, Routes } from "react-router";
import Register from "./pages/Register.jsx";
import Login from "./pages/Login.jsx";
import Home from "./pages/Home.jsx";
import Profile from "./pages/Profile.jsx";
import Sessions from "./pages/Sessions.jsx";
import MfaStep from "./pages/MfaStep.jsx";
import Enroll from "./pages/Enroll.jsx";
import Activate from "./pages/Activate.jsx";
import AdminUsers from "./pages/admin/Users.jsx";
import AdminMfaResets from "./pages/admin/MfaResets.jsx";
import FinanceDashboard from "./pages/finance/Dashboard.jsx";
import OpenAccount from "./pages/finance/OpenAccount.jsx";
import AccountDetail from "./pages/finance/AccountDetail.jsx";
import Transfer from "./pages/finance/Transfer.jsx";
import TransferResult from "./pages/finance/TransferResult.jsx";
import Activity from "./pages/finance/Activity.jsx";
import Approvals from "./pages/finance/admin/Approvals.jsx";

// Enrutador del SPA (T045). /activate llega con US4; /forgot-password y /reset, con US7, con
// exactamente esos nombres (contracts/iam-api.md §6).
export default function App() {
  return (
    <div className="app">
      <header>
        <Link className="brand" to="/" aria-label="SecureFin Gateway, inicio">
          <span className="brand-mark" aria-hidden="true">S</span>
          <span className="brand-copy">
            <strong>SecureFin <span>Gateway</span></strong>
            <small>Seguridad · Fintech simulada</small>
          </span>
        </Link>
        <nav aria-label="Navegación principal">
          <span className="environment-badge"><span aria-hidden="true" />Laboratorio académico</span>
          <Link className="nav-link" to="/login">Iniciar sesión</Link>
          <Link className="nav-cta" to="/register">Crear cuenta</Link>
        </nav>
      </header>
      <main>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/register" element={<Register />} />
          <Route path="/login" element={<Login />} />
          <Route path="/login/mfa" element={<MfaStep />} />
          <Route path="/login/enroll" element={<Enroll mode="login" />} />
          <Route path="/mfa/setup" element={<Enroll mode="self" />} />
          <Route path="/mfa/reconfigure" element={<Enroll mode="self" reconfigure />} />
          <Route path="/profile" element={<Profile />} />
          <Route path="/sessions" element={<Sessions />} />
          <Route path="/finance" element={<FinanceDashboard />} />
          <Route path="/finance/accounts/new" element={<OpenAccount />} />
          <Route path="/finance/accounts/:accountId" element={<AccountDetail />} />
          <Route path="/finance/transfer" element={<Transfer />} />
          <Route path="/finance/transfers/:transactionId" element={<TransferResult />} />
          <Route path="/finance/activity" element={<Activity />} />
          <Route path="/admin/finance/approvals" element={<Approvals />} />
          <Route path="/activate" element={<Activate />} />
          <Route path="/admin/users" element={<AdminUsers />} />
          <Route path="/admin/mfa-resets" element={<AdminMfaResets />} />
          <Route path="*" element={<p>Página no encontrada.</p>} />
        </Routes>
      </main>
    </div>
  );
}
