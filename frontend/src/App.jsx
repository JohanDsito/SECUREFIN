import { Route, Routes } from "react-router";
import Header from "./components/Header.jsx";
import SecurityCenter from "./pages/SecurityCenter.jsx";
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
      <Header />
      <main>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/seguridad" element={<SecurityCenter />} />
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
      <footer className="app-footer">
        <span>SecureFin · Proyecto académico de ciberseguridad. Saldos y operaciones 100 % ficticios.</span>
        <span>TLS 1.2/1.3 · Argon2id · AES-256-GCM · MFA TOTP · Rate limiting</span>
      </footer>
    </div>
  );
}
