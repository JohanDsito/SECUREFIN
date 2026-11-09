import { Link, Route, Routes } from "react-router";
import Register from "./pages/Register.jsx";
import Login from "./pages/Login.jsx";
import Home from "./pages/Home.jsx";
import Profile from "./pages/Profile.jsx";
import Sessions from "./pages/Sessions.jsx";

// Enrutador del SPA (T045). Las rutas /activate, /forgot-password y /reset se añaden en US4 y US7
// con exactamente esos nombres (contracts/iam-api.md §6).
export default function App() {
  return (
    <div className="app">
      <header>
        <strong>SecureFin Gateway</strong> · laboratorio académico (identidades ficticias)
        <nav>
          <Link to="/login">Iniciar sesión</Link> · <Link to="/register">Registrarse</Link>
        </nav>
      </header>
      <main>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/register" element={<Register />} />
          <Route path="/login" element={<Login />} />
          <Route path="/profile" element={<Profile />} />
          <Route path="/sessions" element={<Sessions />} />
          <Route path="*" element={<p>Página no encontrada.</p>} />
        </Routes>
      </main>
    </div>
  );
}
