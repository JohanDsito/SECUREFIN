import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router";
import { api } from "../api/client.js";

// Área personal (T056). Si no hay sesión `full`, invita a iniciar sesión.
export default function Home() {
  const navigate = useNavigate();
  const [state, setState] = useState({ loading: true, data: null });

  useEffect(() => {
    api("/auth/session")
      .then((data) => setState({ loading: false, data }))
      .catch(() => setState({ loading: false, data: null }));
  }, []);

  async function logout() {
    await api("/auth/logout", { method: "POST" }).catch(() => null);
    setState({ loading: false, data: null });
    navigate("/login");
  }

  if (state.loading) return <p>Cargando…</p>;
  if (!state.data) {
    return (
      <p>
        No has iniciado sesión. <Link to="/login">Inicia sesión</Link>
      </p>
    );
  }
  const { user, session } = state.data;
  return (
    <section>
      <h1>Hola, {user.name}</h1>
      <p>Rol: {user.role}</p>
      <p>La sesión caduca por inactividad a las {new Date(session.idle_expires_at).toLocaleTimeString()}.</p>
      <button type="button" onClick={logout}>Cerrar sesión</button>
    </section>
  );
}
