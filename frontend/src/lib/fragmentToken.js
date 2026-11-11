// Lectura segura del token del fragmento de la URL (T045; R7).
// 1. Se lee de location.hash en el primer render.
// 2. Se elimina de inmediato con history.replaceState (no queda en la barra ni en el historial).
// 3. Se devuelve solo para guardarlo en el estado del componente (memoria): nunca en localStorage,
//    sessionStorage, IndexedDB, cookies ni en la URL. Nunca se registra en consola.
export function takeFragmentToken() {
  const hash = window.location.hash || "";
  const params = new URLSearchParams(hash.startsWith("#") ? hash.slice(1) : hash);
  const token = params.get("token");
  if (hash) {
    window.history.replaceState(null, "", window.location.pathname + window.location.search);
  }
  return token && /^[A-Za-z0-9_-]{20,128}$/.test(token) ? token : null;
}
