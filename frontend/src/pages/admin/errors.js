// Mensajes de los errores de la API de administración (contrato §4). Nunca se muestran detalles
// internos: solo el código de negocio traducido o un mensaje genérico.
const MESSAGES = {
  auth_failed: "Tu sesión no es válida o ha caducado. Vuelve a iniciar sesión.",
  forbidden: "No tienes permiso para realizar esta acción.",
  csrf_failed: "La página ha caducado. Recárgala e inténtalo de nuevo.",
  self_action_forbidden: "No puedes realizar esta acción sobre tu propia cuenta.",
  not_case_owner: "Solo el Administrador que abrió el caso puede autorizarlo.",
  last_admin: "No se puede degradar ni desactivar al último Administrador activo.",
  invalid_state: "El estado actual de la cuenta no permite esta operación.",
  user_exists: "Ya existe una cuenta con ese correo.",
  case_conflict: "El caso ha caducado o ya está resuelto.",
  verification_failed: "El código del titular o tu código TOTP no son válidos. Al tercer fallo el caso se cancela.",
  not_found: "No se encontró el recurso.",
  validation_error: "Revisa los datos introducidos.",
  throttled: "Demasiadas solicitudes. Inténtalo más tarde.",
};

export function adminErrorMessage(error) {
  return MESSAGES[error?.code] ?? "No fue posible completar la operación.";
}

// Lista plana de mensajes de validación por campo (400 validation_error), si los hay.
export function fieldMessages(error) {
  if (!error?.fields || typeof error.fields !== "object") return [];
  return Object.entries(error.fields).flatMap(([field, msgs]) =>
    (Array.isArray(msgs) ? msgs : [msgs]).map((m) => ({ key: `${field}-${m}`, text: String(m) })),
  );
}

export function needsLogin(error) {
  return error?.status === 401;
}
