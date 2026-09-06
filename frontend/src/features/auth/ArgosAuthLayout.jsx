import ArgosSky from "./ArgosSky.jsx";
import "./argos-auth.css";

const ArgosAuthLayout = ({ title, subtitle, children }) => (
  <div className="argos-auth">
    <ArgosSky />

    <div className="argos-auth__brand">
      <h1 className="argos-auth__wordmark">ARGOS</h1>
      <p className="argos-auth__motto">centum luminibus cinctum caput</p>
      <div className="argos-auth__rule" />
      <p className="argos-auth__tagline">Threat &amp; Vulnerability Management</p>
    </div>

    <div className="argos-auth__card">
      <p className="argos-auth__office">
        Oficina de Ciberseguridad Corporativa
        <br />
        Corporate Bureau of Cybersecurity
      </p>
      <h2 className="argos-auth__title">{title}</h2>
      {subtitle ? <p className="argos-auth__subtitle">{subtitle}</p> : null}
      {children}
      <p className="argos-auth__note">Uso exclusivo autorizado</p>
    </div>

    <div className="argos-auth__footer">
      <p className="argos-auth__footer-text">
        Desarrollado por la Oficina de Ciberseguridad Corporativa
      </p>
      <span className="argos-auth__seidor">
        SEIDOR<span className="argos-auth__seidor-dot" />
      </span>
    </div>
  </div>
);

export default ArgosAuthLayout;

export const ARGOS_AUTH_COPY = {
  login: {
    title: "Inicia sesión",
    subtitle: "Accede con tu cuenta corporativa autorizada.",
  },
  "mfa-enroll": {
    title: "Activa tu MFA",
    subtitle: "Registra tu segundo factor para completar el acceso.",
  },
  mfa: {
    title: "Verificación MFA",
    subtitle: "Introduce el código de tu autenticador.",
  },
  forgot: {
    title: "Recuperar acceso",
    subtitle: "Te enviaremos un enlace de recuperación.",
  },
  reset: {
    title: "Nueva credencial",
    subtitle: "Define una contraseña para tu cuenta.",
  },
};
