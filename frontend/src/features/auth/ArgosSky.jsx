import { useMemo } from "react";

// Generador determinista (LCG) para que el cielo no cambie en cada render.
const makeStars = (count, seed) => {
  let state = seed;
  const next = () => {
    state = (state * 1664525 + 1013904223) % 4294967296;
    return state / 4294967296;
  };
  return Array.from({ length: count }, (_, i) => ({
    id: i,
    x: Math.round(next() * 1600),
    y: Math.round(next() * 1000),
    r: 0.4 + next() * 1.3,
    o: 0.15 + next() * 0.6,
    d: (next() * 8).toFixed(1),
  }));
};

// Silueta del manto: se estrecha en los hombros y se abre en el bajo.
const TOP_Y = 270;
const HEM_Y = 900;
const edgeLeft = (y) => 340 - 70 * ((y - TOP_Y) / (HEM_Y - TOP_Y));
const edgeRight = (y) => 520 + 70 * ((y - TOP_Y) / (HEM_Y - TOP_Y));

// Los cien ojos de Argos Panoptes, repartidos dentro del manto.
const buildEyes = () => {
  const eyes = [];
  for (let row = 0; row < 9; row += 1) {
    const y = 336 + row * 62;
    const l = edgeLeft(y) + 36;
    const r = edgeRight(y) - 36;
    const count = row % 2 === 0 ? 4 : 3;
    for (let i = 0; i < count; i += 1) {
      eyes.push([Math.round(l + ((r - l) * i) / (count - 1)), y]);
    }
  }
  return eyes;
};

// Plumas del pavo real: los ojos que Hera trasladó a su cola.
const FEATHERS = [-58, -42, -26, -10, 6, 22, 38, 54];
const featherPoint = (deg) => [
  1010 + Math.sin((deg * Math.PI) / 180) * 190,
  760 - Math.cos((deg * Math.PI) / 180) * 190,
];

const ArgosSky = () => {
  const stars = useMemo(() => makeStars(300, 20260906), []);
  const eyes = useMemo(buildEyes, []);

  return (
    <svg
      className="argos-auth__sky"
      viewBox="0 0 1600 1000"
      preserveAspectRatio="xMidYMid slice"
      aria-hidden="true"
      focusable="false"
    >
      <defs>
        <radialGradient id="argosGlow" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#7fb0ff" stopOpacity="0.32" />
          <stop offset="100%" stopColor="#7fb0ff" stopOpacity="0" />
        </radialGradient>
        <linearGradient id="argosLine" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#cfe0ff" stopOpacity="0.75" />
          <stop offset="100%" stopColor="#5f8ddb" stopOpacity="0.32" />
        </linearGradient>
      </defs>

      {/* Campo de estrellas */}
      <g fill="#dbe9ff">
        {stars.map((s) => (
          <circle
            key={s.id}
            cx={s.x}
            cy={s.y}
            r={s.r}
            opacity={s.o}
            className={s.id % 9 === 0 ? "argos-node" : undefined}
            style={s.id % 9 === 0 ? { animationDelay: `${s.d}s` } : undefined}
          />
        ))}
      </g>

      <circle cx="470" cy="560" r="390" fill="url(#argosGlow)" />

      {/* ARGOS PANOPTES — el guardián que nunca cierra todos los ojos */}
      <g transform="translate(130 150) scale(0.84)">
        <g
          stroke="url(#argosLine)"
          strokeWidth="1.2"
          fill="none"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          {/* Cabeza y diadema */}
          <circle cx="430" cy="172" r="48" />
          <path d="M386 146 Q430 112 474 146" />
          <path d="M398 130 L394 106 M430 122 L430 96 M462 130 L466 106" opacity="0.7" />
          <path d="M418 220 L418 258 M442 220 L442 258" />

          {/* Hombros y brazos */}
          <path d="M340 270 Q430 244 520 270" />
          <path d="M340 270 L250 400 L232 560" />
          <path d="M520 270 L612 400 L628 560" />

          {/* Manto */}
          <path d="M340 270 L270 900 M520 270 L590 900" />
          <path d="M430 256 L430 900" opacity="0.55" />
          <path d="M317 480 L543 480" opacity="0.4" />
          <path d="M293 690 L567 690" opacity="0.4" />
          <path d="M270 900 Q430 946 590 900" />

          {/* Cayado del vigía */}
          <path d="M712 190 L712 906" opacity="0.5" />
          <path d="M712 190 q48 -8 42 42 q-5 36 -42 26" opacity="0.5" />
        </g>

        {/* Los ojos: nunca duermen todos a la vez */}
        <g>
          {eyes.map(([x, y], i) => (
            <g
              key={`eye-${x}-${y}`}
              className="argos-eye"
              style={{ animationDelay: `${(i * 0.47).toFixed(2)}s` }}
            >
              <path
                d={`M${x - 12} ${y} q12 -10 24 0 q-12 10 -24 0 Z`}
                fill="none"
                stroke="#bcd4ff"
                strokeWidth="1.1"
                opacity="0.8"
              />
              <circle cx={x} cy={y} r="2.6" fill="#e6f0ff" opacity="0.9" />
            </g>
          ))}
        </g>

        {/* Nodos de articulación */}
        <g fill="#e8f1ff">
          {[[430, 172], [430, 258], [340, 270], [520, 270], [250, 400], [612, 400],
            [232, 560], [628, 560], [270, 900], [590, 900], [430, 900]].map(([x, y]) => (
            <circle key={`node-${x}-${y}`} cx={x} cy={y} r="3.6" opacity="0.85" />
          ))}
        </g>
      </g>

      {/* Pavo real: los cien ojos tras la vigilia */}
      <g transform="translate(173 173) scale(0.72)">
        <g stroke="url(#argosLine)" strokeWidth="1.4" fill="none" strokeLinecap="round">
          <path d="M980 800 q-26 -34 -6 -66 q22 -34 58 -18" />
          <path d="M1032 716 l16 -20 l22 12" />
          <path d="M980 800 L962 900 M980 800 L1012 900" />
          {FEATHERS.map((deg) => {
            const [x, y] = featherPoint(deg);
            return (
              <path
                key={`f-${deg}`}
                d={`M1000 790 Q${(1000 + x) / 2 + deg * 0.6} ${(790 + y) / 2} ${x} ${y}`}
                opacity="0.42"
              />
            );
          })}
        </g>
        {FEATHERS.map((deg, i) => {
          const [x, y] = featherPoint(deg);
          return (
            <g key={`fe-${deg}`} className="argos-eye" style={{ animationDelay: `${(i * 0.83).toFixed(2)}s` }}>
              <circle cx={x} cy={y} r="11" fill="none" stroke="#9dc0ff" strokeWidth="1.4" opacity="0.55" />
              <circle cx={x} cy={y} r="3.6" fill="#e6f0ff" opacity="0.85" />
            </g>
          );
        })}
      </g>

      {/* Emblema de vigilancia */}
      <g transform="translate(-240 -14)" stroke="#5f92e8" fill="none" opacity="0.5">
        <path d="M1210 140 L1268 174 L1268 242 L1210 276 L1152 242 L1152 174 Z" strokeWidth="1.3" />
        <path d="M1210 168 L1246 189 L1246 231 L1210 252 L1174 231 L1174 189 Z" strokeWidth="0.8" opacity="0.6" />
        <path d="M1268 208 L1420 118" strokeWidth="0.7" opacity="0.35" />
        <path d="M1152 242 L1052 330" strokeWidth="0.7" opacity="0.35" />
        <path d="M1191 208 q19 -16 38 0 q-19 16 -38 0 Z" strokeWidth="1.1" />
      </g>
      <circle cx="970" cy="194" r="3" fill="#cfe2ff" opacity="0.9" />
    </svg>
  );
};

export default ArgosSky;
