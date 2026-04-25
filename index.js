require("dotenv").config();

const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const pool = require("./db");

const app = express();

const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:5174",
  "https://bpgroup-panel.vercel.app",
  "https://panel.bpgroup.mx",
  process.env.FRONTEND_URL
].filter(Boolean);

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);

      const isAllowed =
        allowedOrigins.includes(origin) || origin.endsWith(".vercel.app");

      if (isAllowed) return callback(null, true);

      return callback(new Error(`No permitido por CORS: ${origin}`));
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true
  })
);

app.options(/.*/, cors());
app.use(express.json());

const uploadsDir = path.join(__dirname, "uploads");

if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

app.use("/uploads", express.static(uploadsDir));

/* =========================
   MULTER VEHÍCULOS
========================= */

const assetStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname || "").toLowerCase() || ".jpg";
    cb(null, `asset_${req.params.id}_${Date.now()}${ext}`);
  }
});

const upload = multer({ storage: assetStorage });

/* =========================
   MULTER HUERTAS
========================= */

const farmStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    const farmUploadsDir = path.join(__dirname, "uploads", "farms");

    if (!fs.existsSync(farmUploadsDir)) {
      fs.mkdirSync(farmUploadsDir, { recursive: true });
    }

    cb(null, farmUploadsDir);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname || "").toLowerCase();
    const cleanName = file.originalname
      .replace(ext, "")
      .replace(/[^a-zA-Z0-9-_]/g, "_");

    cb(null, `farm_${req.params.id}_${Date.now()}_${cleanName}${ext}`);
  }
});

const farmUpload = multer({ storage: farmStorage });

/* =========================
   MULTER PERSONAL
========================= */

const staffStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    const staffUploadsDir = path.join(__dirname, "uploads", "staff");

    if (!fs.existsSync(staffUploadsDir)) {
      fs.mkdirSync(staffUploadsDir, { recursive: true });
    }

    cb(null, staffUploadsDir);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname || "").toLowerCase();
    const cleanName = file.originalname
      .replace(ext, "")
      .replace(/[^a-zA-Z0-9-_]/g, "_");

    cb(null, `staff_${req.params.id}_${Date.now()}_${cleanName}${ext}`);
  }
});

const staffUpload = multer({ storage: staffStorage });

/* =========================
   MIDDLEWARES
========================= */

function authMiddleware(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({ error: "Token no proporcionado" });
    }

    const parts = authHeader.split(" ");

    if (parts.length !== 2 || parts[0] !== "Bearer") {
      return res.status(401).json({ error: "Formato de token inválido" });
    }

    const token = parts[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Token inválido o expirado" });
  }
}

function allowRoles(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res
        .status(403)
        .json({ error: "No tienes permiso para esta acción" });
    }

    next();
  };
}

function adminOnly(req, res, next) {
  return allowRoles("admin")(req, res, next);
}

function canSeeMoney(role) {
  return role === "admin" || role === "finanzas";
}

/* =========================
   MAPAS CÓDIGOS VEHÍCULOS
========================= */

const TYPE_MAP = {
  LIGERO: "LIG",
  PESADO: "PES",
  MOTO: "MOT",
  "ATV/UTV": "ATV",
  ACCESORIO: "ACC",
  OTROS: "OTT"
};

const FUNCTION_MAP = {
  AGRICOLA: "AGR",
  CONSTRUCCION: "CON",
  TRANSPORTE: "TRA",
  UTILITARIO: "UTI",
  OTROS: "OTR"
};

function buildCode(type, assetFunction, codeNumber) {
  const typeAbbr = TYPE_MAP[type];
  const functionAbbr = FUNCTION_MAP[assetFunction];

  if (!typeAbbr || !functionAbbr || !codeNumber) {
    return null;
  }

  return `${typeAbbr}-${functionAbbr}-${String(codeNumber).toUpperCase()}`;
}

function getCutYearMonth(cutDate) {
  const date = new Date(`${cutDate}T00:00:00`);

  if (Number.isNaN(date.getTime())) {
    return null;
  }

  return {
    year: date.getFullYear(),
    month: date.getMonth() + 1
  };
}
function generateEmployeeCode(fullName, curp) {
  if (!fullName || !curp) return null;

  const namePart = fullName
    .split(" ")
    .slice(0, 2)
    .map(n => n.substring(0, 3).toUpperCase())
    .join("");

  const curpPart = curp.substring(0, 4).toUpperCase();

  return `${namePart}-${curpPart}-${Date.now().toString().slice(-4)}`;
}
/* =========================
   RUTAS BASE
========================= */

app.get("/", (req, res) => {
  res.send("API funcionando 🚀");
});

app.get("/test-db", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* =========================
   CREAR TABLAS
========================= */

app.get("/create-tables", async (req, res) => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(120) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role VARCHAR(30) NOT NULL DEFAULT 'viewer',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS assets (
        id SERIAL PRIMARY KEY,
        code VARCHAR(30) UNIQUE NOT NULL,
        type VARCHAR(30) NOT NULL,
        code_number VARCHAR(20) NOT NULL,
        brand VARCHAR(80),
        model VARCHAR(80),
        year INT,
        function TEXT,
        responsible VARCHAR(120),
        observation TEXT,
        numero_asignado VARCHAR(50),
        image_url TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS farms (
        id SERIAL PRIMARY KEY,
        code VARCHAR(20) UNIQUE,
        name VARCHAR(120) NOT NULL,
        estado VARCHAR(120),
        region VARCHAR(120),
        sector VARCHAR(120),
        coordenadas TEXT,
        maps_link TEXT,
        hectareas NUMERIC(12,2),
        numero_terrenos INT,
        tipo_suelos TEXT,
        variedad_banano TEXT,
        edad_plantacion TEXT,
        sistema_riego TEXT,
        fuente_agua TEXT,
        bomba_agua TEXT,
        prop_medidor_elec TEXT,
        empacadora TEXT,
        a_favor_de TEXT,
        produccion_est_mensual NUMERIC(12,2),
        produccion_est_anual NUMERIC(12,2),
        encargado TEXT,
        telefono_encargado TEXT,
        empresa_compradora TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS farm_files (
        id SERIAL PRIMARY KEY,
        farm_id INT REFERENCES farms(id) ON DELETE CASCADE,
        file_type VARCHAR(20) NOT NULL,
        file_name TEXT NOT NULL,
        file_url TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS farm_cuts (
        id SERIAL PRIMARY KEY,
        farm_id INT REFERENCES farms(id) ON DELETE CASCADE,
        cut_date DATE NOT NULL,
        cut_year INT NOT NULL,
        cut_month INT NOT NULL,
        color VARCHAR(50),
        boxes_produced NUMERIC(12,2) NOT NULL DEFAULT 0,
        price_per_box NUMERIC(12,2),
        buyer_company TEXT,
        box_design TEXT,
        gross_income NUMERIC(12,2),
        observation TEXT,
        status VARCHAR(30) NOT NULL DEFAULT 'PENDIENTE_FINANZAS',
        created_by INTEGER,
        approved_by INTEGER,
        approved_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS staff (
        id SERIAL PRIMARY KEY,
        full_name VARCHAR(120) NOT NULL,
        position VARCHAR(100),
        phone VARCHAR(30),
        farm_id INT REFERENCES farms(id) ON DELETE SET NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
    CREATE TABLE IF NOT EXISTS staff_files (
      id SERIAL PRIMARY KEY,
      staff_id INT REFERENCES staff(id) ON DELETE CASCADE,
      file_type VARCHAR(30) NOT NULL,
      file_name TEXT NOT NULL,
      file_url TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    res.send("Tablas creadas correctamente");
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* =========================
   FIX SCHEMAS / MIGRACIONES
========================= */

app.get("/fix-assets-schema", async (req, res) => {
  try {
    await pool.query(`ALTER TABLE assets ADD COLUMN IF NOT EXISTS observation TEXT;`);
    await pool.query(`ALTER TABLE assets ADD COLUMN IF NOT EXISTS numero_asignado VARCHAR(50);`);
    await pool.query(`ALTER TABLE assets ADD COLUMN IF NOT EXISTS code_number VARCHAR(20);`);
    await pool.query(`ALTER TABLE assets ADD COLUMN IF NOT EXISTS image_url TEXT;`);

    res.send("Schema de assets actualizado correctamente");
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/fix-farms-schema", async (req, res) => {
  try {
    await pool.query(`ALTER TABLE farms ADD COLUMN IF NOT EXISTS code VARCHAR(20);`);
    await pool.query(`ALTER TABLE farms ADD COLUMN IF NOT EXISTS estado VARCHAR(120);`);
    await pool.query(`ALTER TABLE farms ADD COLUMN IF NOT EXISTS region VARCHAR(120);`);
    await pool.query(`ALTER TABLE farms ADD COLUMN IF NOT EXISTS sector VARCHAR(120);`);
    await pool.query(`ALTER TABLE farms ADD COLUMN IF NOT EXISTS coordenadas TEXT;`);
    await pool.query(`ALTER TABLE farms ADD COLUMN IF NOT EXISTS maps_link TEXT;`);
    await pool.query(`ALTER TABLE farms ADD COLUMN IF NOT EXISTS hectareas NUMERIC(12,2);`);
    await pool.query(`ALTER TABLE farms ADD COLUMN IF NOT EXISTS numero_terrenos INT;`);
    await pool.query(`ALTER TABLE farms ADD COLUMN IF NOT EXISTS tipo_suelos TEXT;`);
    await pool.query(`ALTER TABLE farms ADD COLUMN IF NOT EXISTS variedad_banano TEXT;`);
    await pool.query(`ALTER TABLE farms ADD COLUMN IF NOT EXISTS edad_plantacion TEXT;`);
    await pool.query(`ALTER TABLE farms ADD COLUMN IF NOT EXISTS sistema_riego TEXT;`);
    await pool.query(`ALTER TABLE farms ADD COLUMN IF NOT EXISTS fuente_agua TEXT;`);
    await pool.query(`ALTER TABLE farms ADD COLUMN IF NOT EXISTS bomba_agua TEXT;`);
    await pool.query(`ALTER TABLE farms ADD COLUMN IF NOT EXISTS prop_medidor_elec TEXT;`);
    await pool.query(`ALTER TABLE farms ADD COLUMN IF NOT EXISTS empacadora TEXT;`);
    await pool.query(`ALTER TABLE farms ADD COLUMN IF NOT EXISTS a_favor_de TEXT;`);
    await pool.query(`ALTER TABLE farms ADD COLUMN IF NOT EXISTS produccion_est_mensual NUMERIC(12,2);`);
    await pool.query(`ALTER TABLE farms ADD COLUMN IF NOT EXISTS produccion_est_anual NUMERIC(12,2);`);
    await pool.query(`ALTER TABLE farms ADD COLUMN IF NOT EXISTS encargado TEXT;`);
    await pool.query(`ALTER TABLE farms ADD COLUMN IF NOT EXISTS telefono_encargado TEXT;`);
    await pool.query(`ALTER TABLE farms ADD COLUMN IF NOT EXISTS empresa_compradora TEXT;`);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS farm_files (
        id SERIAL PRIMARY KEY,
        farm_id INT REFERENCES farms(id) ON DELETE CASCADE,
        file_type VARCHAR(20) NOT NULL,
        file_name TEXT NOT NULL,
        file_url TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS farm_cuts (
        id SERIAL PRIMARY KEY,
        farm_id INT REFERENCES farms(id) ON DELETE CASCADE,
        cut_date DATE NOT NULL,
        cut_year INT NOT NULL,
        cut_month INT NOT NULL,
        color VARCHAR(50),
        boxes_produced NUMERIC(12,2) NOT NULL DEFAULT 0,
        price_per_box NUMERIC(12,2),
        buyer_company TEXT,
        box_design TEXT,
        gross_income NUMERIC(12,2),
        observation TEXT,
        status VARCHAR(30) NOT NULL DEFAULT 'PENDIENTE_FINANZAS',
        created_by INTEGER,
        approved_by INTEGER,
        approved_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await runCutsMigrationQueries();

    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(30) NOT NULL DEFAULT 'viewer';`).catch(() => {});
    await pool.query(`ALTER TABLE farms ADD CONSTRAINT farms_code_unique UNIQUE (code);`).catch(() => {});

    res.send("Schema de huertas actualizado correctamente");
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

async function runCutsMigrationQueries() {
  await pool.query(`ALTER TABLE farm_cuts ADD COLUMN IF NOT EXISTS status VARCHAR(30) DEFAULT 'PENDIENTE_FINANZAS';`);
  await pool.query(`ALTER TABLE farm_cuts ADD COLUMN IF NOT EXISTS created_by INTEGER;`);
  await pool.query(`ALTER TABLE farm_cuts ADD COLUMN IF NOT EXISTS approved_by INTEGER;`);
  await pool.query(`ALTER TABLE farm_cuts ADD COLUMN IF NOT EXISTS approved_at TIMESTAMP;`);
  await pool.query(`ALTER TABLE farm_cuts ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;`);
  await pool.query(`ALTER TABLE farm_cuts ALTER COLUMN price_per_box DROP NOT NULL;`).catch(() => {});
  await pool.query(`ALTER TABLE farm_cuts ALTER COLUMN gross_income DROP NOT NULL;`).catch(() => {});
  await pool.query(`UPDATE farm_cuts SET status = 'PENDIENTE_FINANZAS' WHERE status IS NULL;`);
}

app.get("/migrate-cuts-flow", async (req, res) => {
  try {
    await runCutsMigrationQueries();
    res.send("Migración de cortes completada");
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* =========================
   AUTH / USUARIOS
========================= */

app.post("/create-admin", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: "name, email y password son obligatorios" });
    }

    const existingUser = await pool.query("SELECT id FROM users WHERE email = $1", [email]);

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: "Ese email ya existe" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `
      INSERT INTO users (name, email, password_hash, role)
      VALUES ($1, $2, $3, 'admin')
      RETURNING id, name, email, role, created_at
      `,
      [name, email, passwordHash]
    );

    res.status(201).json({ message: "Admin creado correctamente", user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/users", authMiddleware, allowRoles("admin"), async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const validRoles = ["admin", "agricola", "finanzas", "inventario", "viewer"];

    if (!name || !email || !password || !role) {
      return res.status(400).json({ error: "name, email, password y role son obligatorios" });
    }

    if (!validRoles.includes(role)) {
      return res.status(400).json({ error: "Rol inválido" });
    }

    const existingUser = await pool.query("SELECT id FROM users WHERE email = $1", [email]);

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: "Ese email ya existe" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `
      INSERT INTO users (name, email, password_hash, role)
      VALUES ($1, $2, $3, $4)
      RETURNING id, name, email, role, created_at
      `,
      [name, email, passwordHash, role]
    );

    res.status(201).json({ message: "Usuario creado correctamente", user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/users", authMiddleware, allowRoles("admin"), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, email, role, created_at
      FROM users
      ORDER BY id ASC
    `);

    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/users/:id/role", authMiddleware, allowRoles("admin"), async (req, res) => {
  try {
    const { role } = req.body;
    const validRoles = ["admin", "agricola", "finanzas", "inventario", "viewer"];

    if (!validRoles.includes(role)) {
      return res.status(400).json({ error: "Rol inválido" });
    }

    const result = await pool.query(
      `
      UPDATE users
      SET role = $1
      WHERE id = $2
      RETURNING id, name, email, role, created_at
      `,
      [role, req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    res.json({ message: "Rol actualizado correctamente", user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "email y password son obligatorios" });
    }

    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Credenciales inválidas" });
    }

    const user = result.rows[0];
    const passwordOk = await bcrypt.compare(password, user.password_hash);

    if (!passwordOk) {
      return res.status(401).json({ error: "Credenciales inválidas" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role, name: user.name },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      message: "Login correcto",
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/me", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, name, email, role, created_at FROM users WHERE id = $1",
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* =========================
   VEHÍCULOS
========================= */

app.post("/assets", authMiddleware, allowRoles("admin", "inventario"), async (req, res) => {
  try {
    const {
      type,
      code_number,
      brand,
      model,
      year,
      function: assetFunction,
      responsible,
      observation,
      numero_asignado
    } = req.body;

    if (!type || !assetFunction || !code_number) {
      return res.status(400).json({ error: "type, function y code_number son obligatorios" });
    }

    const code = buildCode(type, assetFunction, code_number);

    if (!code) {
      return res.status(400).json({ error: "No se pudo generar el código" });
    }

    const exists = await pool.query("SELECT id FROM assets WHERE code = $1", [code]);

    if (exists.rows.length > 0) {
      return res.status(400).json({ error: "Ya existe un vehículo con ese código" });
    }

    const result = await pool.query(
      `
      INSERT INTO assets
      (code, type, code_number, brand, model, year, function, responsible, observation, numero_asignado, image_url)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      RETURNING id, code, type, code_number, brand, model, year, function, responsible, observation, numero_asignado, image_url, created_at, updated_at
      `,
      [
        code,
        type,
        String(code_number).toUpperCase(),
        brand || null,
        model || null,
        year || null,
        assetFunction || null,
        responsible || null,
        observation || null,
        numero_asignado || null,
        null
      ]
    );

    res.status(201).json({ message: "Vehículo creado correctamente", asset: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/assets/:id/photo", authMiddleware, allowRoles("admin", "inventario"), upload.single("photo"), async (req, res) => {
  try {
    const existing = await pool.query("SELECT id FROM assets WHERE id = $1", [req.params.id]);

    if (existing.rows.length === 0) {
      return res.status(404).json({ error: "Vehículo no encontrado" });
    }

    if (!req.file) {
      return res.status(400).json({ error: "No se recibió ninguna foto" });
    }

    const imageUrl = `/uploads/${req.file.filename}`;

    const result = await pool.query(
      `
      UPDATE assets
      SET image_url = $1,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = $2
      RETURNING id, code, type, code_number, brand, model, year, function, responsible, observation, numero_asignado, image_url, created_at, updated_at
      `,
      [imageUrl, req.params.id]
    );

    res.json({ message: "Foto subida correctamente", asset: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/assets", authMiddleware, allowRoles("admin", "inventario", "viewer"), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, code, type, code_number, brand, model, year, function, responsible, observation, numero_asignado, image_url, created_at, updated_at
      FROM assets
      ORDER BY id ASC
    `);

    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/assets/:id", authMiddleware, allowRoles("admin", "inventario", "viewer"), async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT id, code, type, code_number, brand, model, year, function, responsible, observation, numero_asignado, image_url, created_at, updated_at
      FROM assets
      WHERE id = $1
      `,
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Vehículo no encontrado" });
    }

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/assets/:id", authMiddleware, allowRoles("admin", "inventario"), async (req, res) => {
  try {
    const {
      type,
      code_number,
      brand,
      model,
      year,
      function: assetFunction,
      responsible,
      observation,
      numero_asignado
    } = req.body;

    const existing = await pool.query("SELECT * FROM assets WHERE id = $1", [req.params.id]);

    if (existing.rows.length === 0) {
      return res.status(404).json({ error: "Vehículo no encontrado" });
    }

    const current = existing.rows[0];

    const newType = type ?? current.type;
    const newCodeNumber = code_number ?? current.code_number;
    const newBrand = brand ?? current.brand;
    const newModel = model ?? current.model;
    const newYear = year ?? current.year;
    const newFunction = assetFunction ?? current.function;
    const newResponsible = responsible ?? current.responsible;
    const newObservation = observation ?? current.observation;
    const newNumeroAsignado = numero_asignado ?? current.numero_asignado;

    const newCode = buildCode(newType, newFunction, newCodeNumber);

    if (!newCode) {
      return res.status(400).json({ error: "No se pudo generar el código" });
    }

    if (newCode !== current.code) {
      const codeExists = await pool.query(
        "SELECT id FROM assets WHERE code = $1 AND id <> $2",
        [newCode, req.params.id]
      );

      if (codeExists.rows.length > 0) {
        return res.status(400).json({ error: "Ya existe otro vehículo con ese código" });
      }
    }

    const result = await pool.query(
      `
      UPDATE assets
      SET code = $1,
          type = $2,
          code_number = $3,
          brand = $4,
          model = $5,
          year = $6,
          function = $7,
          responsible = $8,
          observation = $9,
          numero_asignado = $10,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = $11
      RETURNING id, code, type, code_number, brand, model, year, function, responsible, observation, numero_asignado, image_url, created_at, updated_at
      `,
      [
        newCode,
        newType,
        String(newCodeNumber).toUpperCase(),
        newBrand,
        newModel,
        newYear,
        newFunction,
        newResponsible,
        newObservation,
        newNumeroAsignado,
        req.params.id
      ]
    );

    res.json({ message: "Vehículo actualizado correctamente", asset: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/assets/:id", authMiddleware, allowRoles("admin"), async (req, res) => {
  try {
    const existing = await pool.query("SELECT * FROM assets WHERE id = $1", [req.params.id]);

    if (existing.rows.length === 0) {
      return res.status(404).json({ error: "Vehículo no encontrado" });
    }

    await pool.query("DELETE FROM assets WHERE id = $1", [req.params.id]);

    res.json({ message: "Vehículo eliminado correctamente" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* =========================
   HUERTAS
========================= */

/* =========================
   STAFF (PERSONAL)
========================= */

// Crear empleado
app.post("/staff", authMiddleware, allowRoles("admin"), async (req, res) => {
  try {
    const { full_name, position, phone, farm_id } = req.body;

    if (!full_name) {
      return res.status(400).json({ error: "Nombre obligatorio" });
    }

    const result = await pool.query(
      `
      INSERT INTO staff (full_name, position, phone, farm_id)
      VALUES ($1, $2, $3, $4)
      RETURNING *
      `,
      [
        full_name,
        position || null,
        phone || null,
        farm_id || null
      ]
    );

    res.status(201).json({
      message: "Empleado creado correctamente",
      staff: result.rows[0]
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// Obtener empleados
app.get("/staff", authMiddleware, allowRoles("admin"), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT *
      FROM staff
      ORDER BY id ASC
    `);

    res.json(result.rows);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/farms", authMiddleware, allowRoles("admin"), async (req, res) => {
  try {
    const {
      code,
      name,
      estado,
      region,
      sector,
      coordenadas,
      maps_link,
      hectareas,
      numero_terrenos,
      tipo_suelos,
      variedad_banano,
      edad_plantacion,
      sistema_riego,
      fuente_agua,
      bomba_agua,
      prop_medidor_elec,
      empacadora,
      a_favor_de,
      produccion_est_mensual,
      produccion_est_anual,
      encargado,
      telefono_encargado,
      empresa_compradora
    } = req.body;

    if (!code || !name) {
      return res.status(400).json({ error: "code y name son obligatorios" });
    }

    const exists = await pool.query("SELECT id FROM farms WHERE code = $1", [code]);

    if (exists.rows.length > 0) {
      return res.status(400).json({ error: "Ya existe una huerta con ese código" });
    }

    const result = await pool.query(
      `
      INSERT INTO farms (
        code, name, estado, region, sector, coordenadas, maps_link,
        hectareas, numero_terrenos, tipo_suelos, variedad_banano, edad_plantacion,
        sistema_riego, fuente_agua, bomba_agua, prop_medidor_elec,
        empacadora, a_favor_de, produccion_est_mensual, produccion_est_anual,
        encargado, telefono_encargado, empresa_compradora
      )
      VALUES (
        $1,$2,$3,$4,$5,$6,$7,
        $8,$9,$10,$11,$12,
        $13,$14,$15,$16,
        $17,$18,$19,$20,
        $21,$22,$23
      )
      RETURNING *
      `,
      [
        code,
        name,
        estado || null,
        region || null,
        sector || null,
        coordenadas || null,
        maps_link || null,
        hectareas || null,
        numero_terrenos || null,
        tipo_suelos || null,
        variedad_banano || null,
        edad_plantacion || null,
        sistema_riego || null,
        fuente_agua || null,
        bomba_agua || null,
        prop_medidor_elec || null,
        empacadora || null,
        a_favor_de || null,
        produccion_est_mensual || null,
        produccion_est_anual || null,
        encargado || null,
        telefono_encargado || null,
        empresa_compradora || null
      ]
    );

    res.status(201).json({ message: "Huerta creada correctamente", farm: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/farms", authMiddleware, allowRoles("admin", "agricola", "finanzas", "viewer"), async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM farms ORDER BY code ASC NULLS LAST, id ASC");
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/farms/:id", authMiddleware, allowRoles("admin", "agricola", "finanzas", "viewer"), async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM farms WHERE id = $1", [req.params.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Huerta no encontrada" });
    }

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/farms/:id", authMiddleware, allowRoles("admin"), async (req, res) => {
  try {
    const existing = await pool.query("SELECT * FROM farms WHERE id = $1", [req.params.id]);

    if (existing.rows.length === 0) {
      return res.status(404).json({ error: "Huerta no encontrada" });
    }

    const current = existing.rows[0];

    const data = {
      code: req.body.code ?? current.code,
      name: req.body.name ?? current.name,
      estado: req.body.estado ?? current.estado,
      region: req.body.region ?? current.region,
      sector: req.body.sector ?? current.sector,
      coordenadas: req.body.coordenadas ?? current.coordenadas,
      maps_link: req.body.maps_link ?? current.maps_link,
      hectareas: req.body.hectareas ?? current.hectareas,
      numero_terrenos: req.body.numero_terrenos ?? current.numero_terrenos,
      tipo_suelos: req.body.tipo_suelos ?? current.tipo_suelos,
      variedad_banano: req.body.variedad_banano ?? current.variedad_banano,
      edad_plantacion: req.body.edad_plantacion ?? current.edad_plantacion,
      sistema_riego: req.body.sistema_riego ?? current.sistema_riego,
      fuente_agua: req.body.fuente_agua ?? current.fuente_agua,
      bomba_agua: req.body.bomba_agua ?? current.bomba_agua,
      prop_medidor_elec: req.body.prop_medidor_elec ?? current.prop_medidor_elec,
      empacadora: req.body.empacadora ?? current.empacadora,
      a_favor_de: req.body.a_favor_de ?? current.a_favor_de,
      produccion_est_mensual: req.body.produccion_est_mensual ?? current.produccion_est_mensual,
      produccion_est_anual: req.body.produccion_est_anual ?? current.produccion_est_anual,
      encargado: req.body.encargado ?? current.encargado,
      telefono_encargado: req.body.telefono_encargado ?? current.telefono_encargado,
      empresa_compradora: req.body.empresa_compradora ?? current.empresa_compradora
    };

    if (data.code !== current.code) {
      const codeExists = await pool.query(
        "SELECT id FROM farms WHERE code = $1 AND id <> $2",
        [data.code, req.params.id]
      );

      if (codeExists.rows.length > 0) {
        return res.status(400).json({ error: "Ya existe otra huerta con ese código" });
      }
    }

    const result = await pool.query(
      `
      UPDATE farms
      SET code = $1,
          name = $2,
          estado = $3,
          region = $4,
          sector = $5,
          coordenadas = $6,
          maps_link = $7,
          hectareas = $8,
          numero_terrenos = $9,
          tipo_suelos = $10,
          variedad_banano = $11,
          edad_plantacion = $12,
          sistema_riego = $13,
          fuente_agua = $14,
          bomba_agua = $15,
          prop_medidor_elec = $16,
          empacadora = $17,
          a_favor_de = $18,
          produccion_est_mensual = $19,
          produccion_est_anual = $20,
          encargado = $21,
          telefono_encargado = $22,
          empresa_compradora = $23
      WHERE id = $24
      RETURNING *
      `,
      [
        data.code,
        data.name,
        data.estado,
        data.region,
        data.sector,
        data.coordenadas,
        data.maps_link,
        data.hectareas,
        data.numero_terrenos,
        data.tipo_suelos,
        data.variedad_banano,
        data.edad_plantacion,
        data.sistema_riego,
        data.fuente_agua,
        data.bomba_agua,
        data.prop_medidor_elec,
        data.empacadora,
        data.a_favor_de,
        data.produccion_est_mensual,
        data.produccion_est_anual,
        data.encargado,
        data.telefono_encargado,
        data.empresa_compradora,
        req.params.id
      ]
    );

    res.json({ message: "Huerta actualizada correctamente", farm: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* =========================
   ARCHIVOS DE HUERTAS
========================= */

app.post(
  "/farms/:id/files",
  authMiddleware,
  allowRoles("admin"),
  farmUpload.fields([
    { name: "pdfs", maxCount: 5 },
    { name: "photos", maxCount: 5 }
  ]),
  async (req, res) => {
    try {
      const farmId = req.params.id;

      const existing = await pool.query("SELECT id FROM farms WHERE id = $1", [farmId]);

      if (existing.rows.length === 0) {
        return res.status(404).json({ error: "Huerta no encontrada" });
      }

      const pdfs = req.files?.pdfs || [];
      const photos = req.files?.photos || [];

      const totalPdfs = await pool.query(
        "SELECT COUNT(*) FROM farm_files WHERE farm_id = $1 AND file_type = 'PDF'",
        [farmId]
      );

      const totalPhotos = await pool.query(
        "SELECT COUNT(*) FROM farm_files WHERE farm_id = $1 AND file_type = 'PHOTO'",
        [farmId]
      );

      if (Number(totalPdfs.rows[0].count) + pdfs.length > 5) {
        return res.status(400).json({ error: "Máximo 5 PDFs por huerta" });
      }

      if (Number(totalPhotos.rows[0].count) + photos.length > 5) {
        return res.status(400).json({ error: "Máximo 5 fotos por huerta" });
      }

      const inserted = [];

      for (const file of pdfs) {
        const fileUrl = `/uploads/farms/${file.filename}`;

        const result = await pool.query(
          `
          INSERT INTO farm_files (farm_id, file_type, file_name, file_url)
          VALUES ($1, 'PDF', $2, $3)
          RETURNING *
          `,
          [farmId, file.originalname, fileUrl]
        );

        inserted.push(result.rows[0]);
      }

      for (const file of photos) {
        const fileUrl = `/uploads/farms/${file.filename}`;

        const result = await pool.query(
          `
          INSERT INTO farm_files (farm_id, file_type, file_name, file_url)
          VALUES ($1, 'PHOTO', $2, $3)
          RETURNING *
          `,
          [farmId, file.originalname, fileUrl]
        );

        inserted.push(result.rows[0]);
      }

      res.json({ message: "Archivos subidos correctamente", files: inserted });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

app.get("/farms/:id/files", authMiddleware, allowRoles("admin", "agricola", "finanzas", "viewer"), async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT *
      FROM farm_files
      WHERE farm_id = $1
      ORDER BY created_at ASC
      `,
      [req.params.id]
    );

    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/farm-files/:fileId", authMiddleware, allowRoles("admin"), async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM farm_files WHERE id = $1", [req.params.fileId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Archivo no encontrado" });
    }

    const file = result.rows[0];

    const absolutePath = path.join(__dirname, file.file_url.replace("/uploads", "uploads"));

    if (fs.existsSync(absolutePath)) {
      fs.unlinkSync(absolutePath);
    }

    await pool.query("DELETE FROM farm_files WHERE id = $1", [req.params.fileId]);

    res.json({ message: "Archivo eliminado correctamente" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* =========================
   CORTES DE HUERTAS
========================= */

app.post("/farms/:id/cuts", authMiddleware, allowRoles("admin", "agricola"), async (req, res) => {
  try {
    const farmId = req.params.id;

    const existingFarm = await pool.query("SELECT id FROM farms WHERE id = $1", [farmId]);

    if (existingFarm.rows.length === 0) {
      return res.status(404).json({ error: "Huerta no encontrada" });
    }

    let {
      cut_date,
      color,
      boxes_produced,
      price_per_box,
      buyer_company,
      box_design,
      observation
    } = req.body;

    if (!cut_date) {
      return res.status(400).json({ error: "Fecha de corte obligatoria" });
    }

    if (!boxes_produced) {
      return res.status(400).json({ error: "Cajas producidas es obligatorio" });
    }

    const yearMonth = getCutYearMonth(cut_date);

    if (!yearMonth) {
      return res.status(400).json({ error: "Fecha de corte inválida" });
    }

    const boxes = Number(boxes_produced || 0);
    let price = null;
    let grossIncome = null;
    let status = "PENDIENTE_FINANZAS";
    let approvedBy = null;
    let approvedAtSql = null;

    if (req.user.role === "admin" && price_per_box !== undefined && price_per_box !== null && price_per_box !== "") {
      price = Number(price_per_box || 0);
      grossIncome = boxes * price;
      status = "COMPLETO";
      approvedBy = req.user.id;
      approvedAtSql = "CURRENT_TIMESTAMP";
    }

    const result = await pool.query(
      `
      INSERT INTO farm_cuts (
        farm_id,
        cut_date,
        cut_year,
        cut_month,
        color,
        boxes_produced,
        price_per_box,
        buyer_company,
        box_design,
        gross_income,
        observation,
        status,
        created_by,
        approved_by,
        approved_at,
        updated_at
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,${approvedAtSql || "NULL"},CURRENT_TIMESTAMP)
      RETURNING *
      `,
      [
        farmId,
        cut_date,
        yearMonth.year,
        yearMonth.month,
        color || null,
        boxes,
        price,
        buyer_company || null,
        box_design || null,
        grossIncome,
        observation || null,
        status,
        req.user.id,
        approvedBy
      ]
    );

    res.status(201).json({
      message:
        req.user.role === "agricola"
          ? "Corte creado correctamente. Pendiente para finanzas"
          : "Corte creado correctamente",
      cut: result.rows[0]
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/farms/:id/cuts", authMiddleware, allowRoles("admin", "agricola", "finanzas", "viewer"), async (req, res) => {
  try {
    const farmId = req.params.id;
    const { year, month } = req.query;

    let query = `
      SELECT *
      FROM farm_cuts
      WHERE farm_id = $1
    `;

    const values = [farmId];

    if (year) {
      values.push(Number(year));
      query += ` AND cut_year = $${values.length}`;
    }

    if (month) {
      values.push(Number(month));
      query += ` AND cut_month = $${values.length}`;
    }

    query += ` ORDER BY cut_date DESC, id DESC`;

    const result = await pool.query(query, values);

    if (!canSeeMoney(req.user.role)) {
      const sanitized = result.rows.map((cut) => ({
        id: cut.id,
        farm_id: cut.farm_id,
        cut_date: cut.cut_date,
        cut_year: cut.cut_year,
        cut_month: cut.cut_month,
        color: cut.color,
        boxes_produced: cut.boxes_produced,
        buyer_company: cut.buyer_company,
        box_design: cut.box_design,
        observation: cut.observation,
        status: cut.status,
        created_at: cut.created_at,
        updated_at: cut.updated_at
      }));

      return res.json(sanitized);
    }

    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/farms/:id/cuts-summary", authMiddleware, allowRoles("admin", "agricola", "finanzas", "viewer"), async (req, res) => {
  try {
    const farmId = req.params.id;

    if (!canSeeMoney(req.user.role)) {
      const result = await pool.query(
        `
        SELECT
          cut_year,
          cut_month,
          COUNT(*)::INT AS total_cuts,
          COALESCE(SUM(boxes_produced), 0)::NUMERIC(12,2) AS total_boxes
        FROM farm_cuts
        WHERE farm_id = $1
        GROUP BY cut_year, cut_month
        ORDER BY cut_year DESC, cut_month DESC
        `,
        [farmId]
      );

      return res.json(result.rows);
    }

    const result = await pool.query(
      `
      SELECT
        cut_year,
        cut_month,
        COUNT(*)::INT AS total_cuts,
        COALESCE(SUM(boxes_produced), 0)::NUMERIC(12,2) AS total_boxes,
        COALESCE(SUM(gross_income), 0)::NUMERIC(12,2) AS total_income
      FROM farm_cuts
      WHERE farm_id = $1
      GROUP BY cut_year, cut_month
      ORDER BY cut_year DESC, cut_month DESC
      `,
      [farmId]
    );

    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/cuts/pending-finance", authMiddleware, allowRoles("admin", "finanzas"), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        fc.*,
        f.code AS farm_code,
        f.name AS farm_name,
        u.name AS created_by_name,
        u.email AS created_by_email
      FROM farm_cuts fc
      INNER JOIN farms f ON f.id = fc.farm_id
      LEFT JOIN users u ON u.id = fc.created_by
      WHERE fc.status = 'PENDIENTE_FINANZAS'
      ORDER BY fc.cut_date DESC, fc.id DESC
    `);

    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/farm-cuts/:cutId/complete-price", authMiddleware, allowRoles("admin", "finanzas"), async (req, res) => {
  try {
    const { price_per_box } = req.body;

    if (price_per_box === undefined || price_per_box === null || price_per_box === "") {
      return res.status(400).json({ error: "Precio por caja obligatorio" });
    }

    const existing = await pool.query("SELECT * FROM farm_cuts WHERE id = $1", [req.params.cutId]);

    if (existing.rows.length === 0) {
      return res.status(404).json({ error: "Corte no encontrado" });
    }

    const cut = existing.rows[0];

    const price = Number(price_per_box || 0);
    const boxes = Number(cut.boxes_produced || 0);
    const grossIncome = boxes * price;

    const result = await pool.query(
      `
      UPDATE farm_cuts
      SET price_per_box = $1,
          gross_income = $2,
          status = 'COMPLETO',
          approved_by = $3,
          approved_at = CURRENT_TIMESTAMP,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = $4
      RETURNING *
      `,
      [price, grossIncome, req.user.id, req.params.cutId]
    );

    res.json({ message: "Precio completado correctamente", cut: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/farm-cuts/:cutId", authMiddleware, allowRoles("admin"), async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM farm_cuts WHERE id = $1", [req.params.cutId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Corte no encontrado" });
    }

    await pool.query("DELETE FROM farm_cuts WHERE id = $1", [req.params.cutId]);

    res.json({ message: "Corte eliminado correctamente" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post(
  "/staff/:id/files",
  authMiddleware,
  allowRoles("admin"),
  staffUpload.fields([
    { name: "ine", maxCount: 1 },
    { name: "pdfs", maxCount: 5 }
  ]),
  async (req, res) => {
    try {
      const staffId = req.params.id;

      const existing = await pool.query("SELECT id FROM staff WHERE id = $1", [
        staffId
      ]);

      if (existing.rows.length === 0) {
        return res.status(404).json({ error: "Empleado no encontrado" });
      }

      const ineFiles = req.files?.ine || [];
      const pdfs = req.files?.pdfs || [];
      const inserted = [];

      for (const file of ineFiles) {
        const fileUrl = `/uploads/staff/${file.filename}`;

        const result = await pool.query(
          `
          INSERT INTO staff_files (staff_id, file_type, file_name, file_url)
          VALUES ($1, 'INE', $2, $3)
          RETURNING *
          `,
          [staffId, file.originalname, fileUrl]
        );

        inserted.push(result.rows[0]);
      }

      for (const file of pdfs) {
        const fileUrl = `/uploads/staff/${file.filename}`;

        const result = await pool.query(
          `
          INSERT INTO staff_files (staff_id, file_type, file_name, file_url)
          VALUES ($1, 'PDF', $2, $3)
          RETURNING *
          `,
          [staffId, file.originalname, fileUrl]
        );

        inserted.push(result.rows[0]);
      }

      res.json({
        message: "Archivos de empleado subidos correctamente",
        files: inserted
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

app.get("/staff/:id/files", authMiddleware, allowRoles("admin"), async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT *
      FROM staff_files
      WHERE staff_id = $1
      ORDER BY created_at ASC
      `,
      [req.params.id]
    );

    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/staff-files/:fileId", authMiddleware, allowRoles("admin"), async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM staff_files WHERE id = $1", [
      req.params.fileId
    ]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Archivo no encontrado" });
    }

    const file = result.rows[0];
    const absolutePath = path.join(
      __dirname,
      file.file_url.replace("/uploads", "uploads")
    );

    if (fs.existsSync(absolutePath)) {
      fs.unlinkSync(absolutePath);
    }

    await pool.query("DELETE FROM staff_files WHERE id = $1", [
      req.params.fileId
    ]);

    res.json({ message: "Archivo eliminado correctamente" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* =========================
   ELIMINAR HUERTA
========================= */

app.delete("/farms/:id", authMiddleware, allowRoles("admin"), async (req, res) => {
  try {
    const existing = await pool.query("SELECT * FROM farms WHERE id = $1", [req.params.id]);

    if (existing.rows.length === 0) {
      return res.status(404).json({ error: "Huerta no encontrada" });
    }

    await pool.query("DELETE FROM farms WHERE id = $1", [req.params.id]);

    res.json({ message: "Huerta eliminada correctamente" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
/* =========================
   PERSONAL
========================= */
app.post("/staff", authMiddleware, allowRoles("admin"), async (req, res) => {
  try {
    const {
      full_name,
      curp,
      birth_date,
      address,
      phone,
      emergency_contact_1_name,
      emergency_contact_1_phone,
      emergency_contact_2_name,
      emergency_contact_2_phone,
      area,
      company_name
    } = req.body;

    if (!full_name || !curp) {
      return res.status(400).json({ error: "Nombre y CURP obligatorios" });
    }

    const employee_code = generateEmployeeCode(full_name, curp);

    const result = await pool.query(
      `
      INSERT INTO staff (
        full_name, curp, birth_date, address, phone,
        emergency_contact_1_name, emergency_contact_1_phone,
        emergency_contact_2_name, emergency_contact_2_phone,
        area, company_name, employee_code
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
      RETURNING *
      `,
      [
        full_name,
        curp,
        birth_date || null,
        address || null,
        phone || null,
        emergency_contact_1_name || null,
        emergency_contact_1_phone || null,
        emergency_contact_2_name || null,
        emergency_contact_2_phone || null,
        area || null,
        company_name || null,
        employee_code
      ]
    );

    res.json({ message: "Empleado creado", employee: result.rows[0] });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/staff", authMiddleware, allowRoles("admin"), async (req, res) => {
  try {
    const { area } = req.query;

    let query = "SELECT * FROM staff";
    let values = [];

    if (area) {
      query += " WHERE area = $1";
      values.push(area);
    }

    query += " ORDER BY id DESC";

    const result = await pool.query(query, values);

    res.json(result.rows);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/staff/:id", authMiddleware, allowRoles("admin"), async (req, res) => {
  try {
    const existing = await pool.query("SELECT * FROM staff WHERE id = $1", [req.params.id]);

    if (existing.rows.length === 0) {
      return res.status(404).json({ error: "Empleado no encontrado" });
    }

    const current = existing.rows[0];

    const data = {
      full_name: req.body.full_name ?? current.full_name,
      phone: req.body.phone ?? current.phone,
      address: req.body.address ?? current.address,
      area: req.body.area ?? current.area,
      company_name: req.body.company_name ?? current.company_name
    };

    const result = await pool.query(
      `
      UPDATE staff
      SET full_name=$1, phone=$2, address=$3, area=$4, company_name=$5
      WHERE id=$6
      RETURNING *
      `,
      [
        data.full_name,
        data.phone,
        data.address,
        data.area,
        data.company_name,
        req.params.id
      ]
    );

    res.json(result.rows[0]);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/staff/:id", authMiddleware, allowRoles("admin"), async (req, res) => {
  try {
    await pool.query("DELETE FROM staff WHERE id = $1", [req.params.id]);
    res.json({ message: "Empleado eliminado" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* =========================
   STAFF (PERSONAL)
========================= */

app.post("/staff", authMiddleware, allowRoles("admin"), async (req, res) => {
  try {
    const {
      full_name,
      curp,
      area,
      company,
      birth_date,
      address,
      phone,
      emergency_contact_1_name,
      emergency_contact_1_phone,
      emergency_contact_2_name,
      emergency_contact_2_phone
    } = req.body;

    if (!full_name || !area) {
      return res.status(400).json({ error: "Nombre y área son obligatorios" });
    }

    const result = await pool.query(
      `
      INSERT INTO staff (
        full_name,
        curp,
        area,
        company,
        birth_date,
        address,
        phone,
        emergency_contact_1_name,
        emergency_contact_1_phone,
        emergency_contact_2_name,
        emergency_contact_2_phone
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      RETURNING *
      `,
      [
        full_name,
        curp || null,
        area,
        company || null,
        birth_date || null,
        address || null,
        phone || null,
        emergency_contact_1_name || null,
        emergency_contact_1_phone || null,
        emergency_contact_2_name || null,
        emergency_contact_2_phone || null
      ]
    );

    res.status(201).json({
      message: "Empleado creado correctamente",
      employee: result.rows[0]
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* =========================
   DASHBOARD GLOBAL
========================= */

app.get("/dashboard/global", authMiddleware, allowRoles("admin", "finanzas"), async (req, res) => {
  try {
    const totals = await pool.query(`
      SELECT
        COUNT(*)::INT AS total_cuts,
        COALESCE(SUM(boxes_produced), 0)::NUMERIC(12,2) AS total_boxes,
        COALESCE(SUM(gross_income), 0)::NUMERIC(12,2) AS total_income,
        COALESCE(AVG(NULLIF(price_per_box, 0)), 0)::NUMERIC(12,2) AS avg_price,
        COUNT(*) FILTER (WHERE status = 'PENDIENTE_FINANZAS')::INT AS pending_finance
      FROM farm_cuts
    `);

    const byMonth = await pool.query(`
      SELECT
        cut_year,
        cut_month,
        COUNT(*)::INT AS total_cuts,
        COALESCE(SUM(boxes_produced), 0)::NUMERIC(12,2) AS total_boxes,
        COALESCE(SUM(gross_income), 0)::NUMERIC(12,2) AS total_income,
        COUNT(*) FILTER (WHERE status = 'PENDIENTE_FINANZAS')::INT AS pending_finance
      FROM farm_cuts
      GROUP BY cut_year, cut_month
      ORDER BY cut_year ASC, cut_month ASC
    `);

    const byFarm = await pool.query(`
      SELECT
        f.id,
        f.code,
        f.name,
        COUNT(fc.id)::INT AS total_cuts,
        COALESCE(SUM(fc.boxes_produced), 0)::NUMERIC(12,2) AS total_boxes,
        COALESCE(SUM(fc.gross_income), 0)::NUMERIC(12,2) AS total_income,
        COUNT(fc.id) FILTER (WHERE fc.status = 'PENDIENTE_FINANZAS')::INT AS pending_finance
      FROM farms f
      LEFT JOIN farm_cuts fc ON fc.farm_id = f.id
      GROUP BY f.id, f.code, f.name
      ORDER BY total_boxes DESC
    `);

    res.json({ totals: totals.rows[0], byMonth: byMonth.rows, byFarm: byFarm.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* =========================
   SERVIDOR
========================= */

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});
