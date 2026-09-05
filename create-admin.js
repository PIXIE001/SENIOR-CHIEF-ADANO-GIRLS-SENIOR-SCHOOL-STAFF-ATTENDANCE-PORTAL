require("dotenv").config();

const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

async function createAdmin() {
  const username = "admin";
  const password = "Admin@12345";
  const fullName = "S.C.A.G.S.S Administrator";

  try {
    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `
      INSERT INTO staff
        (username, password_hash, full_name, role, active)
      VALUES
        ($1, $2, $3, 'admin', true)
      ON CONFLICT (username)
      DO UPDATE SET
        password_hash = EXCLUDED.password_hash,
        full_name = EXCLUDED.full_name,
        role = 'admin',
        active = true
      RETURNING id, username, full_name, role, active
      `,
      [username, passwordHash, fullName]
    );

    console.log("\n=================================");
    console.log(" S.C.A.G.S.S ADMIN CREATED");
    console.log("=================================");
    console.log(result.rows[0]);
    console.log("\nLOGIN DETAILS");
    console.log("Username: admin");
    console.log("Password: Admin@12345");
    console.log("=================================\n");

  } catch (error) {
    console.error("\nERROR CREATING ADMIN:");
    console.error(error.message);
  } finally {
    await pool.end();
  }
}

createAdmin();
