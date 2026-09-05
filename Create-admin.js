require("dotenv").config();

const bcrypt = require("bcryptjs");

async function main() {
  const password = "Admin@12345";

  const hash = await bcrypt.hash(password, 12);

  console.log("\n================================");
  console.log("S.C.A.G.S.S ADMIN PASSWORD HASH");
  console.log("================================");
  console.log(hash);
  console.log("================================\n");
}

main();
